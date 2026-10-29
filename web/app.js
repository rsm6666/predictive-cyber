/* ===================================================================
   واجهة مركز التنبؤ — منطق الاتصال بخادم FastAPI
   =================================================================== */
const API = location.origin.startsWith("http") ? "" : "http://localhost:8000";

const $ = (s) => document.querySelector(s);
const $$ = (s) => [...document.querySelectorAll(s)];
const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) =>
  ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const pct = (v, d = 1) => (v * 100).toFixed(d) + "%";

function toast(msg) {
  const t = $("#toast"); t.textContent = msg; t.classList.add("show");
  clearTimeout(t._t); t._t = setTimeout(() => t.classList.remove("show"), 2600);
}
async function api(path, opts) {
  const r = await fetch(API + path, opts);
  if (!r.ok) throw new Error("HTTP " + r.status);
  return r.json();
}
const post = (path) => api(path, { method: "POST" });
const loadingHtml = (msg) => `<div class="loading-state"><span class="loading"></span>${msg}</div>`;
const errorHtml = (title, detail = "") =>
  `<div class="error-state"><b>${title}</b>${detail ? `<div>${detail}</div>` : ""}</div>`;
const OFFLINE = errorHtml("تعذّر الاتصال بالخادم.", "تأكد أن الخادم يعمل (uvicorn api_server:app).");

/* ---------- جلسة المنشأة (مفتاح اللوحة في sessionStorage، يُرسل في الترويسة فقط) ---------- */
const DASH_KEY = "pc_dashboard_key";
const TENANT_PAGES = new Set(["tenant", "monitor", "analyst", "settings"]);
let afterLoginPage = "tenant";
function dashKey() {
  try { return sessionStorage.getItem(DASH_KEY); } catch (e) { return null; }
}
function setDashKey(k) {
  try { k ? sessionStorage.setItem(DASH_KEY, k) : sessionStorage.removeItem(DASH_KEY); } catch (e) {}
}
async function tenantApi(path, method = "GET", body) {
  const headers = { Authorization: "Bearer " + (dashKey() || "") };
  if (body) headers["Content-Type"] = "application/json";
  const r = await fetch(API + path, { method, headers, body: body ? JSON.stringify(body) : undefined });
  const data = await r.json().catch(() => ({}));
  if (r.status === 401) { logout(); throw new Error("مفتاح غير صالح أو منتهٍ، ادخل من جديد"); }
  if (!r.ok) throw new Error(typeof data.detail === "string" ? data.detail : "طلب غير صالح");
  return data;
}

/* ---------- معلومات أنواع الهجوم (تطابق سياسة sandbox_firewall.py) ---------- */
const FAMILY = {
  "BENIGN":                { ar: "اتصال طبيعي",        sev: "safe" },
  "DDoS":                  { ar: "حجب خدمة موزّع",     sev: "critical", action: "rate_limit_target", min: 30,
    advice: "فعّل تحديد المعدل على الخدمة المستهدفة، ووجّه الترافيك عبر خدمة حماية من الإغراق، وراقب سعة الرابط." },
  "DoS":                   { ar: "حجب خدمة",           sev: "critical", action: "block_ip", min: 30,
    advice: "احظر عنوان المصدر مؤقتًا، وقلّل مهلة الاتصالات المفتوحة على الخادم المستهدف." },
  "Botnet":                { ar: "جهاز ضمن شبكة بوتات", sev: "critical", action: "quarantine_host", min: 120,
    advice: "اعزل الجهاز المصاب عن الشبكة وافحصه، واحظر اتصاله بخوادم التحكم." },
  "Brute Force (FTP/SSH)": { ar: "تخمين كلمات المرور",  sev: "high", action: "block_ip", min: 60,
    advice: "احظر المصدر، وفعّل قفل الحساب بعد المحاولات الفاشلة، وألزم بالمصادقة الثنائية لخدمات FTP وSSH." },
  "Web Attack":            { ar: "هجوم على تطبيق ويب",  sev: "high", action: "block_ip", min: 30,
    advice: "احظر المصدر، وفعّل جدار حماية تطبيقات الويب، وراجع سجلات الخادم بحثًا عن استغلال ناجح." },
  "PortScan":              { ar: "فحص المنافذ",         sev: "medium", action: "block_ip", min: 15,
    advice: "احظر المصدر ١٥ دقيقة، وراجع المنافذ المفتوحة وأغلق غير الضروري منها." },
};
const SEV_AR = { critical: "حرج", high: "مرتفع", medium: "متوسط", safe: "آمن" };
const ACTION_AR = {
  block_ip: ["حظر العنوان", "critical"], quarantine_host: ["عزل الجهاز", "critical"],
  rate_limit_target: ["تحديد معدل الهدف", "high"], monitor: ["مراقبة", "info"], none: ["لا إجراء (قائمة السماح)", "safe"],
};
const famInfo = (f) => FAMILY[f] || { ar: f, sev: "high" };

// نفس منطق normalize_label في train_attack_type_model.py
function normalizeLabel(label) {
  const low = String(label).trim().toLowerCase();
  if (low === "benign") return "BENIGN";
  if (low === "ddos") return "DDoS";
  if (low.startsWith("dos")) return "DoS";
  if (low === "portscan") return "PortScan";
  if (low === "ftp-patator" || low === "ssh-patator") return "Brute Force (FTP/SSH)";
  if (low.startsWith("web attack")) return "Web Attack";
  if (low === "bot") return "Botnet";
  return String(label).trim();
}

const ICON = {
  alert: '<svg viewBox="0 0 24 24"><path d="M12 3 2 20h20L12 3Z"/><path d="M12 10v4M12 17h.01"/></svg>',
  ok: '<svg viewBox="0 0 24 24"><path d="M12 2 4 5v6c0 5 3.4 9.4 8 11 4.6-1.6 8-6 8-11V5l-8-3Z"/><path d="m9 12 2 2 4-4"/></svg>',
};

/* ---------- الوضع الليلي ---------- */
function applyTheme(t) {
  document.documentElement.setAttribute("data-theme", t);
  try { localStorage.setItem("theme", t); } catch (e) {}
}
$("#themeBtn").addEventListener("click", () => {
  const cur = document.documentElement.getAttribute("data-theme");
  applyTheme(cur === "dark" ? "light" : "dark");
});
try {
  const saved = localStorage.getItem("theme");
  if (saved) applyTheme(saved);
} catch (e) {}

/* ---------- التنقل بين الصفحات ومصدر البيانات ---------- */
const PAGES = {
  overview: ["نظرة عامة", "ملخص أداء النظام وطبقاته الثلاث"],
  analyst:  ["المحلل الذكي", "وكيل ذكاء اصطناعي يحقق في الحادثة ويقترح، والقرار لك"],
  tenant:   ["منشأتي", "بيانات منشأتك والمصادر المتصلة"],
  monitor:  ["المراقبة", "مراقبة موقعك من الخارج: التوفر، ودرجة الأمان، والملفات المكشوفة"],
  settings: ["الإعدادات", "التنبيهات وقائمة السماح ومفاتيح الوصول"],
  login:    ["دخول المنشأة", "سجّل منشأتك أو ادخل بمفتاح اللوحة"],
  detect:   ["الكشف اللحظي", "تصنيف الاتصال إلى طبيعي أو نوع هجوم، مع سبب القرار"],
  forecast: ["التنبؤ", "احتمال بداية هجوم في الدقيقة التالية"],
  respond:  ["الاستجابة", "إجراءات مقترحة لكل مصدر مشبوه مع حواجز الأمان"],
};
function setPage(p) {
  if (!PAGES[p]) p = "overview";
  if (TENANT_PAGES.has(p) && !dashKey()) { afterLoginPage = p; p = "login"; }
  document.body.dataset.page = p;
  $$(".nav button").forEach((b) => b.classList.toggle("on", b.dataset.page === p));
  $$(".page").forEach((s) => s.classList.toggle("on", s.id === "p-" + p));
  $("#pageTitle").textContent = PAGES[p][0];
  $("#pageSub").textContent = PAGES[p][1];
  if (location.hash.slice(1) !== p) history.replaceState(null, "", "#" + p);
  if (p === "tenant") refreshLogs();
  if (p === "settings") refreshDeliveries();
  if (p === "monitor") refreshSites();
  window.scrollTo(0, 0);
}
$$(".nav button").forEach((b) => b.addEventListener("click", () => setPage(b.dataset.page)));
$$("[data-goto]").forEach((b) => b.addEventListener("click", () => setPage(b.dataset.goto)));
$$("#sourceSwitch button").forEach((b) => b.addEventListener("click", () => {
  $$("#sourceSwitch button").forEach((x) => x.classList.toggle("on", x === b));
  document.body.dataset.source = b.dataset.source;
}));
setPage(location.hash.slice(1));

/* ---------- نظرة عامة: حالة النظام + مؤشرات الأداء ---------- */
async function loadOverview() {
  const card = $("#statusCard"), sys = $("#sysStatus");
  try {
    const [h, s] = await Promise.all([api("/"), api("/api/stats")]);
    const ok = h.models_loaded;
    card.className = "status-card " + (ok ? "ok" : "off");
    $("#statusTitle").textContent = ok ? "النظام يعمل — كل الطبقات جاهزة" : "النماذج غير محمّلة";
    $("#statusSub").textContent = (ok ? "نماذج الكشف محمّلة" : "شغّل سكربتات التدريب أولًا") +
      " · " + (h.lstm_ready ? "نماذج التنبؤ (٥ LSTM) جاهزة" : "نماذج التنبؤ غير متاحة");
    sys.className = "sys " + (ok ? "ok" : "off");
    sys.lastElementChild.textContent = ok ? "النظام يعمل" : "النماذج غير محمّلة";

    const kpi = (cls, k, v, d, bar) => `<div class="kpi ${cls}"><div class="k">${k}</div>
      <div class="v">${v}</div><div class="d">${d}</div>
      ${bar != null ? `<div class="bar"><span style="width:${Math.min(bar * 100, 100)}%"></span></div>` : ""}</div>`;
    $("#kpis").innerHTML = [
      kpi("good", "نسبة رصد الهجمات", pct(s.detector_recall), "من الهجمات الفعلية التقطها الكاشف", s.detector_recall),
      kpi("good", "دقة تحديد نوع الهجوم", pct(s.attack_type_f1), "Macro-F1 على ٧ فئات", s.attack_type_f1),
      kpi("brand", "رصد بدايات الهجوم مسبقًا", pct(s.onset_recall, 0), "مقابل ~١٨٪ بالصدفة", s.onset_recall),
      kpi("good", "الضرر الجانبي للاستجابة", pct(s.collateral), "اتصالات سليمة تأثرت بالحظر", null),
      kpi("brand", "أنواع الهجوم المدعومة", s.attack_types, "فحص منافذ، DoS، DDoS، تخمين، ويب، بوتات", null),
      kpi("brand", "حجم بيانات التدريب", (s.dataset_rows / 1e6).toFixed(2) + "M", "اتصال من CICIDS2017", null),
    ].join("");
  } catch (e) {
    card.className = "status-card off";
    $("#statusTitle").textContent = "تعذّر الاتصال بالخادم";
    $("#statusSub").textContent = "شغّل: uvicorn api_server:app --port 8001";
    sys.className = "sys off";
    sys.lastElementChild.textContent = "الخادم غير متصل";
    $("#kpis").innerHTML = "";
  }
}
loadOverview();

/* ---------- التوصية الأمنية (Ollama إن توفر، وإلا دليل الاستجابة) ---------- */
async function getAdvice(context, fallback) {
  try {
    const r = await api("/api/recommend", {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ context }),
    });
    if (r.recommendation) return { text: r.recommendation, src: "مولّدة بنموذج لغوي محلّي (Ollama)" };
  } catch (e) {}
  return { text: fallback, src: "من دليل الاستجابة المعتمد (Ollama غير مفعّل)" };
}
function adviceCard(id) {
  return `<div class="card advice"><div class="card-title">التوصية الأمنية</div>
    <div id="${id}"><span class="loading"></span> جاري توليد التوصية…</div></div>`;
}
function fillAdvice(id, a) {
  const el = document.getElementById(id);
  if (el) el.innerHTML = `<p>${esc(a.text)}</p><div class="src">${a.src}</div>`;
}

/* ---------- رسوم مساعدة (SVG) ---------- */
function sparkPath(vals, w, h) {
  const mx = Math.max(...vals), mn = Math.min(...vals), rng = mx - mn || 1;
  return vals.map((v, i) =>
    `${i ? "L" : "M"}${(i / (vals.length - 1) * w).toFixed(1)} ${(h - 2 - (v - mn) / rng * (h - 4)).toFixed(1)}`).join(" ");
}
function lineChart(vals) {
  const W = 600, H = 210, L = 46, R = 14, T = 14, B = 30;
  const mx = Math.max(...vals, 1) * 1.1, n = vals.length;
  const x = (i) => L + i * (W - L - R) / (n - 1);
  const y = (v) => T + (1 - v / mx) * (H - T - B);
  const line = vals.map((v, i) => `${i ? "L" : "M"}${x(i).toFixed(1)} ${y(v).toFixed(1)}`).join(" ");
  const area = `${line} L${x(n - 1)} ${H - B} L${x(0)} ${H - B} Z`;
  const grid = [0, 0.5, 1].map((f) => {
    const v = mx * f, yy = y(v);
    return `<line class="grid" x1="${L}" x2="${W - R}" y1="${yy}" y2="${yy}"/>
      <text class="axis" x="${L - 8}" y="${yy + 4}" text-anchor="end">${Math.round(v).toLocaleString("en")}</text>`;
  }).join("");
  const labels = vals.map((_, i) =>
    `<text class="axis" x="${x(i)}" y="${H - 8}" text-anchor="middle">${i === n - 1 ? "الآن" : "-" + (n - 1 - i)}</text>`).join("");
  const pts = vals.map((v, i) => `<circle class="pt${i === n - 1 ? " last" : ""}" cx="${x(i)}" cy="${y(v)}" r="3.5"/>`).join("");
  return `<div class="chart" dir="ltr"><svg viewBox="0 0 ${W} ${H}" role="img" aria-label="عدد التدفقات لكل دقيقة">
    <defs><linearGradient id="areaG" x1="0" y1="0" x2="0" y2="1">
      <stop offset="0" style="stop-color:var(--accent);stop-opacity:.35"/>
      <stop offset="1" style="stop-color:var(--accent);stop-opacity:0"/></linearGradient></defs>
    ${grid}<path d="${area}" fill="url(#areaG)"/><path class="line" d="${line}"/>${pts}${labels}</svg></div>`;
}
function gauge(p, thr, alert) {
  const pt = (t, r) => [100 - r * Math.cos(Math.PI * t), 100 - r * Math.sin(Math.PI * t)];
  const [x1, y1] = pt(thr, 68), [x2, y2] = pt(thr, 94);
  const color = alert ? "var(--danger)" : "var(--ok)";
  return `<svg viewBox="0 0 200 110" aria-hidden="true">
    <path class="track" d="M20 100 A80 80 0 0 1 180 100" stroke-width="16" stroke-linecap="round" fill="none"/>
    <path class="val" d="M20 100 A80 80 0 0 1 180 100" pathLength="100" stroke="${color}" stroke-width="16"
      stroke-linecap="round" fill="none" stroke-dasharray="${Math.max(p * 100, 0.5)} 100"/>
    <line class="tick" x1="${x1}" y1="${y1}" x2="${x2}" y2="${y2}" stroke-width="2.5"/></svg>`;
}

/* ---------- الكشف اللحظي (بيانات CICIDS) ---------- */
$("#detectBtn").addEventListener("click", async () => {
  const box = $("#detectResult"), btn = $("#detectBtn");
  btn.disabled = true;
  box.innerHTML = loadingHtml("جاري تحليل الاتصال…");
  let d;
  try { d = await post("/api/detect"); }
  catch (e) { box.innerHTML = OFFLINE; btn.disabled = false; return; }
  btn.disabled = false;
  btn.textContent = "حلّل اتصالًا آخر";

  const f = famInfo(d.prediction);
  const truth = normalizeLabel(d.true_label);
  const match = truth === d.prediction;
  const maxZ = Math.max(...d.explanation.map((e) => Math.abs(e.z)), 1);
  const act = d.is_attack && f.action ? ACTION_AR[f.action] : null;

  box.innerHTML = `
  <div class="incident ${d.is_attack ? "attack" : "benign"}">
    <div class="inc-main">
      <div class="card">
        <div class="inc-head">
          <div class="inc-icon">${d.is_attack ? ICON.alert : ICON.ok}</div>
          <div><h3>${d.is_attack ? "رُصد هجوم: " + f.ar : "الاتصال طبيعي"}</h3>
            <div class="en">${esc(d.prediction)}</div></div>
          <span class="badge ${f.sev}">${d.is_attack ? "الخطورة: " : ""}${SEV_AR[f.sev]}</span>
        </div>
        <div class="meta" style="margin-top:16px">
          <div><div class="k">ثقة النموذج</div><div class="v mono">${pct(d.confidence)}</div></div>
          <div><div class="k">الحكم</div><div class="v">${d.is_attack ? "هجوم" : "طبيعي"}</div></div>
          <div><div class="k">التصنيف الحقيقي</div><div class="v mono">${esc(d.true_label)}</div>
            <div class="match ${match ? "yes" : "no"}">${match ? "✓ يطابق تنبؤ النموذج" : "✗ لا يطابق"}</div></div>
        </div>
      </div>
      <div class="card">
        <div class="card-title">لماذا هذا القرار؟ الخصائص الأكثر انحرافًا عن السلوك الطبيعي</div>
        ${d.explanation.map((e) => `
          <div class="why-row">
            <span class="fname" title="${esc(e.feature)}">${esc(e.feature)}</span>
            <div class="why-track"><span class="${e.z > 0 ? "up" : "down"}" style="width:${Math.abs(e.z) / maxZ * 100}%"></span></div>
            <span class="z">z=${e.z > 0 ? "+" : ""}${e.z}</span>
          </div>`).join("")}
        <div class="why-legend"><span><i style="background:var(--danger)"></i>أعلى من الطبيعي</span>
          <span><i style="background:var(--accent)"></i>أقل من الطبيعي</span></div>
      </div>
    </div>
    <div class="inc-side">
      ${d.is_attack ? adviceCard("detectAdvice") : `<div class="card advice"><div class="card-title">التوصية الأمنية</div>
        <p>لا إجراء مطلوب. الاتصال ضمن نمط السلوك الطبيعي.</p></div>`}
      <div class="card">
        <div class="card-title">الإجراء المقترح</div>
        <div class="kv"><span>الإجراء</span><span>${act ? `<span class="badge ${act[1]}">${act[0]}</span>` : "لا شيء"}</span></div>
        <div class="kv"><span>المدة</span><span>${act ? f.min + " دقيقة" : "—"}</span></div>
        <div class="kv"><span>وضع التنفيذ</span><span>بيئة معزولة</span></div>
        ${d.is_attack ? `<button class="btn-ghost" style="width:100%;justify-content:center;margin-top:12px" data-goto-btn="respond">افتح طبقة الاستجابة</button>` : ""}
      </div>
    </div>
  </div>`;
  box.querySelector("[data-goto-btn]")?.addEventListener("click", () => setPage("respond"));

  if (d.is_attack) {
    const ctx = `رصد النظام اتصالًا من نوع ${d.prediction} بثقة ${pct(d.confidence, 0)}، ` +
      `وأبرز مؤشراته: ${d.explanation.slice(0, 3).map((e) => e.feature + " " + e.direction).join("، ")}.`;
    getAdvice(ctx, f.advice).then((a) => fillAdvice("detectAdvice", a));
  }
});

/* ---------- التنبؤ (بيانات CICIDS) ---------- */
async function runForecast(mode) {
  const box = $("#fcResult");
  $$("[data-mode]").forEach((b) => {
    b.className = b.dataset.mode === mode ? "btn-primary" : "btn-ghost";
    b.disabled = true;
  });
  box.innerHTML = loadingHtml("مجموعة نماذج LSTM تقرأ آخر ١٠ دقائق…");
  let d;
  try { d = await post("/api/forecast?mode=" + mode); }
  catch (e) { box.innerHTML = OFFLINE; return; }
  finally { $$("[data-mode]").forEach((b) => (b.disabled = false)); }
  if (d.error) { box.innerHTML = errorHtml(esc(d.error)); return; }

  const correct = d.alert === Boolean(d.true_label);
  const t = d.trend;
  const last = (a) => a[a.length - 1];
  box.innerHTML = `
  <div class="fc-grid">
    <div class="card gauge">
      <span class="badge ${d.alert ? "critical" : "safe"}">${d.alert ? "إنذار: هجوم متوقَّع" : "لا خطر متوقَّع"}</span>
      ${gauge(d.probability, d.threshold, d.alert)}
      <div class="gauge-num">${pct(d.probability)}</div>
      <div class="gauge-cap">احتمال بداية هجوم في الدقيقة التالية</div>
      <div style="width:100%">
        <div class="kv"><span>عتبة الإنذار (الخط)</span><span class="mono">${pct(d.threshold)}</span></div>
        <div class="kv"><span>ما حدث فعلًا</span><span>${d.true_label ? "هجوم" : "هادئ"}</span></div>
        <div class="kv"><span>تقييم التنبؤ</span>
          <span class="match ${correct ? "yes" : "no"}">${correct ? "✓ تنبؤ صحيح" : "✗ تنبؤ خاطئ"}</span></div>
      </div>
    </div>
    <div class="card">
      <div class="card-title">عدد التدفقات لكل دقيقة (آخر ١٠ دقائق)</div>
      ${lineChart(t.total_flows)}
      <div class="sparks">
        <div class="spark"><div class="k">منافذ وجهة مختلفة</div><div class="v">${last(t.unique_dst_ports).toLocaleString("en")}</div>
          <svg viewBox="0 0 120 30" preserveAspectRatio="none"><path d="${sparkPath(t.unique_dst_ports, 120, 30)}"/></svg></div>
        <div class="spark"><div class="k">متوسط حجم الحزمة (بايت)</div><div class="v">${last(t.avg_packet_size)}</div>
          <svg viewBox="0 0 120 30" preserveAspectRatio="none"><path d="${sparkPath(t.avg_packet_size, 120, 30)}"/></svg></div>
      </div>
    </div>
  </div>`;
}
$$("[data-mode]").forEach((b) => b.addEventListener("click", () => runForecast(b.dataset.mode)));

/* ---------- اختبار التحقق ---------- */
$("#validateBtn").addEventListener("click", async () => {
  const box = $("#validateResult"), btn = $("#validateBtn");
  btn.disabled = true;
  box.innerHTML = `<div style="margin-top:14px">${loadingHtml("جاري التقييم على مجموعة الاختبار الزمنية…")}</div>`;
  let d;
  try { d = await post("/api/validate"); }
  catch (e) { box.innerHTML = OFFLINE; btn.disabled = false; return; }
  btn.disabled = false;
  if (d.error) { box.innerHTML = errorHtml(esc(d.error)); return; }

  box.innerHTML = `
    <div class="val-kpis">
      <div><div class="k">بدايات هجوم رُصدت مسبقًا</div><div class="v">${d.onset_caught}/${d.n_onset}</div>
        <div class="match yes">${d.onset_recall != null ? pct(d.onset_recall, 0) : "—"}</div></div>
      <div><div class="k">إنذارات كاذبة على النوافذ الهادئة</div><div class="v">${d.false_alarms}/${d.n_benign}</div>
        <div class="match">${d.false_alarm_rate != null ? pct(d.false_alarm_rate) : "—"}</div></div>
      <div><div class="k">تسلسلات مُختبرة</div><div class="v">${d.n_test_sequences}</div>
        <div class="match">عتبة ${pct(d.threshold)}</div></div>
    </div>
    <div class="card-title">أمثلة من مجموعة الاختبار</div>
    ${d.examples.map((x) => `
      <div class="ex-row">
        <span class="badge ${x.kind === "onset" ? "high" : "info"}">${x.kind === "onset" ? "قبل بداية هجوم" : "نافذة هادئة"}</span>
        <span class="mono">${pct(x.probability)} ${x.alert ? "· إنذار" : ""}</span>
        <svg viewBox="0 0 160 24" preserveAspectRatio="none"><path d="${sparkPath(x.trend, 160, 24)}"/></svg>
        <span class="${x.correct ? "ok" : "bad"}">${x.correct ? "✓ صحيح" : "✗ خطأ"}</span>
      </div>`).join("")}`;
});

/* ---------- الاستجابة ---------- */
$("#respondBtn").addEventListener("click", async () => {
  const box = $("#respondResult"), btn = $("#respondBtn");
  btn.disabled = true;
  box.innerHTML = loadingHtml("جاري تحليل نافذة المراقبة وتجميع المصادر…");
  let d;
  try { d = await post("/api/respond"); }
  catch (e) { box.innerHTML = OFFLINE; btn.disabled = false; return; }
  btn.disabled = false;
  btn.textContent = "حلّل نافذة أخرى";

  const ps = d.proposals || [];
  if (!ps.length) {
    box.innerHTML = `<div class="empty-state"><b>لا مصادر مشبوهة في هذه النافذة</b><span>كل الاتصالات ضمن السلوك الطبيعي.</span></div>`;
    return;
  }
  const enforced = ps.filter((p) => p.enforced).length;
  const avgConf = ps.reduce((s, p) => s + p.confidence, 0) / ps.length;
  box.innerHTML = `
    <div class="resp-sum">
      <div class="kpi brand"><div class="k">مصادر مشبوهة</div><div class="v">${ps.length}</div><div class="d">في نافذة المراقبة</div></div>
      <div class="kpi"><div class="k">إجراءات تُنفَّذ</div><div class="v" style="color:var(--danger)">${enforced}</div><div class="d">حظر، عزل، أو تحديد معدل</div></div>
      <div class="kpi good"><div class="k">متوسط ثقة القرار</div><div class="v">${pct(avgConf, 0)}</div><div class="d">قبل تطبيق أي إجراء</div></div>
    </div>
    <div class="card" style="padding:6px 8px">
      <div class="tbl"><table class="resp-table">
        <thead><tr><th>المصدر</th><th>نوع النشاط</th><th>الاتصالات</th><th>الثقة</th><th>الإجراء</th><th>المدة</th><th>هجوم فعلي</th></tr></thead>
        <tbody>${ps.map((p) => {
          const a = ACTION_AR[p.action] || [p.action, "info"];
          return `<tr>
            <td class="mono">${esc(p.source_ip)}</td>
            <td>${esc(famInfo(p.attack_type).ar)}</td>
            <td class="mono">${p.n_flows.toLocaleString("en")}</td>
            <td><div class="conf-cell"><div class="why-track"><span class="down" style="width:${p.confidence * 100}%"></span></div>
              <span class="mono">${pct(p.confidence, 0)}</span></div></td>
            <td><span class="badge ${a[1]}">${a[0]}</span></td>
            <td>${p.duration_min ? p.duration_min + " د" : "—"}</td>
            <td class="mono">${pct(p.true_ratio, 0)}</td></tr>`;
        }).join("")}</tbody></table></div>
    </div>
    <p class="sec-q" style="margin-top:10px">«هجوم فعلي» = نسبة اتصالات المصدر المصنّفة هجومًا في البيانات الحقيقية، للتحقق من صحة القرار.</p>`;
});

/* ---------- فحص الشبكة الحقيقية ---------- */
$("#scanBtn").addEventListener("click", async () => {
  const box = $("#scanResult"), btn = $("#scanBtn");
  btn.disabled = true;
  box.innerHTML = loadingHtml("جاري التقاط ترافيك شبكتك وتحليله… (~١٥ ثانية)");
  let d;
  try { d = await post("/api/livescan?count=1500&iface=any"); }
  catch (e) { box.innerHTML = OFFLINE; btn.disabled = false; return; }
  btn.disabled = false;
  if (d.error) {
    const title = d.error === "capture_failed" ? "تعذّر التقاط ترافيك الشبكة" : "تعذّر الفحص: " + esc(d.error);
    box.innerHTML = errorHtml(title, esc(d.hint || ""));
    return;
  }
  if (d.verdict === "no_traffic") {
    box.innerHTML = `<div class="empty-state"><b>لم يُلتقط ترافيك كافٍ</b><span>حرّك بعض الاتصالات وأعد المحاولة.</span></div>`;
    return;
  }
  const isAttack = d.verdict === "attack";
  const alertsHtml = d.alerts.length ? d.alerts.map((a) => `
    <div class="alert-row">
      <b>${esc(a.type)}</b><span class="mono">${esc(a.entity)}</span>
      <span class="badge high">${esc(a.evidence)}</span><span class="badge info">${esc(a.severity)}</span>
    </div>`).join("") :
    `<div class="match yes" style="padding:8px 0">لا تنبيهات سلوكية — السلوك ضمن الطبيعي ✓</div>`;
  box.innerHTML = `
    <div class="card" style="margin-bottom:14px">
      <div class="inc-head ${isAttack ? "attack" : "benign"}">
        <span class="badge ${isAttack ? "critical" : "safe"}">${isAttack ? "رُصد نشاط هجومي" : "الترافيك طبيعي"}</span>
        <span class="sec-q" style="margin:0">${d.flows} تدفق مُحلَّل</span>
      </div>
    </div>
    <div class="net-grid">
      <div class="card"><div class="card-title">الطبقة ١ — النموذج (لكل تدفق)</div>
        ${Object.entries(d.model).map(([k, v]) => `
          <div class="metric-row"><span class="lbl">${esc(k)}</span>
            <div class="why-track"><span class="down" style="width:${Math.min(v / d.flows * 100, 100)}%"></span></div>
            <span class="val">${v}</span></div>`).join("")}</div>
      <div class="card"><div class="card-title">الطبقة ٢ — الكاشف السلوكي</div>${alertsHtml}</div>
    </div>
    ${isAttack ? `<div class="note" style="margin-top:14px">${ICON.alert}<span><b>الحكم المدمج:</b> الكاشف السلوكي التقط ما فات النموذج اللحظي — وهذا يوضّح «فجوة المجال» بين الترافيك الحقيقي وبيئة التدريب، وكيف تعالجها الطبقة السلوكية.</span></div>
      <div style="margin-top:14px">${adviceCard("scanAdvice")}</div>` : ""}`;
  if (isAttack) {
    const ctx = "رُصد على الشبكة الحقيقية نشاط هجومي: " +
      d.alerts.map((a) => `${a.type} (${a.evidence})`).join("، ") + ".";
    getAdvice(ctx, "احظر المصادر المرصودة مؤقتًا، وراجع سجلات الأجهزة المستهدفة، وأغلق المنافذ غير الضرورية.")
      .then((a) => fillAdvice("scanAdvice", a));
  }
});

/* ---------- المراقبة الاستباقية الحية ---------- */
let monPoll = null;
async function startMonitor() {
  const box = $("#monResult"), btn = $("#monBtn");
  btn.disabled = true;
  box.innerHTML = loadingHtml("جاري بدء المراقبة وبناء أول نافذة زمنية…");
  try {
    const r = await post("/api/monitor/start?window=8&cycles=20");
    if (r.error) {
      btn.disabled = false;
      box.innerHTML = errorHtml("تعذّر البدء: " + esc(r.error));
      return;
    }
    if (monPoll) clearInterval(monPoll);
    monPoll = setInterval(pollMonitor, 3000);
    pollMonitor();
  } catch (e) {
    btn.disabled = false;
    box.innerHTML = OFFLINE;
  }
}
$("#monBtn").addEventListener("click", () => startMonitor());

async function pollMonitor() {
  const box = $("#monResult"), btn = $("#monBtn");
  let d;
  try { d = await api("/api/monitor/status"); }
  catch (e) { return; }

  const need = d.need || 10, got = d.collected || 0;
  const bars = (d.windows || []).slice(-need);
  const mx = Math.max(...bars.map((w) => w.total_flows || 0), 1);

  let predHtml = "";
  if (d.prediction) {
    const p = d.prediction;
    predHtml = `<div class="card" style="margin-top:14px">
      <span class="badge ${p.alert ? "critical" : "safe"}">${p.alert ? "إنذار استباقي: هجوم متوقَّع" : "لا خطر متوقَّع"}</span></div>`;
    // عند توقّع هجوم: نعرض التوصية التي يولّدها الخادم (state.advice)
    if (p.alert) {
      predHtml += `<div class="card advice" style="margin-top:14px"><div class="card-title">التوصية الأمنية</div>
        ${d.advice ? `<p>${esc(d.advice)}</p>` : '<span class="loading"></span> جاري توليد التوصية…'}</div>`;
    }
  }

  const done = !d.running && got >= need;
  box.innerHTML = `
    <div class="card">
      <div class="kv" style="border:none"><span>بناء التاريخ الزمني من شبكتك</span>
        <span class="mono">${got} / ${need} ${d.running ? '<span class="loading"></span>' : ""}</span></div>
      <div class="progress"><span style="width:${Math.min(got / need * 100, 100)}%"></span></div>
      <div class="card-title">نشاط النوافذ (عدد التدفقات)</div>
      <div class="bars">${bars.map((w) => `<div class="b" style="height:${(w.total_flows || 0) / mx * 100}%"></div>`).join("") ||
        '<span class="sec-q">بانتظار أول نافذة…</span>'}</div>
      ${got < need && d.running ? `<p class="sec-q" style="margin-top:12px">يحتاج ${need} نوافذ قبل أول تنبؤ. كل نافذة ~٢٠ ثانية.</p>` : ""}
    </div>
    ${predHtml}`;

  if (!d.running && (d.prediction || done)) {
    clearInterval(monPoll); monPoll = null;
    btn.disabled = false;
    btn.textContent = "أعد التنبؤ";
  }
}

/* ---------- المحلل الذكي (وكيل Claude) ---------- */
const TOOL_AR = {
  incident_overview: "نظرة عامة", suspicious_sources: "المصادر المشبوهة", explain_source: "تفسير السلوك",
  forecast_next_minute: "التنبؤ", check_policy: "فحص السياسة", propose_action: "اقتراح إجراء",
  source_activity: "نشاط العنوان", sample_requests: "عينة الطلبات", anomaly_context: "سياق الشذوذ",
  campaign_overview: "نظرة على الحملة", specialist_report: "تقرير المتخصص", attacker_profile: "ملف المهاجم",
};
const REPORT_SEV = {
  critical: ["حرج", "critical"], high: ["مرتفع", "high"], medium: ["متوسط", "medium"],
  low: ["منخفض", "info"], none: ["لا خطر", "safe"],
};
const STATUS_AR = {
  pending: "بانتظار قرارك", applied: "طُبّق", rejected: "رُفض", refused: "مرفوض من الحاجز",
  covered: "مغطّى بقاعدة سابقة", no_enforcement: "مراقبة فقط", merged: "دُمج في الحملة", superseded: "استُبدل",
};
const STAGE_AR = { weakness: ["ثغرة مكشوفة", "medium"], recon: ["استطلاع", "info"], access: ["محاولة دخول", "high"],
  exploit: ["استغلال أو تسريب", "critical"], disruption: ["تعطيل", "critical"] };
const KIND_AR = { log: "السجلات", network: "الشبكة", monitor: "المراقبة", campaign: "حملة" };
let agentIncident = null, agentStream = null, agentDemo = false;

$("#agentFamily").innerHTML = '<option value="random">عشوائي</option>' +
  Object.entries(FAMILY).filter(([k]) => k !== "BENIGN")
    .map(([k, f]) => `<option value="${esc(k)}">${f.ar}</option>`).join("") +
  '<option value="BENIGN">ترافيك طبيعي فقط</option>';

async function initAgent() {
  try {
    const s = await tenantApi("/api/v1/agent/status");
    agentDemo = s.mode === "demo";
    $("#agentSetup").hidden = !agentDemo;
    $("#agentModel").textContent = agentDemo ? "عرض تجريبي بلا Claude" : s.model;
    $("#agentModel").classList.toggle("mono", !agentDemo);
  } catch (e) {}
}

function addStep(s) {
  const li = document.createElement("li");
  li.className = "tl-step" + (s.is_error ? " err" : "");
  li.innerHTML = `<div class="tl-head"><span class="badge info">${TOOL_AR[s.tool] || esc(s.tool)}</span>
      <span>${esc(s.summary)}</span></div>
    <details><summary>التفاصيل</summary><pre class="mono">${esc(JSON.stringify(s.result, null, 2))}</pre></details>`;
  $("#agentTimeline").appendChild(li);
}

function proposalsHtml(ps) {
  ps = ps.filter((p) => p.status !== "superseded");      // مقترح تشغيل سابق للمنسّق حلّ محله الأحدث
  if (!ps.length) return '<p class="sec-q">لا توجد إجراءات مقترحة.</p>';
  return ps.map((p) => {
    const a = ACTION_AR[p.action] || [p.action, "info"];
    return `<div class="proposal" data-id="${p.id}">
      <div><span class="mono">${esc(p.source_ip)}</span> · <span class="badge ${a[1]}">${a[0]}</span>
        ${p.duration_min ? ` · ${p.duration_min} د` : ""}
        <div class="sec-q" style="margin:4px 0 0">${esc((p.reasons || []).join("، "))}</div>
        <div class="executor" data-executor="${p.id}">${esc(p.executor || "")}</div></div>
      <div class="p-actions">${p.status === "pending"
        ? '<button class="btn-primary" data-decide="approve">وافق</button><button class="btn-ghost" data-decide="reject">ارفض</button>'
        : `<span class="badge info">${STATUS_AR[p.status] || esc(p.status)}</span>`}</div></div>`;
  }).join("");
}

function renderReport(d) {
  const r = d.report, sev = REPORT_SEV[r.severity] || REPORT_SEV.medium;
  $("#agentReport").innerHTML = `
    <div class="card">
      <div class="inc-head"><h3>${r.stages ? "تقرير المنسّق" : "تقرير المحلل"}</h3>${agentDemo ? '<span class="badge info">عرض تجريبي</span>' : ""}
        <span class="badge ${sev[1]}">الخطورة: ${sev[0]}</span></div>
      <p class="report-summary">${esc(r.summary_owner)}</p>
      ${r.stages ? `<ol class="stages">${r.stages.map((x) => {
        const st = STAGE_AR[x.stage] || [x.stage, "info"];
        return `<li><span class="badge ${st[1]}">${st[0]}</span> ${esc(x.description)}
          <span class="when mono">${esc(x.incident_id)}</span></li>`;
      }).join("")}</ol>` : ""}
      ${r.findings.map((f) => `<div class="finding"><b class="mono">${esc(f.source_ip)}</b> — ${esc(f.assessment)}
        <ul>${f.evidence.map((x) => `<li>${esc(x)}</li>`).join("")}</ul></div>`).join("")}
      <div class="kv"><span>ما يجب مراقبته</span><span>${esc(r.watch_next)}</span></div>
      <div class="kv"><span>ثقة المحلل</span><span class="mono">${pct(r.confidence, 0)}</span></div>
    </div>
    <div class="card" style="margin-top:14px">
      <div class="card-title">الإجراءات المقترحة — القرار لك</div>${proposalsHtml(d.proposals)}</div>`;
}

function renderAgentError(d) {
  $("#agentReport").innerHTML = errorHtml("توقّف المحلل: " + esc(d.message), "عرضنا مقترحات القواعد الثابتة بدلًا منه.") +
    `<div class="card" style="margin-top:14px"><div class="card-title">مقترحات القواعد الثابتة</div>${proposalsHtml(d.proposals)}</div>`;
}

function resetAgentView() {
  $("#campaignBox").innerHTML = "";
  $("#agentTimeline").innerHTML = "";
  $("#agentTruth").textContent = "";
  $("#chatLog").innerHTML = "";
  $("#agentReport").innerHTML = loadingHtml("المحلل يحقق في الحادثة…");
}

$("#agentStart").addEventListener("click", async () => {
  const btn = $("#agentStart");
  btn.disabled = true;
  resetAgentView();
  let r;
  try {
    r = await tenantApi("/api/v1/agent/investigate?family=" + encodeURIComponent($("#agentFamily").value), "POST");
  } catch (e) {
    $("#agentReport").innerHTML = errorHtml("تعذّر بدء التحقيق", esc(e.message));
    btn.disabled = false;
    return;
  }
  streamIncident(r.incident_id);
});

/* بث تحقيق أي حادثة (محاكاة أو حقيقية): الخط الزمني ثم التقرير */
async function streamIncident(id) {
  const btn = $("#agentStart");
  resetAgentView();
  let token;
  try {
    ({ token } = await tenantApi("/api/v1/agent/stream-token", "POST", { incident_id: id }));
  } catch (e) {
    $("#agentReport").innerHTML = errorHtml("تعذّر فتح التحقيق", esc(e.message));
    btn.disabled = false;
    return;
  }
  agentIncident = id;
  if (agentStream) agentStream.close();
  agentStream = new EventSource(API + "/api/v1/agent/stream/" + encodeURIComponent(id) +
    "?token=" + encodeURIComponent(token));
  agentStream.addEventListener("step", (e) => addStep(JSON.parse(e.data)));
  agentStream.addEventListener("report", (e) => renderReport(JSON.parse(e.data)));
  agentStream.addEventListener("agent_error", (e) => renderAgentError(JSON.parse(e.data)));
  agentStream.addEventListener("done", (e) => {
    const d = JSON.parse(e.data);
    agentStream.close();
    btn.disabled = false;
    if (d.truth_family == null) {
      $("#agentTruth").innerHTML = `حادثة حقيقية من سجلات منشأتك (${esc(id)}) · استغرق التحقيق ${d.seconds} ثانية`;
      return;
    }
    btn.textContent = "حاكِ هجومًا آخر";
    const truth = d.truth_family === "BENIGN" ? "ترافيك طبيعي فقط" : famInfo(d.truth_family).ar;
    $("#agentTruth").innerHTML = `السيناريو الحقيقي: <b>${esc(truth)}</b> · استغرق ${d.seconds} ثانية`;
  });
}

$("#agentReport").addEventListener("click", async (e) => {
  const b = e.target.closest("[data-decide]");
  if (!b) return;
  const row = b.closest(".proposal");
  row.querySelectorAll("button").forEach((x) => (x.disabled = true));
  try {
    const r = await tenantApi("/api/v1/agent/decide", "POST",
      { incident_id: agentIncident, proposal_id: Number(row.dataset.id), decision: b.dataset.decide });
    row.querySelector(".p-actions").innerHTML =
      `<span class="badge info">${esc(STATUS_AR[r.status] || r.status || r.error)}</span>`;
    if (r.note) toast(r.note);
    if (b.dataset.decide === "approve") watchExecutor(Number(row.dataset.id));
  } catch (err) {
    toast(err.message);
    row.querySelectorAll("button").forEach((x) => (x.disabled = false));
  }
});

function addBubble(role, html) {
  const d = document.createElement("div");
  d.className = "bubble " + role;
  d.innerHTML = html;
  $("#chatLog").appendChild(d);
  d.scrollIntoView({ block: "nearest" });
  return d;
}
async function sendChat(text) {
  if (!agentIncident) { toast("ابدأ تحقيقًا أولًا"); return; }
  addBubble("user", esc(text));
  const pending = addBubble("agent", '<span class="loading"></span>');
  try {
    const r = await tenantApi("/api/v1/agent/chat", "POST", { incident_id: agentIncident, message: text });
    pending.innerHTML = r.error
      ? `<span style="color:var(--danger)">${esc(r.error)}</span>`
      : esc(r.reply) + (r.steps.length ? `<div class="sec-q" style="margin:6px 0 0">${r.steps.map(esc).join(" · ")}</div>` : "");
  } catch (e) {
    pending.innerHTML = `<span style="color:var(--danger)">${esc(e.message)}</span>`;
  }
}
$("#chatForm").addEventListener("submit", (e) => {
  e.preventDefault();
  const v = $("#chatInput").value.trim();
  if (!v) return;
  $("#chatInput").value = "";
  sendChat(v);
});
$$("[data-ask]").forEach((b) => b.addEventListener("click", () => sendChat(b.textContent)));

/* ---------- المنشأة: التسجيل، الدخول، الإعدادات ---------- */
function showKeys(keys) {
  $("#ingestKey").textContent = keys.ingest_key;
  $("#dashKey").textContent = keys.dashboard_key;
  $("#keysDialog").showModal();
}
$$("[data-copy]").forEach((b) => b.addEventListener("click", () => {
  navigator.clipboard.writeText($("#" + b.dataset.copy).textContent)
    .then(() => toast("نُسخ المفتاح"), () => toast("انسخ المفتاح يدويًا"));
}));
$("#keysDone").addEventListener("click", () => { $("#keysDialog").close(); loadTenant(); });

$("#signupForm").addEventListener("submit", async (e) => {
  e.preventDefault();
  try {
    const r = await fetch(API + "/api/v1/tenants", {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ name: $("#signupName").value }),
    });
    const d = await r.json();
    if (!r.ok) { toast(typeof d.detail === "string" ? d.detail : "تعذّر التسجيل"); return; }
    setDashKey(d.dashboard_key);
    $("#signupName").value = "";
    showKeys(d);
  } catch (err) {
    toast("تعذّر الاتصال بالخادم");
  }
});

$("#loginForm").addEventListener("submit", (e) => {
  e.preventDefault();
  setDashKey($("#loginKey").value.trim());
  $("#loginKey").value = "";
  loadTenant();
});

async function loadTenant() {
  let me;
  try { me = await tenantApi("/api/v1/me"); }
  catch (e) { toast(e.message); return; }
  $("#tenantName").textContent = me.name;
  $("#tenantBox").hidden = false;
  $("#tenantInfo").innerHTML = `
    <div class="kv"><span>الاسم</span><span>${esc(me.name)}</span></div>
    <div class="kv"><span>المعرّف</span><span class="mono">${esc(me.tenant_id)}</span></div>
    <div class="kv"><span>تاريخ التسجيل</span><span>${new Date(me.created_at * 1000).toLocaleDateString("ar")}</span></div>`;
  $("#ingestExample").textContent =
    `# web server logs (Nginx/Apache)\ncurl -X POST ${location.origin}/api/v1/ingest/web \\\n  -H "Authorization: Bearer $INGEST_KEY" \\\n  --data-binary @/var/log/nginx/access.log\n\n` +
    `# firewall logs (iptables/UFW)\ncurl -X POST ${location.origin}/api/v1/ingest/firewall \\\n  -H "Authorization: Bearer $INGEST_KEY" \\\n  --data-binary @/var/log/ufw.log`;
  $("#agentExample").textContent =
    `pip install scapy numpy\nsudo setcap cap_net_raw+eip "$(readlink -f "$(which python3)")"\n` +
    `python3 -m sensor.agent --url ${location.origin} --key $INGEST_KEY --iface eth0`;
  fillSettings(me.settings);
  initAgent();
  refreshLogs();
  if (document.body.dataset.page === "login") setPage(afterLoginPage);
}

function logout() {
  setDashKey(null);
  $("#tenantBox").hidden = true;
  if (TENANT_PAGES.has(document.body.dataset.page)) setPage(document.body.dataset.page);   // يعيد لشاشة الدخول
}
$$("[data-logout]").forEach((b) => b.addEventListener("click", logout));

function fillSettings(s) {
  $("#webhookUrl").value = s.webhook_url || "";
  $("#allowlist").value = s.allowlist.join("\n");
  $("#secretRow").hidden = !s.webhook_secret;
  $("#webhookSecret").textContent = s.webhook_secret || "";
  $("#telegramToken").value = "";
  $("#telegramToken").placeholder = s.telegram_token || "123456:ABC-…";
  $("#telegramChat").value = s.telegram_chat_id || "";
}

$("#settingsForm").addEventListener("submit", async (e) => {
  e.preventDefault();
  try {
    fillSettings(await tenantApi("/api/v1/settings", "PUT", {
      webhook_url: $("#webhookUrl").value.trim() || null,
      allowlist: $("#allowlist").value.split("\n").map((s) => s.trim()).filter(Boolean),
      telegram_token: $("#telegramToken").value.trim() || null,      // فارغ = بلا تغيير
      telegram_chat_id: $("#telegramChat").value.trim(),
    }));
    toast("حُفظت الإعدادات");
  } catch (err) {
    toast(err.message);
  }
});

$("#rotateBtn").addEventListener("click", async () => {
  if (!confirm("سيتوقف المفتاحان الحاليان فورًا. متابعة؟")) return;
  try {
    const keys = await tenantApi("/api/v1/keys/rotate", "POST");
    setDashKey(keys.dashboard_key);
    showKeys(keys);
  } catch (err) {
    toast(err.message);
  }
});

if (dashKey()) loadTenant();

/* ---------- السجلات: المصادر والحوادث في «منشأتي» ---------- */
const LOG_TYPE_AR = {
  brute_force: "تخمين كلمات المرور", path_scan: "فحص مسارات الموقع", flood: "إغراق بالطلبات",
  injection: "محاولة حقن (SQL/XSS)", fw_port_scan: "فحص منافذ الخادم", fw_flood: "اتصالات محظورة متكررة",
  anomaly: "سلوك غير معتاد", site_down: "الموقع متعطل", exposed_file: "ملف حساس مكشوف",
  net_scan: "فحص منافذ الخادم (شبكة)", net_sweep: "مسح أجهزة الشبكة", net_brute: "تخمين على خدمة دخول",
  net_flood: "إغراق بالاتصالات", net_ddos: "هجوم موزّع (DDoS)", net_model: "هجوم رصده النموذج",
};
const INC_STATUS_AR = { open: ["بانتظار التحقيق", "info"], investigating: ["بانتظار قرارك", "high"], closed: ["مغلقة", "safe"],
  merged: ["دُمجت في حملة", "info"] };
const MONITOR_STATUS_AR = { open: ["مفتوحة حتى الإصلاح", "high"], closed: ["حُلّت", "safe"] };
const fmtTime = (ts) => ts ? new Date(ts * 1000).toLocaleString("ar", { dateStyle: "short", timeStyle: "short" }) : "—";

function agentBox(a) {
  const state = { connected: ["متصل", "safe"], offline: ["منقطع", "critical"] }[a.state];
  if (!state) return `<div class="source"><div class="k">وكيل الخادم (الشبكة)</div><div class="v">لم يتصل بعد</div>
    <div class="d">اربطه من «كيف أربط وكيل الخادم؟» أدناه</div></div>`;
  return `<div class="source"><div class="k">وكيل الخادم (الشبكة) · <span class="mono">${esc(a.host)}</span></div>
    <div class="v"><span class="badge ${state[1]}">${state[0]}</span> ${a.flows_per_minute.toLocaleString("ar")} اتصال/دقيقة</div>
    <div class="d">آخر نافذة: ${fmtTime(a.last_window)}${a.truncated_last_hour ? " · مقتطعة (أكثر من 5000 اتصال)" : ""}</div></div>`;
}
function forecastHtml(f) {
  if (!f) return "";
  if (f.state === "learning") return f.windows ? `<div class="learn">مؤشر التنبؤ (LSTM) يجمع نوافذ الشبكة: ${f.windows} من ${f.needed}
    <div class="progress"><span style="width:${f.windows / f.needed * 100}%"></span></div></div>` : "";
  if (f.state !== "ready") return `<div class="learn">مؤشر التنبؤ غير متاح: ${esc(f.detail)}</div>`;
  return `<div class="learn"><span class="badge ${f.alert ? "high" : "safe"}">${f.alert ? "إنذار مبكر" : "هادئ"}</span>
    احتمال بدء هجوم على الشبكة في الدقيقة التالية: <b>${Math.round(f.probability * 100)}%</b> (مؤشر فقط، لا يفتح حادثة)</div>`;
}

async function refreshLogs() {
  if (!dashKey()) return;
  let src, inc;
  try { [src, inc] = await Promise.all([tenantApi("/api/v1/sources"), tenantApi("/api/v1/incidents")]); }
  catch (e) { return; }
  const box = (label, v) => `<div class="source"><div class="k">${label}</div>
    <div class="v">${v.events.toLocaleString("ar")} حدث</div><div class="d">آخر حدث: ${fmtTime(v.last_ts)}</div></div>`;
  $("#sourcesBox").innerHTML = box("سجلات الموقع (Nginx/Apache)", src.web) + box("الجدار الناري (iptables/UFW)", src.firewall)
    + agentBox(src.agent);
  $("#forecastBox").innerHTML = forecastHtml(src.agent.forecast);
  const a = src.anomaly;
  $("#anomalyBox").innerHTML = a.state === "ready"
    ? `<div class="learn"><span class="badge safe">نموذج الشذوذ جاهز</span> تعلّم من ${a.windows.toLocaleString("ar")} نافذة من سلوك زوارك</div>`
    : `<div class="learn">نموذج الشذوذ يتعلّم السلوك الطبيعي لموقعك: ${a.windows} من ${a.needed} نافذة
       <div class="progress"><span style="width:${Math.min(a.windows / a.needed * 100, 100)}%"></span></div></div>`;
  const row = (i, cls = "") => {
    const st = (i.kind === "monitor" ? MONITOR_STATUS_AR : INC_STATUS_AR)[i.status] || [i.status, "info"];
    const sev = REPORT_SEV[i.severity] || REPORT_SEV.medium;
    const tag = i.kind === "campaign" ? '<span class="badge critical">حملة</span> '
      : i.campaign ? `<span class="in-camp">ضمن الحملة ${esc(i.campaign)} · ${KIND_AR[i.kind] || ""}</span> ` : "";
    return `<button class="inc-row ${cls}" data-incident="${esc(i.id)}" data-kind="${esc(i.kind)}"><span class="badge ${sev[1]}">${sev[0]}</span>
      <span>${tag}${i.types.map((t) => esc(LOG_TYPE_AR[t] || t)).join("، ")}</span>
      <span class="badge ${st[1]}">${st[0]}</span><span class="when">${fmtTime(i.opened_at)}</span></button>`;
  };
  const camps = inc.incidents.filter((i) => i.kind === "campaign" && i.status !== "merged");
  const rest = inc.incidents.filter((i) => i.kind !== "campaign" && !camps.some((c) => c.id === i.campaign));
  $("#incidentsBox").innerHTML = inc.incidents.length ? camps.map((c) => `<div class="camp">${row(c, "camp-head")}${
    inc.incidents.filter((i) => i.campaign === c.id).map((i) => row(i, "camp-member")).join("")}</div>`).join("")
    + rest.map((i) => row(i)).join("") : `<div class="empty-state"><b>لا توجد حوادث</b>
      <span>عندما يرصد النظام هجومًا في سجلاتك تظهر الحادثة هنا ويبدأ المحلل التحقيق تلقائيًا.</span></div>`;
}
$("#incidentsBox").addEventListener("click", (e) => {
  const b = e.target.closest("[data-incident]");
  if (b) (b.dataset.kind === "monitor" ? openMonitorIncident : openIncident)(b.dataset.incident);
});

async function openIncident(id) {
  setPage("analyst");
  $("#agentReport").innerHTML = loadingHtml("جاري فتح الحادثة…");
  for (let i = 0; i < 30; i++) {
    let d;
    try { d = await tenantApi("/api/v1/incidents/" + encodeURIComponent(id)); }
    catch (e) { $("#agentReport").innerHTML = errorHtml("تعذّر فتح الحادثة", esc(e.message)); return; }
    if (d.investigation) {
      const stream = streamIncident(id);
      if (d.campaign) renderCampaign(d.campaign);
      return stream;
    }
    if (i === 0 && !d.queued) {     // تحقيق سابق لإعادة تشغيل الخادم: نبدأ تحقيقًا جديدًا
      await tenantApi(`/api/v1/incidents/${encodeURIComponent(id)}/investigate`, "POST").catch(() => {});
    }
    $("#agentReport").innerHTML = loadingHtml("الحادثة بانتظار دورها في التحقيق…");
    await new Promise((r) => setTimeout(r, 1000));
  }
  $("#agentReport").innerHTML = errorHtml("لم يبدأ التحقيق بعد", "حاول بعد قليل.");
}
setInterval(() => { if (document.body.dataset.page === "tenant") refreshLogs(); }, 10000);

/* الحملة: سلسلة المراحل وأسباب الربط فوق خطوات المنسّق */
function renderCampaign(c) {
  const chain = c.stages.map((x) => {
    const st = STAGE_AR[x.stage] || [x.stage, "info"];
    return `<button class="stage" data-incident="${esc(x.incident_id)}" data-kind="${esc(x.kind)}">
      <span class="badge ${st[1]}">${st[0]}</span><span>${esc(x.description)}</span>
      <span class="when">${fmtTime(x.ts)}</span></button>`;
  }).join('<span class="stage-arrow" aria-hidden="true">←</span>');
  const reasons = [...new Set(c.links.map((l) => l.reason))];
  $("#campaignBox").innerHTML = `<div class="card campaign">
    <div class="card-title">الحملة ${esc(c.campaign_id)} · ${c.members.length} حوادث من
      ${[...new Set(c.members.map((m) => KIND_AR[m.kind]))].join("، ")}</div>
    <div class="chain">${chain}</div>
    <div class="card-title" style="margin-top:12px">لماذا رُبطت؟</div>
    <ul class="reasons">${reasons.map((r) => `<li>${esc(r)}</li>`).join("")}</ul></div>`;
}
$("#campaignBox").addEventListener("click", (e) => {
  const b = e.target.closest("[data-incident]");
  if (b) (b.dataset.kind === "monitor" ? openMonitorIncident : openIncident)(b.dataset.incident);
});

/* ---------- التنبيهات: السرّ، التجربة، سجل التسليمات، رد المنفّذ ---------- */
const DELIVERY_AR = { delivered: ["سُلّم", "safe"], pending: ["قيد الإرسال", "info"], failed: ["فشل", "critical"] };
const EVENT_AR = { "incident.report": "تقرير حادثة", "action.execute": "أمر تنفيذ", "action.result": "نتيجة قرار", test: "تجربة" };

async function refreshDeliveries() {
  if (!dashKey()) return;
  let d;
  try { d = await tenantApi("/api/v1/deliveries"); } catch (e) { return; }
  $("#deliveriesBox").innerHTML = d.deliveries.length ? d.deliveries.map((x) => {
    const st = DELIVERY_AR[x.status] || [x.status, "info"];
    return `<div class="dl-row"><span class="badge ${st[1]}">${st[0]}</span><span>${EVENT_AR[x.event] || esc(x.event)}</span>
      <span class="err" title="${esc(x.last_error || x.response)}">${esc(x.last_error || x.response || "")}</span>
      <span class="when">${x.channel === "telegram" ? "Telegram" : "Webhook"} · ${x.attempts} محاولة · ${fmtTime(x.created_at)}</span></div>`;
  }).join("") : '<p class="sec-q">لا رسائل بعد. اضبط Webhook أو Telegram ثم اضغط «اختبار».</p>';
}
setInterval(() => { if (document.body.dataset.page === "settings") refreshDeliveries(); }, 5000);

$$("[data-test]").forEach((b) => b.addEventListener("click", async () => {
  try {
    await tenantApi("/api/v1/notify/test", "POST", { channel: b.dataset.test });
    toast("أُرسلت رسالة تجربة");
    setTimeout(refreshDeliveries, 2500);
  } catch (err) {
    toast(err.message);
  }
}));

$("#rotateSecretBtn").addEventListener("click", async () => {
  if (!confirm("سيتوقف المنفّذ عن قبول الرسائل حتى تحدّث السرّ فيه. متابعة؟")) return;
  try {
    const r = await tenantApi("/api/v1/settings/webhook-secret/rotate", "POST");
    $("#webhookSecret").textContent = r.webhook_secret;
    toast("سرّ جديد: حدّثه في المنفّذ");
  } catch (err) {
    toast(err.message);
  }
});

/* بعد الموافقة: ننتظر رد المنفّذ على خادم المنشأة (حوادث السجلات) */
async function watchExecutor(proposalId) {
  if (!String(agentIncident).startsWith("log-")) return;
  for (let i = 0; i < 10; i++) {
    await new Promise((r) => setTimeout(r, 1500));
    let d;
    try { d = await tenantApi("/api/v1/incidents/" + encodeURIComponent(agentIncident)); } catch (e) { return; }
    const p = (d.proposals || []).find((x) => x.id === proposalId);
    if (p && p.executor) {
      const el = document.querySelector(`[data-executor="${proposalId}"]`);
      if (el) el.textContent = p.executor;
      return;
    }
  }
}

/* ---------- المراقبة الخارجية: المواقع ودرجاتها وملاحظاتها ---------- */
const SITE_STATE_AR = { up: ["يعمل", "safe"], slow: ["بطيء", "medium"], down: ["متعطل", "critical"] };

function findingHtml(siteId, f) {
  const sev = REPORT_SEV[f.severity] || REPORT_SEV.medium, id = `${siteId}-${f.key.replace(/\W/g, "_")}`;
  const fix = (label, code, n) => `<div class="fix"><div class="fix-head"><span>${label}</span>
      <button class="btn-ghost" type="button" data-copyfrom="fix-${id}-${n}">نسخ</button></div>
      <pre class="code mono" id="fix-${id}-${n}">${esc(code)}</pre></div>`;
  return `<details class="finding" data-fid="${esc(id)}"><summary><span class="badge ${sev[1]}">${sev[0]}</span>
      <span>${f.key.startsWith("exposed:")
        ? `${esc(f.title.replace(f.detail, ""))}<span class="mono">${esc(f.detail)}</span>`   // المسار معزول عن اتجاه النص العربي
        : esc(f.title) + (f.detail ? ` <span class="mono">(${esc(f.detail)})</span>` : "")}</span>
      <span class="ded">−${f.deduction}</span></summary>
    <div class="finding-body">${esc(f.risk)}${fix("Nginx", f.fix.nginx, 1)}${fix("Apache", f.fix.apache, 2)}</div></details>`;
}

function siteHtml(s) {
  const st = SITE_STATE_AR[s.state] || ["بانتظار أول فحص", "info"];
  const meta = [`<span class="badge ${st[1]}">${st[0]}</span>`];
  if (s.checked_at) meta.push(`آخر فحص ${fmtTime(s.checked_at)}`);
  if (s.state && s.state !== "down") meta.push(`<span class="mono">${s.ms} ms</span>`);
  if (s.state === "down") meta.push(esc(s.detail));
  if (s.uptime_24h !== null) meta.push(`التوفر خلال 24 ساعة: ${s.uptime_24h}%`);
  const grade = s.grade
    ? `<div class="grade g-${s.grade}" title="درجة الأمان">${s.grade}<small>${s.score}/100</small></div>`
    : `<div class="grade g-none">${s.verified ? "بانتظار الفحص" : "بانتظار التحقق"}</div>`;
  const v = s.verification;
  const body = !s.verified
    ? `<div class="verify"><b>تحقّق من ملكيتك للموقع</b> لنبدأ فحص ترويسات الأمان والملفات المكشوفة. اختر طريقة واحدة:
        <ol><li>ملف على <code class="mono">${esc(v.file_url)}</code> يحوي الرمز.</li>
          <li>أو سجل DNS من نوع TXT باسم <code class="mono">${esc(v.dns_name)}</code> وقيمته الرمز.</li></ol>
        <div class="inline">الرمز: <code class="mono" id="tok-${s.id}">${esc(v.token)}</code>
          <button class="btn-ghost" type="button" data-copyfrom="tok-${s.id}">نسخ</button>
          <button class="btn-primary" type="button" data-verify="${s.id}">تحقّق</button></div></div>`
    : !s.deep_at ? `<p class="sec-q findings">تم التحقق (${s.verify_method === "dns" ? "DNS" : "ملف"}). الفحص العميق يبدأ عند عودة الموقع للعمل.</p>`
    : s.findings.length
      ? `<div class="findings"><div class="card-title">الملاحظات (${s.findings.length}) — افتح أي ملاحظة لترى الخطر والإصلاح</div>
          ${s.findings.map((f) => findingHtml(s.id, f)).join("")}</div>`
      : `<p class="sec-q findings">لا ملاحظات: ترويسات الأمان مكتملة ولا ملفات مكشوفة.</p>`;
  return `<div class="card site" data-site="${s.id}" data-url="${esc(s.url)}">
    <div class="card-head"><div><b class="mono">${esc(s.url)}</b><div class="site-meta">${meta.join(" · ")}</div></div>${grade}</div>
    ${body}
    <div class="site-actions"><button class="btn-ghost" data-check="${s.id}">افحص الآن</button>
      <button class="btn-ghost" data-delsite="${s.id}">حذف</button></div></div>`;
}

async function refreshSites() {
  if (!dashKey()) return;
  let d;
  try { d = await tenantApi("/api/v1/monitor/sites"); } catch (e) { return; }
  const open = new Set($$("#sitesBox details[open]").map((x) => x.dataset.fid));   // لا نطوي ما فتحه المستخدم
  $("#sitesBox").innerHTML = d.sites.length ? d.sites.map(siteHtml).join("")
    : `<div class="card site"><div class="empty-state"><b>لا مواقع بعد</b>
        <span>أضف رابط موقعك أعلاه لنبدأ مراقبة توفره ودرجة أمانه.</span></div></div>`;
  $$("#sitesBox details").forEach((x) => { if (open.has(x.dataset.fid)) x.open = true; });
}
setInterval(() => { if (document.body.dataset.page === "monitor") refreshSites(); }, 15000);

$("#siteForm").addEventListener("submit", async (e) => {
  e.preventDefault();
  try {
    await tenantApi("/api/v1/monitor/sites", "POST", { url: $("#siteUrl").value.trim() });
    $("#siteUrl").value = "";
    toast("أُضيف الموقع، وأول فحص توفر خلال ثوانٍ");
    refreshSites();
    setTimeout(refreshSites, 4000);
  } catch (err) {
    toast(err.message);
  }
});

$("#sitesBox").addEventListener("click", async (e) => {
  const copy = e.target.closest("[data-copyfrom]");
  if (copy) {
    navigator.clipboard.writeText(document.getElementById(copy.dataset.copyfrom).textContent)
      .then(() => toast("نُسخ"), () => toast("انسخ يدويًا"));
    return;
  }
  const b = e.target.closest("[data-verify],[data-check],[data-delsite]");
  if (!b) return;
  const id = b.dataset.verify || b.dataset.check || b.dataset.delsite, base = "/api/v1/monitor/sites/" + id;
  if (b.dataset.delsite && !confirm("حذف الموقع من المراقبة؟ تُغلق حوادثه المفتوحة.")) return;
  b.disabled = true;
  try {
    if (b.dataset.verify) {
      const r = await tenantApi(base + "/verify", "POST");
      toast(r.verified ? "تم التحقق، وانتهى الفحص العميق"
        : r.dns_unavailable ? "لم نجد الملف، والتحقق بـ DNS غير متاح على الخادم" : "لم نجد الرمز في الملف ولا في DNS بعد");
    } else if (b.dataset.check) {
      await tenantApi(base + "/check", "POST");
      toast("انتهى الفحص");
    } else {
      await tenantApi(base, "DELETE");
      toast("حُذف الموقع");
    }
  } catch (err) {
    toast(err.message);
  }
  b.disabled = false;
  refreshSites();
});

/* حادثة مراقبة: لا تحقيق للمحلل، بل ننقل لبطاقة الموقع حيث الإصلاح */
async function openMonitorIncident(id) {
  let url = null;
  try { url = (await tenantApi("/api/v1/incidents/" + encodeURIComponent(id))).alerts[0]?.details?.url; } catch (e) {}
  setPage("monitor");
  await refreshSites();
  const card = $$("#sitesBox [data-url]").find((c) => c.dataset.url === url);
  if (!card) return;
  card.scrollIntoView({ behavior: "smooth", block: "start" });
  card.classList.add("flash");
  setTimeout(() => card.classList.remove("flash"), 1800);
}
