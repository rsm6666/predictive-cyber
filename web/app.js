/* ===================================================================
   واجهة مركز التنبؤ — منطق الاتصال بخادم FastAPI
   =================================================================== */
const API = location.origin.includes("8000") ? "" : "http://localhost:8000";

const $ = (s) => document.querySelector(s);
const $$ = (s) => [...document.querySelectorAll(s)];

function toast(msg) {
  const t = $("#toast"); t.textContent = msg; t.classList.add("show");
  clearTimeout(t._t); t._t = setTimeout(() => t.classList.remove("show"), 2600);
}
async function api(path, opts) {
  const r = await fetch(API + path, opts);
  if (!r.ok) throw new Error("HTTP " + r.status);
  return r.json();
}

/* ---------- الوضع الليلي ---------- */
const themeBtn = $("#themeBtn");
function applyTheme(t) {
  document.documentElement.setAttribute("data-theme", t);
  themeBtn.textContent = t === "dark" ? "☀️" : "🌙";
  try { localStorage.setItem("theme", t); } catch (e) {}
}
themeBtn.addEventListener("click", () => {
  const cur = document.documentElement.getAttribute("data-theme");
  applyTheme(cur === "dark" ? "light" : "dark");
});
try {
  const saved = localStorage.getItem("theme");
  if (saved) applyTheme(saved);
} catch (e) {}

/* ---------- التبويبات والمجموعات ---------- */
function showPanel(tab) {
  $$(".panel").forEach((p) => p.classList.remove("on"));
  const el = $("#p-" + tab);
  if (el) el.classList.add("on");
}
$$(".subtabs button").forEach((b) => b.addEventListener("click", () => {
  [...b.parentElement.children].forEach((x) => x.classList.remove("on"));
  b.classList.add("on");
  showPanel(b.dataset.tab);
}));
$$("#groupSwitch button").forEach((b) => b.addEventListener("click", () => {
  $$("#groupSwitch button").forEach((x) => x.classList.remove("on"));
  b.classList.add("on");
  const real = b.dataset.group === "real";
  $("#tabs-real").style.display = real ? "" : "none";
  $("#tabs-proof").style.display = real ? "none" : "";
  const row = real ? $("#tabs-real") : $("#tabs-proof");
  const active = row.querySelector("button.on") || row.querySelector("button");
  active.classList.add("on");
  showPanel(active.dataset.tab);
}));

/* ---------- التوصية الأمنية (عبر Ollama) ---------- */
async function getAdviceText(context) {
  try {
    const r = await api("/api/recommend", {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ context }),
    });
    if (r.recommendation) return r.recommendation;
    return "التوصية غير متاحة — شغّل Ollama لتفعيلها.";
  } catch (e) {
    return "تعذّر توليد التوصية (تأكد أن Ollama يعمل).";
  }
}
function adviceCard(text, loading) {
  return `<div style="margin-top:14px;padding:12px 14px;background:var(--accent-dim);border-radius:10px;font-size:.86rem">
    <b>🛡️ التوصية الأمنية</b>
    <div style="margin-top:6px;white-space:pre-wrap;color:var(--ink)">${
      loading ? '<span class="loading"></span> جاري توليد التوصية…' : text}</div></div>`;
}

/* ---------- كشف وتحليل ---------- */
$("#detectBtn").addEventListener("click", async () => {
  const box = $("#detectResult");
  box.classList.remove("hidden"); box.classList.add("show");
  box.innerHTML = '<span class="loading"></span> جاري التحليل…';
  try {
    const d = await api("/api/detect", { method: "POST" });
    const cls = d.is_attack ? "attack" : "benign";
    const label = d.is_attack ? d.prediction : "طبيعي (BENIGN)";
    box.innerHTML = `
      <div class="verdict-big">
        <span class="verdict-badge ${cls}">${label}</span>
        <div style="flex:1;min-width:0">
          <div style="font-size:.8rem;color:var(--ink-2);margin-bottom:3px">ثقة النموذج: ${(d.confidence*100).toFixed(1)}%</div>
          <div class="meter"><span style="width:${d.confidence*100}%;background:${d.is_attack?'var(--danger)':'var(--ok)'}"></span></div>
        </div>
      </div>
      <div style="font-size:.82rem;color:var(--ink-2);margin-bottom:10px">
        التصنيف الحقيقي بالداتاسيت: <b class="mono">${d.true_label}</b></div>
      <div style="font-weight:600;margin-bottom:6px">لماذا هذا القرار؟ أبرز الخصائص المؤثرة:</div>
      ${d.explanation.map(e => `
        <div class="expl-row">
          <span class="fname">${e.feature}</span>
          <span class="chip ${e.z>0?'up':'down'}">${e.direction}</span>
          <span class="mono" style="font-size:.78rem;color:var(--ink-2)">z=${e.z>0?'+':''}${e.z}</span>
        </div>`).join("")}`;
  } catch (e) {
    box.innerHTML = '<span style="color:var(--danger)">تعذّر الاتصال بالخادم. تأكد أنه يعمل على المنفذ 8000.</span>';
  }
});

/* ---------- إنذار مبكر ---------- */
async function runForecast(mode) {
  const box = $("#fcResult");
  box.classList.remove("hidden"); box.classList.add("show");
  box.innerHTML = '<span class="loading"></span> جاري التنبؤ…';
  try {
    const d = await api("/api/forecast?mode=" + mode, { method: "POST" });
    if (d.error) { box.innerHTML = `<span style="color:var(--danger)">${d.error}</span>`; return; }
    const alertCls = d.alert ? "attack" : "benign";
    const trend = d.trend.total_flows || [];
    const mx = Math.max(...trend, 1);
    box.innerHTML = `
      <div class="verdict-big">
        <span class="verdict-badge ${alertCls}">${d.alert ? "إنذار" : "لا إنذار"}</span>
        <div style="flex:1;min-width:0">
          <div class="meter"><span style="width:${Math.min(d.probability*100,100)}%;background:${d.alert?'var(--danger)':'var(--accent)'}"></span></div>
        </div>
      </div>
      <div style="font-weight:600;margin-bottom:4px;font-size:.85rem">عدد التدفقات خلال آخر 10 دقائق:</div>
      <div class="mini-chart">${trend.map(v=>`<div class="b" style="height:${(v/mx*100)}%"></div>`).join("")}</div>`;
  } catch (e) {
    box.innerHTML = '<span style="color:var(--danger)">تعذّر الاتصال بالخادم.</span>';
  }
}
$("#fcRandom").addEventListener("click", () => runForecast("random"));

/* ---------- فحص الشبكة الحقيقية ---------- */
$("#scanBtn").addEventListener("click", async () => {
  const box = $("#scanResult"), btn = $("#scanBtn");
  box.classList.remove("hidden"); box.classList.add("show");
  btn.disabled = true;
  box.innerHTML = '<span class="loading"></span> جاري التقاط ترافيك شبكتك الحقيقي وتحليله… (قد يأخذ ~15 ثانية)';
  try {
    const d = await api("/api/livescan?count=1500&iface=any", { method: "POST" });
    btn.disabled = false;
    if (d.error) {
      box.innerHTML = `<div style="color:var(--danger)"><b>تعذّر الفحص:</b> ${d.error}</div>
        <div style="font-size:.82rem;color:var(--ink-2);margin-top:6px">${d.hint || ""}</div>`;
      return;
    }
    if (d.verdict === "no_traffic") {
      box.innerHTML = '<div style="color:var(--ink-2)">لم يُلتقط ترافيك كافٍ. حرّك بعض الاتصالات وأعد المحاولة.</div>';
      return;
    }
    const isAttack = d.verdict === "attack";
    const alertsHtml = d.alerts.length ? d.alerts.map(a => `
      <div class="expl-row">
        <span><b>${a.type}</b> — ${a.entity}</span>
        <span class="chip up">${a.evidence}</span>
        <span class="mono" style="font-size:.74rem;color:var(--ink-2)">${a.severity}</span>
      </div>`).join("") :
      '<div style="color:var(--ok);padding:8px 0">لا تنبيهات سلوكية — السلوك ضمن الطبيعي ✅</div>';
    box.innerHTML = `
      <div class="verdict-big">
        <span class="verdict-badge ${isAttack?'attack':'benign'}">
          ${isAttack ? "رُصد نشاط هجومي" : "الترافيك طبيعي"}</span>
      </div>
      <div style="display:grid;gap:14px;grid-template-columns:1fr 1fr">
        <div>
          <div style="font-weight:600;margin-bottom:6px;font-size:.9rem">🔍 الطبقة 1 — النموذج (لكل تدفق)</div>
          ${Object.entries(d.model).map(([k,v])=>`
            <div class="metric-row"><span class="lbl">${k}</span>
            <div class="bar"><span style="width:${Math.min(v/d.flows*100,100)}%;background:var(--accent)"></span></div>
            <span class="val">${v}</span></div>`).join("")}
        </div>
        <div>
          ${alertsHtml}
        </div>
      </div>
      ${isAttack ? `<div style="margin-top:14px;padding:12px 14px;background:var(--danger-soft);border-radius:10px;font-size:.86rem">
        <b>الحكم المدمج:</b> الكاشف السلوكي التقط ما فات النموذج اللحظي — وهذا يوضّح «فجوة المجال» بين الترافيك الحقيقي وبيئة التدريب، وكيف تعالجها الطبقة السلوكية.</div>` : ""}`;
    if (isAttack) {
      const holder = document.createElement("div");
      holder.innerHTML = adviceCard("", true);
      box.appendChild(holder);
      const ctx = "رُصد على الشبكة الحقيقية نشاط هجومي: " +
        d.alerts.map(a => `${a.type} (${a.evidence})`).join("، ") + ".";
      getAdviceText(ctx).then(t => holder.innerHTML = adviceCard(t, false));
    }
  } catch (e) {
    btn.disabled = false;
    box.innerHTML = '<span style="color:var(--danger)">تعذّر الاتصال بالخادم.</span>';
  }
});

/* ---------- المراقبة الاستباقية الحية ---------- */
let monPoll = null;
async function startMonitor() {
  const box = $("#monResult"), btn = $("#monBtn");
  box.classList.remove("hidden"); box.classList.add("show");
  btn.disabled = true;
  box.innerHTML = '<span class="loading"></span> جاري بدء المراقبة وبناء أول نافذة زمنية…';
  try {
    const r = await api("/api/monitor/start?window=8&cycles=20", { method: "POST" });
    if (r.error) {
      btn.disabled = false;
      box.innerHTML = `<span style="color:var(--danger)">تعذّر البدء: ${r.error}</span>`;
      return;
    }
    if (monPoll) clearInterval(monPoll);
    monPoll = setInterval(pollMonitor, 3000);
    pollMonitor();
  } catch (e) {
    btn.disabled = false;
    box.innerHTML = '<span style="color:var(--danger)">تعذّر الاتصال بالخادم.</span>';
  }
}
$("#monBtn").addEventListener("click", () => startMonitor());

async function pollMonitor() {
  const box = $("#monResult"), btn = $("#monBtn");
  let d;
  try { d = await api("/api/monitor/status"); }
  catch (e) { return; }

  const need = d.need || 10, got = d.collected || 0;
  const pct = Math.min(got / need * 100, 100);
  const bars = (d.windows || []).slice(-need);
  const mx = Math.max(...bars.map(w => w.total_flows || 0), 1);

  let predHtml = "";
  if (d.prediction) {
    const p = d.prediction;
    const cls = p.alert ? "attack" : "benign";
    predHtml = `
      <div class="verdict-big" style="margin-top:16px">
        <span class="verdict-badge ${cls}">${p.alert ? "إنذار استباقي" : "لا خطر متوقع"}</span>
      </div>`;
    // عند توقّع هجوم: نعرض التوصية التي يولّدها الخادم (state.advice)
    if (p.alert) {
      predHtml += d.advice ? adviceCard(d.advice, false) : adviceCard("", true);
    }
  }

  const done = !d.running && got >= need;
  box.innerHTML = `
    <div style="font-size:.9rem;margin-bottom:8px">
      بناء التاريخ الزمني من شبكتك: <b class="mono">${got} / ${need}</b> نافذة
      ${d.running ? '<span class="loading" style="margin-inline-start:8px"></span>' : ''}</div>
    <div class="meter"><span class="sev-accent" style="width:${pct}%"></span></div>
    <div style="font-weight:600;margin:14px 0 4px;font-size:.85rem">نشاط النوافذ (عدد التدفقات):</div>
    <div class="mini-chart">${bars.map(w=>`<div class="b" style="height:${((w.total_flows||0)/mx*100)}%"></div>`).join("") || '<span style="color:var(--ink-3);font-size:.82rem">بانتظار أول نافذة…</span>'}</div>
    ${predHtml}
    ${got < need && d.running ? `<div style="font-size:.8rem;color:var(--ink-2);margin-top:12px">يحتاج ${need} نوافذ قبل أول تنبؤ. كل نافذة ~20 ثانية.</div>` : ''}`;

  if (!d.running && (d.prediction || done)) {
    clearInterval(monPoll); monPoll = null;
    btn.disabled = false;
    btn.textContent = "أعد التنبؤ";
  }
}
