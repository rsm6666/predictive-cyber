/*
 * ===================================================================
 * تصوير مشاهد فيديو العرض — متصفح آلي بمؤشر ظاهر ولقطات حادة
 * ===================================================================
 * كل مشهد يُصوَّر بـ CDP screencast (JPEG جودة 92 بدقة 1920×1080) مع وقت كل
 * لقطة، فيُبنى منه فيديو بإيقاع حقيقي (build.py). مدة كل مشهد ثابتة لتطابق
 * السكربت الصوتي (voice_script.md). يتطلب بيانات seed_demo.py والخادم على 8001.
 *
 *   node demo_video/record.mjs            # كل المشاهد
 *   node demo_video/record.mjs 07 08      # مشاهد محددة
 * ===================================================================
 */
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { createRequire } from "node:module";
import { fileURLToPath } from "node:url";

const require = createRequire(import.meta.url);
const PW = process.env.PLAYWRIGHT || path.join(os.homedir(), ".npm/_npx/e41f203b7505f1fb/node_modules/playwright");
const { chromium } = require(PW);

const HERE = path.dirname(fileURLToPath(import.meta.url));
const OUT = path.join(HERE, "out", "frames");
const BASE = process.env.BASE || "http://localhost:8001";
const KEYS = JSON.parse(fs.readFileSync(path.join(HERE, "out", "demo_keys.json"), "utf8"));
const CARDS = "file://" + path.join(HERE, "cards.html");

/* ---------- مؤشر، نقرة، شريط عنوان المشهد، وتمييز عنصر (يُحقن في كل صفحة) ---------- */
const ZOOM = 1.25;      // واجهة أكبر للفيديو مع رسم أصلي بدقة 1920×1080
const OVERLAY = `(() => {
  const Z = ${ZOOM};
  if (document.documentElement) document.documentElement.style.zoom = Z;    // قد لا يوجد بعد عند بدء المستند
  const css = \`#__cursor{position:fixed;left:0;top:0;z-index:2147483647;pointer-events:none;
      transition:transform .9s cubic-bezier(.45,0,.2,1);filter:drop-shadow(0 3px 6px #000a)}
    .__ripple{position:fixed;z-index:2147483646;pointer-events:none;width:16px;height:16px;margin:-8px 0 0 -8px;
      border-radius:50%;border:3px solid #38bdf8;animation:__rip .6s ease-out forwards}
    @keyframes __rip{to{transform:scale(4);opacity:0}}
    #__cap{position:fixed;bottom:28px;left:28px;z-index:2147483645;display:flex;align-items:center;gap:12px;
      padding:12px 22px;border-radius:14px;background:#05070dd9;border:1px solid #38bdf866;color:#eaf0fb;
      font:600 22px "IBM Plex Sans Arabic",system-ui;box-shadow:0 10px 30px #0008;backdrop-filter:blur(6px);
      transform:translateY(120px);opacity:0;transition:all .6s cubic-bezier(.2,.7,.2,1)}
    #__cap.on{transform:none;opacity:1}
    #__cap b{font-family:"IBM Plex Mono",monospace;color:#38bdf8}
    #campaignBox,#agentTimeline,#agentReport *,#incidentsBox,#sourcesBox,#sitesBox *,#kpis,h2{scroll-margin-top:100px}
    .__hl{outline:3px solid #38bdf8 !important;outline-offset:6px;border-radius:14px;
      box-shadow:0 0 0 9999px #05070d55, 0 0 40px #38bdf866 !important;transition:outline-color .3s}\`;
  const boot = () => {
    if (location.protocol === "file:" || document.getElementById("__cursor")) return;   // البطاقات بلا مؤشر
    document.documentElement.style.zoom = Z;
    const st = document.createElement("style"); st.textContent = css; document.head.appendChild(st);
    const c = document.createElement("div"); c.id = "__cursor";
    c.innerHTML = '<svg width="30" height="30" viewBox="0 0 24 24"><path d="M5 3l14 8-6.2 1.6L10 19z" fill="#fff" stroke="#05070d" stroke-width="1.4" stroke-linejoin="round"/></svg>';
    c.style.transform = "translate(" + (innerWidth * .5 / Z) + "px," + (innerHeight * .8 / Z) + "px)";
    document.body.appendChild(c);
  };
  window.__move = (x, y) => { boot(); document.getElementById("__cursor").style.transform =
    "translate(" + (x / Z - 5) + "px," + (y / Z - 3) + "px)"; };
  window.__ripple = (x, y) => { const r = document.createElement("div"); r.className = "__ripple";
    r.style.left = x / Z + "px"; r.style.top = y / Z + "px"; document.body.appendChild(r); setTimeout(() => r.remove(), 700); };
  window.__caption = (n, text) => { boot(); let el = document.getElementById("__cap");
    if (!el) { el = document.createElement("div"); el.id = "__cap"; document.body.appendChild(el); }
    el.innerHTML = "<b>" + n + "</b><span>" + text + "</span>"; requestAnimationFrame(() => el.classList.add("on")); };
  window.__hl = (sel, on) => document.querySelectorAll(sel).forEach((e) => e.classList.toggle("__hl", on));
  if (document.readyState === "loading") addEventListener("DOMContentLoaded", boot); else boot();
})();`;

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function moveTo(page, loc) {
  await loc.scrollIntoViewIfNeeded();
  const b = await loc.boundingBox();
  await page.evaluate(([x, y]) => window.__move(x, y), [b.x + b.width / 2, b.y + b.height / 2]);
  await sleep(1000);
  return b;
}

async function click(page, loc) {
  const b = await moveTo(page, loc);
  await page.evaluate(([x, y]) => window.__ripple(x, y), [b.x + b.width / 2, b.y + b.height / 2]);
  await loc.click();
  await sleep(400);
}

async function scrollTo(page, loc, block = "center", ms = 1400) {
  await loc.evaluate((e, block) => e.scrollIntoView({ behavior: "smooth", block }), block);
  await sleep(ms);
}

async function scrollBy(page, dy, ms = 1400) {
  await page.evaluate((dy) => window.scrollBy({ top: dy, behavior: "smooth" }), dy);
  await sleep(ms);
}

const caption = (page, n, text) => page.evaluate(([n, t]) => window.__caption(n, t), [n, text]);
const nav = (page, p) => click(page, page.locator(`aside .nav button[data-page="${p}"]`));
const api = (page, p, method = "GET") => page.evaluate(async ([p, m, k]) =>
  (await fetch(p, { method: m, headers: { Authorization: "Bearer " + k } })).json(), [p, method, KEYS.dashboard_key]);

/* ---------- المشاهد: المدة بالثواني تطابق voice_script.md ---------- */
const SCENES = [
  { id: "01_title", dur: 8, card: "title" },
  { id: "02_problem", dur: 16, card: "problem" },
  { id: "03_sources", dur: 18, async run(page) {
    await nav(page, "tenant");
    await caption(page, "01", "منشأة واحدة، ثلاثة مصادر");
    await sleep(1500);
    await scrollTo(page, page.locator("#sourcesBox"), "start");
    await page.evaluate(() => window.__hl("#sourcesBox", true));
    await moveTo(page, page.locator("#sourcesBox .source").nth(2));
    await sleep(3500);
    await page.evaluate(() => window.__hl("#sourcesBox", false));
    await moveTo(page, page.locator("#anomalyBox"));
    await sleep(1800);
    await moveTo(page, page.locator("#forecastBox"));
  } },
  { id: "04_models", dur: 18, async run(page) {
    await nav(page, "overview");
    await caption(page, "02", "نماذج الكشف والتنبؤ");
    await sleep(1200);
    const metrics = page.getByText("أداء النماذج").first();
    await scrollTo(page, metrics, "start");
    const kpis = page.locator("#kpis .kpi:not(.skeleton)");
    await kpis.first().waitFor();
    await page.evaluate(() => window.__hl("#kpis", true));
    for (const [i, ms] of [[0, 3200], [1, 3200], [2, 3500]]) { await moveTo(page, kpis.nth(i)); await sleep(ms); }
    await page.evaluate(() => window.__hl("#kpis", false));
  } },
  { id: "05_monitor", dur: 18, async run(page) {
    await nav(page, "monitor");
    await caption(page, "03", "المراقبة الخارجية للموقع");
    await page.locator("#sitesBox .site .grade").waitFor();
    await sleep(800);
    await scrollTo(page, page.locator("#sitesBox .site"), "start");
    await moveTo(page, page.locator("#sitesBox .grade"));
    await sleep(2200);
    const env = page.locator('#sitesBox details.finding:has-text("/.env") summary');
    await click(page, env);
    await sleep(800);
    await scrollTo(page, page.locator('#sitesBox details.finding[open] .fix').first(), "center");
    await moveTo(page, page.locator('#sitesBox details.finding[open] .fix button').first());
  } },
  { id: "06_campaign", dur: 44, async run(page) {
    await nav(page, "tenant");
    await caption(page, "04", "ثلاث حوادث… حملة واحدة");
    await scrollTo(page, page.locator("#incidentsBox"), "center");
    await page.evaluate(() => window.__hl("#incidentsBox .camp", true));
    await moveTo(page, page.locator("#incidentsBox .camp-member").nth(0));
    await sleep(1300);
    await moveTo(page, page.locator("#incidentsBox .camp-member").nth(2));
    await sleep(1300);
    await page.evaluate(() => window.__hl("#incidentsBox .camp", false));
    const camp = await api(page, "/api/v1/incidents");
    const cid = camp.incidents.find((i) => i.kind === "campaign").id;
    await api(page, `/api/v1/incidents/${cid}/investigate`, "POST");      // المنسّق يعمل أمام الكاميرا
    await click(page, page.locator("#incidentsBox .camp-head"));
    await page.locator("#campaignBox .chain").waitFor();
    await sleep(600);
    await scrollTo(page, page.locator("#campaignBox"), "start");
    await moveTo(page, page.locator("#campaignBox .stage").nth(3));
    await sleep(2500);
    await moveTo(page, page.locator("#campaignBox .reasons"));
    await page.evaluate(() => window.__hl("#campaignBox .reasons", true));
    await sleep(3500);
    await page.evaluate(() => window.__hl("#campaignBox .reasons", false));
    // ---- المشهد 7 في السكربت: فريق الوكلاء (يبدأ عند الثانية 18 من هذا المقطع) ----
    await caption(page, "05", "المتخصصون ثم المنسّق");
    await scrollTo(page, page.locator("#agentTimeline"), "start", 1600);
    await moveTo(page, page.locator("#agentTimeline li").nth(1));
    await sleep(4000);
    await page.locator("#agentReport .report-summary").waitFor();
    await scrollTo(page, page.locator("#agentReport .report-summary"), "center", 1600);
    await page.evaluate(() => window.__hl("#agentReport .report-summary", true));
    await sleep(5000);
    await page.evaluate(() => window.__hl("#agentReport .report-summary", false));
    await scrollTo(page, page.locator("#agentReport .stages"), "center", 1600);
  } },
  { id: "08_decision", dur: 22, async run(page) {
    await caption(page, "06", "قرار واحد… بموافقتك");
    const prop = page.locator("#agentReport .proposal").last();
    await scrollTo(page, prop, "center");
    await page.evaluate(() => window.__hl("#agentReport .proposal:last-child", true));
    await sleep(1500);
    await click(page, prop.locator('button[data-decide="approve"]'));
    await page.evaluate(() => window.__hl("#agentReport .proposal:last-child", false));
    await page.locator("#agentReport .executor:not(:empty)").last().waitFor({ timeout: 15000 });
    await moveTo(page, page.locator("#agentReport .executor:not(:empty)").last());
    await page.evaluate(() => window.__hl("#agentReport .proposal:last-child", true));
    await sleep(4500);
    await page.evaluate(() => window.__hl("#agentReport .proposal:last-child", false));
    await nav(page, "tenant");
    await scrollTo(page, page.locator("#incidentsBox"), "center");
    await page.evaluate(() => window.__hl("#incidentsBox .camp", true));
  } },
  { id: "09_results", dur: 16, card: "results" },
  { id: "10_closing", dur: 10, card: "closing" },
];

/* ---------- التصوير ---------- */
async function capture(page, scene) {
  const dir = path.join(OUT, scene.id);
  fs.rmSync(dir, { recursive: true, force: true });
  fs.mkdirSync(dir, { recursive: true });
  const frames = [];
  const save = (buf, t) => {
    const f = path.join(dir, String(frames.length).padStart(5, "0") + ".jpg");
    fs.writeFileSync(f, buf);
    frames.push({ f, t });
  };
  const cdp = await page.context().newCDPSession(page);
  let live = false;
  cdp.on("Page.screencastFrame", ({ data, metadata, sessionId }) => {
    cdp.send("Page.screencastFrameAck", { sessionId }).catch(() => {});
    if (live) save(Buffer.from(data, "base64"), metadata.timestamp);
  });
  const start = Date.now() / 1000;
  save(await page.screenshot({ type: "jpeg", quality: 92 }), start);
  live = true;
  await cdp.send("Page.startScreencast", { format: "jpeg", quality: 92, maxWidth: 1920, maxHeight: 1080 });
  await scene.run(page);
  const left = start + scene.dur - Date.now() / 1000;
  if (left < 0) console.warn(`  ⚠ ${scene.id} تجاوز مدته بـ ${(-left).toFixed(1)} ث`);
  else await sleep(left * 1000);
  live = false;
  await cdp.send("Page.stopScreencast");
  await cdp.detach();
  save(await page.screenshot({ type: "jpeg", quality: 92 }), Date.now() / 1000);
  fs.writeFileSync(path.join(dir, "frames.json"), JSON.stringify({ start, dur: scene.dur, frames }));
  console.log(`  ✓ ${scene.id}: ${frames.length} لقطة`);
}

const only = process.argv.slice(2);
const browser = await chromium.launch();
const context = await browser.newContext({ viewport: { width: 1920, height: 1080 }, deviceScaleFactor: 1,
  colorScheme: "dark", locale: "ar" });
await context.addInitScript(OVERLAY);
await context.addInitScript((k) => sessionStorage.setItem("pc_dashboard_key", k), KEYS.dashboard_key);
const app = await context.newPage();
await app.goto(BASE + "/app/#overview");
await app.evaluate(async () => { await document.fonts.ready; return true; });
for (const scene of SCENES.filter((s) => !only.length || only.some((o) => s.id.startsWith(o)))) {
  if (scene.card) {
    const page = await context.newPage();
    await page.goto(CARDS + "?card=" + scene.card);
    await page.evaluate(async () => { await document.fonts.ready; return true; });
    await page.reload();          // الحركات تبدأ والخطوط محمّلة
    scene.run = async () => {};
    await capture(page, scene);
    await page.close();
  } else {
    await app.bringToFront();
    await capture(app, scene);
  }
}
await browser.close();
