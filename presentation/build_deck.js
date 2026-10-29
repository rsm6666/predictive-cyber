/*
 * عرض المشروع للجنة — يبني presentation/slides.pptx (13 شريحة، عربي من اليمين لليسار)
 *
 *   NODE_PATH=<مجلد فيه pptxgenjs وreact-icons وreact وreact-dom وsharp> node presentation/build_deck.js
 *
 * الألوان والخطوط من THEME، وكل شريحة على تخطيط (layout) بعنوان في مكان ثابت.
 * ملاحظات المتحدث في كل شريحة = نص الشرح الشفهي.
 */
const path = require("path");
const pptxgen = require("pptxgenjs");
const React = require("react");
const { renderToStaticMarkup } = require("react-dom/server");
const sharp = require("sharp");
const fa = require("react-icons/fa6");

const OUT = path.join(__dirname, "slides.pptx");
const APPLY_THEME = process.env.APPLY_THEME;   // مسار scripts/apply_theme.js من مهارة pptx (اختياري)

const THEME = {
  name: "Predictive Cyber",
  headFontFace: "Arial",
  bodyFontFace: "Arial",
  colors: {
    dk1: "0A0E18", lt1: "FFFFFF", dk2: "121A2C", lt2: "9AA7C4",
    accent1: "38BDF8", accent2: "2FE38A", accent3: "FF4D62", accent4: "FFB020",
    accent5: "1E2A44", accent6: "64718E", hlink: "38BDF8", folHlink: "9AA7C4",
  },
};
const HEX = { bg: THEME.colors.dk1, panel: THEME.colors.dk2, line: THEME.colors.accent5, cyan: THEME.colors.accent1,
  ok: THEME.colors.accent2, danger: THEME.colors.accent3, warn: THEME.colors.accent4, muted: THEME.colors.lt2,
  white: THEME.colors.lt1, dim: THEME.colors.accent6 };

const pres = new pptxgen();
pres.layout = "LAYOUT_WIDE";          // 13.333 × 7.5 بوصة
pres.rtlMode = true;
pres.title = "التنبؤ بالهجمات السيبرانية";
pres.author = "فريق المشروع";
pres.theme = { headFontFace: THEME.headFontFace, bodyFontFace: THEME.bodyFontFace };
const C = pres.SchemeColor;
const W = 13.333, M = 0.6;

/* ---------- التخطيطات ---------- */
pres.defineSlideMaster({
  title: "TITLE",
  background: { color: HEX.bg },
  objects: [
    { placeholder: { options: { name: "title", type: "title", x: 1, y: 3.05, w: W - 2, h: 1.0, fontSize: 44, bold: true,
      color: C.background1, align: "center", valign: "middle" }, text: "" } },
    { placeholder: { options: { name: "body", type: "body", x: 1, y: 4.1, w: W - 2, h: 0.6, fontSize: 22,
      color: C.background2, align: "center", valign: "top" }, text: "" } },
  ],
});
pres.defineSlideMaster({
  title: "CONTENT",
  background: { color: HEX.bg },
  slideNumber: { x: M, y: 6.95, w: 0.6, h: 0.3, fontSize: 10, color: C.accent6, fontFace: "Arial" },
  objects: [
    { text: { text: "التنبؤ بالهجمات السيبرانية", options: { x: W - M - 4, y: 6.95, w: 4, h: 0.3, fontSize: 10,
      color: C.accent6, align: "right", rtlMode: true } } },
    { placeholder: { options: { name: "title", type: "title", x: M, y: 0.4, w: W - 2 * M, h: 0.8, fontSize: 34, bold: true,
      color: C.background1, align: "right", valign: "middle" }, text: "" } },
  ],
});

/* ---------- أدوات ---------- */
async function icon(name, hex, px = 256) {
  const svg = renderToStaticMarkup(React.createElement(fa[name], { color: "#" + hex, size: px }));
  const buf = await sharp(Buffer.from(svg)).resize(px, px).png().toBuffer();
  return "image/png;base64," + buf.toString("base64");
}

function text(slide, t, o) {
  const rtl = o.rtlMode !== false;
  if (Array.isArray(t))           // pptxgenjs يأخذ اتجاه الفقرة من خيارات كل جزء، لا من الصندوق
    t = t.map((r) => ({ ...r, options: { rtlMode: rtl, align: o.align || "right", ...r.options } }));
  slide.addText(t, { isTextBox: true, rtlMode: true, lang: "ar-SA", align: "right", valign: "top", margin: 0,
    fontSize: 16, color: C.background1, ...o });
}

function card(slide, x, y, w, h, o = {}) {
  slide.addShape(pres.shapes.ROUNDED_RECTANGLE, { x, y, w, h, rectRadius: 0.12, fill: { color: C.text2 },
    line: { color: C.accent5, width: 1 }, objectName: o.name || "card", ...o.shape });
}

async function badge(slide, name, color, x, y, d = 0.75) {
  slide.addShape(pres.shapes.OVAL, { x, y, w: d, h: d, fill: { color: C.text1 }, line: { color, width: 1.5 },
    objectName: "icon-circle" });
  const hex = { [C.accent1]: HEX.cyan, [C.accent2]: HEX.ok, [C.accent3]: HEX.danger, [C.accent4]: HEX.warn }[color] || HEX.white;
  slide.addImage({ data: await icon(name, hex), x: x + d * 0.25, y: y + d * 0.25, w: d * 0.5, h: d * 0.5,
    altText: name, objectName: "icon" });
}

function content(title, section) {
  const s = pres.addSlide({ masterName: "CONTENT", sectionTitle: section });
  s.addText(title, { placeholder: "title", rtlMode: true });
  return s;
}

/* ---------- الشرائح ---------- */
async function build() {
  // 1 — العنوان
  pres.addSection({ title: "البداية" });
  let s = pres.addSlide({ masterName: "TITLE", sectionTitle: "البداية" });
  s.addImage({ data: await icon("FaShieldHalved", HEX.cyan, 512), x: W / 2 - 0.75, y: 1.35, w: 1.5, h: 1.5,
    altText: "درع", objectName: "logo" });
  s.addText("التنبؤ بالهجمات السيبرانية", { placeholder: "title", rtlMode: true });
  s.addText("فريق أمني ذكي لكل منشأة صغيرة", { placeholder: "body", rtlMode: true });
  text(s, "تكشف · تتنبأ · تحقق · تقترح … والقرار لك", { x: 1, y: 5.3, w: W - 2, h: 0.5, fontSize: 18, bold: true,
    color: C.accent2, align: "center" });
  s.addNotes("هذه منصة التنبؤ بالهجمات السيبرانية: فريق أمني ذكي لكل منشأة صغيرة. تكشف الهجوم، وتتنبأ به، وتحقق فيه، وتقترح الإجراء، والقرار يبقى لصاحب المنشأة.");

  // 2 — المشكلة
  pres.addSection({ title: "المشكلة والحل" });
  s = content("مهاجم واحد… وأبواب كثيرة", "المشكلة والحل");
  const problems = [
    ["FaUserSecret", "لا فريق أمني", "المنشأة الصغيرة لا تملك محللًا يراقب على مدار الساعة، ولا ميزانية لمركز عمليات أمنية."],
    ["FaDoorOpen", "هجوم متعدد المراحل", "يفحص المهاجم الخادم، ثم يبحث في الموقع عن ملف مكشوف، ثم يحاول الدخول."],
    ["FaPuzzlePiece", "أدوات متفرقة", "كل أداة ترى جزءًا من الصورة وتطلق تنبيهاتها وحدها، فيضيع الربط ويتأخر القرار."],
  ];
  for (const [i, [ic, h, b]] of problems.entries()) {
    const x = W - M - (i + 1) * 3.9 - i * 0.215;
    card(s, x, 1.75, 3.9, 4.1);
    await badge(s, ic, C.accent3, x + 3.9 - 1.2, 2.1, 0.85);
    text(s, h, { x: x + 0.35, y: 3.2, w: 3.2, h: 0.5, fontSize: 22, bold: true });
    text(s, b, { x: x + 0.35, y: 3.85, w: 3.2, h: 1.8, fontSize: 16, color: C.background2 });
  }
  s.addNotes("المنشآت الصغيرة لا تملك فريقًا أمنيًا. والمهاجم لا يطرق بابًا واحدًا: يفحص الخادم، ثم يبحث في الموقع عن ملف مكشوف، ثم يحاول الدخول. وكل أداة ترى جزءًا صغيرًا من الصورة.");

  // 3 — الحل: المسار
  s = content("الحل: من الإشارة إلى القرار في مسار واحد", "المشكلة والحل");
  const flow = [
    ["FaNetworkWired", "مصادرك", "سجلات، وكيل خادم، مراقبة خارجية", C.accent1],
    ["FaMagnifyingGlass", "الكشف", "نماذج تعلّم آلي + قواعد سلوكية", C.accent1],
    ["FaRobot", "فريق الوكلاء", "متخصصون ومنسّق يربط الحوادث", C.accent1],
    ["FaUserShield", "قرارك", "موافقة واحدة لكل مهاجم", C.accent2],
    ["FaBolt", "التنفيذ", "أمر موقّع إلى خادمك", C.accent2],
  ];
  const fw = 2.05, gap = 0.47;
  for (const [i, [ic, h, b, col]] of flow.entries()) {
    const x = W - M - (i + 1) * fw - i * gap;
    card(s, x, 2.3, fw, 2.9);
    await badge(s, ic, col, x + fw / 2 - 0.42, 2.6, 0.84);
    text(s, h, { x: x + 0.15, y: 3.65, w: fw - 0.3, h: 0.45, fontSize: 19, bold: true, align: "center" });
    text(s, b, { x: x + 0.15, y: 4.15, w: fw - 0.3, h: 0.9, fontSize: 14, color: C.background2, align: "center" });
    if (i < flow.length - 1)
      s.addImage({ data: await icon("FaArrowLeftLong", HEX.dim), x: x - gap + 0.06, y: 3.6, w: 0.35, h: 0.35,
        altText: "سهم", objectName: "arrow" });
  }
  text(s, "لا شيء يُنفَّذ على أنظمة المنشأة دون موافقة صاحبها، وكل منشأة معزولة تمامًا عن غيرها.",
    { x: M, y: 5.7, w: W - 2 * M, h: 0.5, fontSize: 18, color: C.accent2, align: "center" });
  s.addNotes("المنصة مسار واحد: تجمع الإشارات من مصادر المنشأة، تكشف الهجوم بالنماذج والقواعد، يحقق فيه فريق وكلاء أذكياء، ثم يقرر صاحب المنشأة بموافقة واحدة، ويصل الأمر موقّعًا إلى خادمه.");

  // 4 — المصادر
  pres.addSection({ title: "كيف تعمل" });
  s = content("ثلاثة مصادر تُربط في دقائق", "كيف تعمل");
  const sources = [
    ["FaFileLines", "سجلات الموقع والجدار", ["سجلات Nginx وApache والجدار الناري", "قواعد: تخمين، فحص مسارات، حقن، إغراق", "نموذج شذوذ يتعلّم سلوك زوّار المنشأة"]],
    ["FaServer", "وكيل الخادم", ["يلخّص كل اتصال إلى 77 خاصية", "لا يُرسل محتوى الحزم أبدًا", "صلاحية التقاط فقط، ومخزن 24 ساعة"]],
    ["FaGlobe", "المراقبة الخارجية", ["التوفر والشهادة وترويسات الأمان", "يكتشف الملفات الحساسة المكشوفة", "درجة من A إلى F وإصلاح جاهز للنسخ"]],
  ];
  for (const [i, [ic, h, items]] of sources.entries()) {
    const x = W - M - (i + 1) * 3.9 - i * 0.215;
    card(s, x, 1.55, 3.9, 4.2);
    await badge(s, ic, C.accent1, x + 3.9 - 1.15, 1.85, 0.8);
    text(s, h, { x: x + 0.3, y: 2.85, w: 3.3, h: 0.5, fontSize: 21, bold: true });
    text(s, items.map((t, j) => ({ text: t, options: { bullet: true, breakLine: j < items.length - 1 } })),
      { x: x + 0.3, y: 3.5, w: 3.3, h: 2.1, fontSize: 15, color: C.background2, paraSpaceAfter: 8 });
  }
  card(s, M, 6.0, W - 2 * M, 0.7, { shape: { fill: { color: C.text1 } } });
  text(s, "مفتاح استقبال للإرسال فقط، ومفتاح لوحة للقرار · قاعدة بيانات مستقلة لكل منشأة · لا يُخزَّن مفتاح خام",
    { x: M + 0.3, y: 6.13, w: W - 2 * M - 0.6, h: 0.45, fontSize: 15, color: C.accent1, align: "center" });
  s.addNotes("تسجّل المنشأة في دقيقة وتربط مصادرها: سجلات موقعها وجدارها الناري، ووكيلًا خفيفًا على خادمها يلخّص الترافيك دون أن يرسل محتواه، ومراقبة خارجية للموقع تفحصه كما يراه المهاجم.");

  // 5 — النماذج
  s = content("نماذج الكشف والتنبؤ", "كيف تعمل");
  const stats = [
    ["94.8%", "رصد الهجمات", "Random Forest: هجوم أم طبيعي", C.accent2],
    ["95.2%", "تحديد نوع الهجوم", "Macro-F1 على 7 فئات", C.accent2],
    ["41%", "إنذار قبل بدء الهجوم", "5 نماذج LSTM · الصدفة تقارب 18%", C.accent1],
  ];
  for (const [i, [n, h, b, col]] of stats.entries()) {
    const x = W - M - (i + 1) * 3.9 - i * 0.215;
    card(s, x, 1.6, 3.9, 3.4);
    text(s, n, { x: x + 0.2, y: 1.95, w: 3.5, h: 1.2, fontSize: 60, bold: true, color: col, align: "center", rtlMode: false });
    text(s, h, { x: x + 0.2, y: 3.25, w: 3.5, h: 0.5, fontSize: 21, bold: true, align: "center" });
    text(s, b, { x: x + 0.2, y: 3.85, w: 3.5, h: 0.8, fontSize: 15, color: C.background2, align: "center" });
  }
  text(s, [
    { text: "التدريب: ", options: { bold: true, color: C.background1 } },
    { text: "قرابة 2.83 مليون اتصال من CICIDS2017، بتقسيم زمني صارم: النموذج لم يرَ بيانات الاختبار. ", options: {} },
    { text: "حاجز أدلة: ", options: { bold: true, color: C.background1 } },
    { text: "لا يُفتح بلاغ من النموذج إلا بـ 20 اتصالًا على الأقل، وثقة 80%، ونسبة هجوم 50%.", options: {} },
  ], { x: M, y: 5.35, w: W - 2 * M, h: 1.2, fontSize: 16, color: C.background2 });
  s.addNotes("في القلب نماذج تعلّم آلي مدرّبة على ملايين الاتصالات: تكشف 94.8% من الهجمات، وتحدد نوعها بـ Macro-F1 يبلغ 95.2%، ونموذج ثالث يرصد مبكرًا 41% من الهجمات قبل أن تبدأ. ولتفادي الإنذار الكاذب، لا يفتح النموذج حادثة إلا بعد حاجز أدلة.");

  // 6 — فريق الوكلاء
  pres.addSection({ title: "الوكلاء والقرار" });
  s = content("فريق وكلاء: متخصصون ثم منسّق", "الوكلاء والقرار");
  const agents = [["FaFileLines", "محلل السجلات"], ["FaNetworkWired", "محلل الشبكة"], ["FaGlobe", "المراقبة"]];
  for (const [i, [ic, h]] of agents.entries()) {
    const y = 1.6 + i * 1.5;
    card(s, W - M - 3.6, y, 3.6, 1.2);
    await badge(s, ic, C.accent1, W - M - 1.0, y + 0.22, 0.76);
    text(s, h, { x: W - M - 3.35, y: y + 0.38, w: 2.2, h: 0.45, fontSize: 19, bold: true });
    s.addImage({ data: await icon("FaArrowLeftLong", HEX.dim), x: W - M - 4.25, y: y + 0.42, w: 0.4, h: 0.36,
      altText: "سهم", objectName: "arrow" });
  }
  card(s, 4.55, 1.6, 3.9, 4.2, { shape: { line: { color: C.accent1, width: 2 } } });
  await badge(s, "FaBrain", C.accent1, 6.06, 1.9, 0.9);
  text(s, "المنسّق", { x: 4.75, y: 2.95, w: 3.5, h: 0.5, fontSize: 24, bold: true, align: "center" });
  const tools = ["يقرأ تقارير المتخصصين", "يبني ملف كل مهاجم عبر المصادر", "يفحص السياسة والحد الأقصى", "يكتب تقريرًا واحدًا بمراحل"];
  text(s, tools.map((t, j) => ({ text: t, options: { bullet: true, breakLine: j < tools.length - 1 } })),
    { x: 4.85, y: 3.6, w: 3.3, h: 2.0, fontSize: 15, color: C.background2, paraSpaceAfter: 6 });
  s.addImage({ data: await icon("FaArrowLeftLong", HEX.dim), x: 4.0, y: 3.5, w: 0.4, h: 0.36, altText: "سهم", objectName: "arrow" });
  card(s, M, 1.6, 3.25, 4.2, { shape: { line: { color: C.accent2, width: 2 } } });
  await badge(s, "FaUserShield", C.accent2, M + 1.25, 1.9, 0.8);
  text(s, "لصاحب المنشأة", { x: M + 0.2, y: 2.9, w: 2.85, h: 0.5, fontSize: 21, bold: true, align: "center" });
  const outs = ["ماذا حدث، بلغة بسيطة", "ما الخطر الآن", "إجراء واحد لكل مهاجم", "ينتظر موافقته"];
  text(s, outs.map((t, j) => ({ text: t, options: { bullet: true, breakLine: j < outs.length - 1 } })),
    { x: M + 0.25, y: 3.55, w: 2.75, h: 2.0, fontSize: 15, color: C.background2, paraSpaceAfter: 6 });
  text(s, "وكلاء Claude بأدوات تستدعي طبقات النظام الحقيقية · بلا مفتاح يعمل وضع عرض بنفس الأدوات",
    { x: M, y: 6.15, w: W - 2 * M, h: 0.45, fontSize: 15, color: C.accent6, align: "center" });
  s.addNotes("هذا نظام متعدد الوكلاء: محلل السجلات ومحلل الشبكة يحقق كل منهما في حادثته بأدوات تستدعي النماذج والسجلات الحقيقية، ثم يقرأ المنسّق تقاريرهما ويبني ملف المهاجم ويفحص السياسة، ويكتب لصاحب المنشأة تقريرًا واحدًا: ماذا حدث، وما الخطر، وماذا يفعل الآن.");

  // 7 — الحملة
  s = content("ثلاث حوادث… حملة واحدة", "الوكلاء والقرار");
  const chain = [
    ["ثغرة مكشوفة", "المراقبة: ملف الإعدادات مكشوف", C.accent4],
    ["استطلاع", "الشبكة: فحص منافذ", C.accent1],
    ["استطلاع", "السجلات: فحص مسارات", C.accent1],
    ["تسريب", "حُمّل الملف المكشوف (200)", C.accent3],
    ["محاولة دخول", "السجلات: تخمين كلمات المرور", C.accent3],
  ];
  const cw = 2.15, cg = 0.33;
  for (const [i, [st, d, col]] of chain.entries()) {
    const x = W - M - (i + 1) * cw - i * cg;
    card(s, x, 1.65, cw, 1.9, { shape: { line: { color: col, width: 1.5 } } });
    text(s, st, { x: x + 0.15, y: 1.85, w: cw - 0.3, h: 0.45, fontSize: 18, bold: true, color: col, align: "center" });
    text(s, d, { x: x + 0.15, y: 2.45, w: cw - 0.3, h: 0.95, fontSize: 15, align: "center" });
    if (i < chain.length - 1)
      s.addImage({ data: await icon("FaArrowLeftLong", HEX.dim), x: x - cg + 0.02, y: 2.45, w: 0.29, h: 0.29,
        altText: "سهم", objectName: "arrow" });
  }
  const rules = [
    ["FaLink", "نفس المهاجم", "نفس العنوان في حادثتي سجلات أو شبكة خلال 24 ساعة. القائمة البيضاء لا تربط شيئًا."],
    ["FaFileShield", "الملف المكشوف", "مهاجم طلب مسارًا كشفته المراقبة؛ الرد 200 يعني تسريبًا فعليًا، فترتفع الحملة إلى حرجة."],
  ];
  for (const [i, [ic, h, b]] of rules.entries()) {
    const x = W - M - (i + 1) * 5.9 - i * 0.33;
    card(s, x, 4.0, 5.9, 2.05);
    await badge(s, ic, C.accent1, x + 5.9 - 1.05, 4.25, 0.75);
    text(s, h, { x: x + 0.3, y: 4.4, w: 4.4, h: 0.5, fontSize: 20, bold: true });
    text(s, b, { x: x + 0.3, y: 5.1, w: 5.3, h: 0.8, fontSize: 15, color: C.background2 });
  }
  s.addNotes("ثلاثة مصادر فتحت ثلاث حوادث منفصلة، لكن المنصة ربطتها في حملة واحدة بقاعدتين ثابتتين قابلتين للتفسير: نفس العنوان ظهر في الشبكة والسجلات، وطلب الملف الذي كشفته المراقبة وحمّله فعلًا. ولكل ربط سبب مكتوب يراه صاحب المنشأة.");

  // 8 — القرار والحواجز
  s = content("القرار يبقى للإنسان", "الوكلاء والقرار");
  card(s, M, 1.6, 4.3, 4.45);
  text(s, "3 ← 1", { x: M + 0.2, y: 2.45, w: 3.9, h: 1.3, fontSize: 66, bold: true, color: C.accent2, align: "center" });
  text(s, "موافقة واحدة لكل مهاجم", { x: M + 0.2, y: 3.9, w: 3.9, h: 0.5, fontSize: 21, bold: true, align: "center" });
  text(s, "بدل موافقة منفصلة لكل حادثة من كل مصدر", { x: M + 0.3, y: 4.5, w: 3.7, h: 0.9, fontSize: 15,
    color: C.background2, align: "center" });
  const guards = [
    ["FaHandPointer", "لا تنفيذ دون موافقة", "رابط موافقة لمرة واحدة، صالح ساعة، يفتح صفحة تأكيد"],
    ["FaKey", "أمر موقّع", "Webhook بتوقيع HMAC إلى منفّذ على خادم المنشأة يطبّق ufw"],
    ["FaLock", "حواجز ثابتة", "لا حظر لعنوان محمي، ولا إجراء أشد مما تسمح به السياسة"],
    ["FaClockRotateLeft", "سجل تدقيق كامل", "كل خطوة وقرار ونتيجة تنفيذ محفوظة لكل حادثة"],
  ];
  for (const [i, [ic, h, b]] of guards.entries()) {
    const y = 1.6 + i * 1.18;
    await badge(s, ic, C.accent1, W - M - 0.75, y + 0.08, 0.72);
    text(s, h, { x: 5.4, y: y + 0.02, w: W - M - 1.05 - 5.4, h: 0.45, fontSize: 19, bold: true });
    text(s, b, { x: 5.4, y: y + 0.5, w: W - M - 1.05 - 5.4, h: 0.5, fontSize: 15, color: C.background2 });
  }
  s.addNotes("والقرار يبقى للإنسان. بدل ثلاث موافقات، موافقة واحدة تحظر المهاجم. يصل الأمر موقّعًا إلى خادم المنشأة، ويمر بحواجز أمان: لا حظر لعنوان محمي، ولا إجراء أشد مما تسمح به السياسة. ثم تُغلق الحوادث تلقائيًا.");

  // 9 — النتائج
  pres.addSection({ title: "النتائج" });
  s = content("النتائج المقيسة", "النتائج");
  const results = [
    ["100%", "رصد هجمات الشبكة", "6 أنواع × حجمان × 5 بذور"],
    ["0", "تنبيه كاذب", "خلال 300 دقيقة ترافيك طبيعي"],
    ["100%", "كشف السجلات", "6 أنماط، ولا تنبيه كاذب"],
    ["100%", "دقة ربط الحملات", "10 سيناريوهات فيها طُعوم"],
  ];
  for (const [i, [n, h, b]] of results.entries()) {
    const col = i % 2, row = Math.floor(i / 2);
    const x = W - M - (col + 1) * 5.9 - col * 0.33, y = 1.55 + row * 2.45;
    card(s, x, y, 5.9, 2.15);
    text(s, n, { x: x + 0.25, y: y + 0.45, w: 2.3, h: 1.2, fontSize: 54, bold: true, color: C.accent2, align: "center",
      valign: "middle", rtlMode: false });
    text(s, h, { x: x + 2.7, y: y + 0.5, w: 2.95, h: 0.5, fontSize: 21, bold: true });
    text(s, b, { x: x + 2.7, y: y + 1.1, w: 2.95, h: 0.7, fontSize: 15, color: C.background2 });
  }
  text(s, "إعادة تشغيل تدفقات CICIDS2017 الحقيقية عبر مسار المنصة نفسه، بلا تكلفة API · 229 اختبارًا آليًا تنجح",
    { x: M, y: 6.45, w: W - 2 * M, h: 0.4, fontSize: 14, color: C.accent6, align: "center" });
  s.addNotes("قسنا ذلك: رُصد كل هجوم في اختبارات إعادة التشغيل بحجمين، دون تنبيه كاذب واحد خلال 300 دقيقة من الترافيك الطبيعي، وكشفت قواعد السجلات كل الأنماط، وربط الحملات صحيح في كل السيناريوهات المختبرة بما فيها الطُعوم.");

  // 10 — لماذا النموذج
  s = content("لماذا التعلّم الآلي؟ حين يكون الهجوم هادئًا", "النتائج");
  const attacks = ["PortScan", "DoS", "DDoS", "Brute Force", "Web Attack", "Botnet"];
  s.addChart(pres.charts.BAR, [
    { name: "القواعد السلوكية", labels: attacks, values: [100, 0, 0, 100, 0, 0] },
    { name: "نموذج التعلّم الآلي", labels: attacks, values: [100, 100, 100, 100, 100, 100] },
  ], {
    x: M, y: 1.45, w: 8.1, h: 5.1, barDir: "col", barGrouping: "clustered", barGapWidthPct: 60,
    chartColors: [HEX.dim, HEX.ok], showLegend: true, legendPos: "b", legendColor: HEX.muted, legendFontSize: 13,
    legendFontFace: "+mn-lt", showValue: true, dataLabelPosition: "outEnd", dataLabelColor: HEX.white,
    dataLabelFontSize: 12, dataLabelFontFace: "+mn-lt", dataLabelFormatCode: "0\"%\"",
    catAxisLabelColor: HEX.muted, catAxisLabelFontSize: 12, catAxisLabelFontFace: "+mn-lt",
    valAxisLabelColor: HEX.muted, valAxisLabelFontSize: 11, valAxisLabelFontFace: "+mn-lt", valAxisMaxVal: 100,
    valAxisLabelFormatCode: "0\"%\"", valGridLine: { color: HEX.line, size: 0.5 }, catGridLine: { style: "none" },
    showTitle: true, title: "نسبة رصد المهاجم عند 25 اتصالًا في الدقيقة", titleColor: HEX.white, titleFontSize: 15,
    titleFontFace: "+mn-lt", objectName: "chart-low-volume",
  });
  card(s, 9.05, 1.6, W - M - 9.05, 4.9);
  text(s, "4 من 6", { x: 9.25, y: 1.95, w: W - M - 9.45, h: 1.0, fontSize: 54, bold: true, color: C.accent2,
    align: "center" });
  text(s, "هجمات لم تلتقطها إلا النماذج حين قلّ حجم الهجوم", { x: 9.3, y: 3.05, w: W - M - 9.55, h: 0.9, fontSize: 18,
    bold: true, align: "center" });
  text(s, "بحجم كبير تكفي القواعد لأي هجوم بسبب حجمه، والنموذج هو من يحدد نوعه بدقة 100%. بحجم منخفض يبقى النموذج وحده.",
    { x: 9.3, y: 4.1, w: W - M - 9.55, h: 2.2, fontSize: 15, color: C.background2 });
  s.addNotes("عند هجوم هادئ بخمسة وعشرين اتصالًا في الدقيقة، لم تلتقط القواعد السلوكية هجمات حجب الخدمة والويب والبوتنت، بينما التقطها نموذج التعلّم الآلي كلها وحدد نوعها. هذا هو مكان الذكاء الاصطناعي في المنصة.");

  // 11 — البنية التقنية
  pres.addSection({ title: "التقنية والختام" });
  s = content("البنية التقنية", "التقنية والختام");
  const stack = [
    ["FaServer", "المنصة", "FastAPI، وقاعدة SQLite مستقلة لكل منشأة"],
    ["FaChartColumn", "النماذج", "scikit-learn (Random Forest) وTensorFlow (LSTM)"],
    ["FaRobot", "الوكلاء", "Claude بأدوات (Tool Use)، ووضع عرض بلا مفتاح"],
    ["FaNetworkWired", "وكيل الخادم", "Python وscapy وnumpy، التقاط حي أو ملف pcap"],
    ["FaCode", "الواجهة", "لوحة عربية من اليمين لليسار، بوضعين فاتح وغامق"],
    ["FaFlask", "الجودة", "229 اختبار pytest، وتقييمات قابلة للإعادة"],
  ];
  for (const [i, [ic, h, b]] of stack.entries()) {
    const col = i % 3, row = Math.floor(i / 3);
    const x = W - M - (col + 1) * 3.9 - col * 0.215, y = 1.6 + row * 2.45;
    card(s, x, y, 3.9, 2.15);
    await badge(s, ic, C.accent1, x + 3.9 - 1.0, y + 0.3, 0.7);
    text(s, h, { x: x + 0.3, y: y + 0.42, w: 2.5, h: 0.45, fontSize: 20, bold: true });
    text(s, b, { x: x + 0.3, y: y + 1.15, w: 3.3, h: 0.85, fontSize: 15, color: C.background2 });
  }
  s.addNotes("المنصة مبنية بـ FastAPI مع قاعدة مستقلة لكل منشأة، والنماذج بـ scikit-learn وTensorFlow، والوكلاء بـ Claude عبر استدعاء الأدوات، ووكيل الخادم بـ Python، والواجهة عربية بالكامل، ومعها 229 اختبارًا آليًا.");

  // 12 — الحدود والقادم
  s = content("بصراحة: الحدود والخطوة التالية", "التقنية والختام");
  const limits = ["التقييم على إعادة تشغيل CICIDS2017، لا على ترافيك منشأة حقيقية بعد",
    "خصائص Bulk وActive/Idle مصفّرة في وكيل الخادم", "مؤشر LSTM إنذار مبكر فقط ولا يفتح حادثة وحده",
    "السجلات لا تحدد الموقع المطلوب، فيُطابق المسار على مستوى المنشأة"];
  const nexts = ["تجربة ميدانية على منشأة صغيرة حقيقية", "تقرير أمني دوري لصاحب المنشأة",
    "ربط الحملات بالشبكة الفرعية وسلوك المهاجم", "نشر سحابي بقاعدة بيانات مُدارة"];
  for (const [i, [h, items, col, ic]] of [["حدود معلنة", limits, C.accent4, "FaTriangleExclamation"],
    ["الخطوة التالية", nexts, C.accent2, "FaRoute"]].entries()) {
    const x = W - M - (i + 1) * 5.9 - i * 0.33;
    card(s, x, 1.55, 5.9, 4.3);
    await badge(s, ic, col, x + 5.9 - 1.05, 1.85, 0.75);
    text(s, h, { x: x + 0.3, y: 1.98, w: 4.4, h: 0.5, fontSize: 22, bold: true });
    text(s, items.map((t, j) => ({ text: t, options: { bullet: true, breakLine: j < items.length - 1 } })),
      { x: x + 0.35, y: 2.85, w: 5.2, h: 3.4, fontSize: 16, color: C.background2, paraSpaceAfter: 12 });
  }
  s.addNotes("نعرض الحدود بصراحة: التقييم على بيانات مختبر معاد تشغيلها، وبعض الخصائص مصفّرة، ومؤشر التنبؤ إنذار فقط. والخطوة التالية تجربة ميدانية على منشأة حقيقية، وتقرير دوري، ونشر سحابي.");

  // 13 — الختام
  s = pres.addSlide({ masterName: "TITLE", sectionTitle: "التقنية والختام" });
  s.addImage({ data: await icon("FaShieldHalved", HEX.ok, 512), x: W / 2 - 0.75, y: 1.35, w: 1.5, h: 1.5,
    altText: "درع", objectName: "logo" });
  s.addText("تكشف · تتنبأ · تحقق · تقترح", { placeholder: "title", rtlMode: true });
  text(s, "… والقرار لك", { x: 1, y: 4.15, w: W - 2, h: 0.6, fontSize: 28, bold: true, color: C.accent2, align: "center" });
  text(s, "شكرًا لكم", { x: 1, y: 5.4, w: W - 2, h: 0.5, fontSize: 20, color: C.background2, align: "center" });
  s.addNotes("منصة التنبؤ بالهجمات السيبرانية: تكشف، وتتنبأ، وتحقق، وتقترح… والقرار لك. شكرًا لكم، ويسعدنا عرض المنصة مباشرة.");

  await pres.writeFile({ fileName: OUT });
  if (APPLY_THEME) await require(APPLY_THEME).applyTheme(OUT, THEME);
  console.log("written", OUT);
}

build().catch((e) => { console.error(e); process.exit(1); });
