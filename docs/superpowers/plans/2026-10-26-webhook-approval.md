# خطة تنفيذ: التنبيهات ومسار الموافقة والتنفيذ (الجزء 3)

> طلب صاحب المشروع التنفيذ مباشرة بعد الخطة، فهي تحدد لكل مهمة الملفات والواجهات والسلوك وحالات الاختبار، والكود يُكتب في المستودع بالاختبار أولًا مع commit لكل مهمة.

- **مستند التصميم:** [2026-10-26-webhook-approval-design.md](../specs/2026-10-26-webhook-approval-design.md)
- **الفرع:** `platform-core`

## قرارات تقنية

- **عدد المحاولات:** 5 محاولات إجمالًا، والانتظار بينها 5 ثوانٍ ثم 30 ثم دقيقتان ثم 10 دقائق. (المستند ذكر 5 فترات مع 5 محاولات، وهذا يناقض نفسه؛ 5 محاولات تعني 4 فترات. يُصحَّح المستند.)
- **النقل قابل للاستبدال:** `transport(url, headers, body, timeout) -> (status, text)`؛ الافتراضي `urllib`، والاختبارات تمرر نقلًا وهميًا، فلا اتصال حقيقي بـ Telegram في الاختبارات.
- **أزرار Telegram:** Telegram يرفض أزرار URL لعناوين `localhost`. إن كان `PUBLIC_BASE_URL` محليًا تُرسل الروابط نصًا داخل الرسالة بلا أزرار، مع تنبيه بأن الرابط يعمل من نفس الجهاز فقط.
- **مسار قرار واحد:** `_apply_decision(p, tenant, run, proposal_id, decision, approver)` تستدعيها اللوحة وصفحة الرابط.
- **ملاحظة المنفّذ:** تُحفظ في `Proposal.rationale` (حقل قائم غير مستخدم) وتُعرض في `proposal_public` كـ `executor`.
- **المنفّذ المرجعي مستقل:** لا يستورد شيئًا من المشروع (يُنسخ إلى خادم العميل)، فيكرر دالة التحقق من التوقيع عمدًا.

## خريطة الملفات

| الملف | المسؤولية |
|---|---|
| `notify/signing.py` | `sign(secret, ts, body)` و`verify(...)` |
| `notify/outbox.py` | `Outbox(tenant_db)`: جدول `deliveries`، `enqueue`، `due`، `delivered`، `attempt_failed`، `recent`، `pending_count` |
| `notify/channels.py` | بناء طلب Webhook وطلب Telegram ونصوصه |
| `notify/service.py` | `Notifier`: `emit` (لكل قناة مفعّلة)، `dispatch_once`، خيط المرسِل، رد المنفّذ |
| `tenancy/approvals.py` | `ApprovalTokens(registry.db)`: `issue`، `peek`، `consume` |
| `tenancy/pages.py` | `GET/POST /approve/{token}` صفحات HTML |
| `tenancy/api.py` | إعدادات Telegram والسرّ، `_apply_decision`، أحداث التقرير، `POST /notify/test`، `GET /deliveries`، فحص SSRF |
| `agent/tools.py` و`agent/analyst.py` | `decide(..., approver)`؛ `executor` في `proposal_public` |
| `enforcer/receiver.py` | المنفّذ المرجعي (HTTP + `Enforcer.handle`) |
| `api_server.py` | تركيب صفحات الموافقة، `PUBLIC_BASE_URL` و`ALLOW_PRIVATE_WEBHOOKS`، تشغيل المرسِل |
| `web/*` | الإعدادات: Telegram، السرّ، سجل التسليمات، أزرار التجربة؛ ملاحظة المنفّذ في المقترح |

## المهام

1. **التوقيع والصندوق الصادر والقنوات** (`tests/test_notify.py`): التوقيع يتحقق وتعديل بايت يفشله؛ قديم أو مستقبلي يُرفض؛ `enqueue` ثم `due`؛ فشلان ثم نجاح بالتوقيتات (5 ثم 30)؛ 5 فشلات ← `failed`؛ طلب Webhook بترويساته وتوقيعه؛ رسالة Telegram عربية بأزرار URL لعنوان عام وبلا أزرار لعنوان محلي.
2. **رموز الموافقة والخدمة** (`tests/test_approvals.py`): الرمز يُخزَّن بصمةً؛ `peek` لا يستهلك؛ `consume` مرة واحدة؛ منتهٍ ← None. `Notifier.emit` بلا قناة ← لا شيء؛ بقناتين ← تسليمان؛ `dispatch_once` بنقل وهمي يسلّم؛ رد المنفّذ `dry_run` يحدّث ملاحظة المقترح.
3. **الـ API والصفحات** (`tests/test_approval_flow.py`): إعدادات Telegram مُقنّعة في `/me` والسرّ يُولَّد عند حفظ الرابط ويُدوَّر؛ رابط خاص مرفوض عند `allow_private_webhooks=False`؛ تحقيق سجلات ← `incident.report` في الصندوق برابط موافقة؛ `GET /approve` لا يغيّر شيئًا؛ `POST` يطبّق ويُدرج `action.execute` و`action.result`؛ الرابط لمرة واحدة؛ الرفض بلا `action.execute`؛ رمز منشأة A لا يمس B؛ `POST /notify/test` و`GET /deliveries`.
4. **المنفّذ المرجعي** (`tests/test_enforcer.py`): الوضع التجريبي يرجع `dry_run` بالأمر؛ قائمة السماح المحلية والعناوين الخاصة ← `refused`؛ توقيع خاطئ وقديم ← 401؛ تسليم مكرر يُتجاهل؛ `rate_limit_target` ← `refused`؛ `--apply` يستدعي `ufw` بقائمة وسائط ويجدول الإزالة (بمشغّل وهمي).
5. **الواجهة والتوثيق والتحقق الكامل:** الإعدادات (Telegram، السرّ مع نسخ وتدوير، سجل التسليمات، أزرار التجربة)، ملاحظة المنفّذ تحت المقترح، README. تحقق: منفّذ مرجعي على المنفذ 9000 بوضع تجريبي ← Webhook المنشأة إليه ← حادثة من المولّد ← الموافقة من صفحة الرابط ← المنفّذ يطبع `ufw insert 1 deny from …` ← سجل التسليمات والملاحظة «تجربة».
