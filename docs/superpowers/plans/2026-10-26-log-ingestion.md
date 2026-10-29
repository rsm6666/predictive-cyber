# خطة تنفيذ: استقبال السجلات وكواشف هجمات الويب (الجزء 2)

> **ملاحظة على الشكل:** طلب صاحب المشروع التنفيذ مباشرة بعد الخطة، فهذه الخطة تحدد لكل مهمة الملفات والواجهات والسلوك وحالات الاختبار وأوامر التحقق، دون تكرار الكود كاملًا. الكود يُكتب في المستودع بأسلوب الاختبار أولًا، وكل مهمة تنتهي بـ commit.

- **الهدف:** استقبال سجلات الويب والجدار الناري لكل منشأة، كشف الهجمات بقواعد ونموذج شذوذ لكل منشأة، فتح حوادث حقيقية يحقق فيها المحلل تلقائيًا، ومولّد سجلات للعرض والتقييم.
- **مستند التصميم:** [2026-10-26-log-ingestion-design.md](../specs/2026-10-26-log-ingestion-design.md)
- **الفرع:** `platform-core`
- **التقنيات:** Python 3.11، SQLite، pandas، scikit-learn (IsolationForest)، FastAPI، pytest.

## قرارات تقنية

- **نوافذ ثابتة (tumbling) لا منزلقة:** القواعد ونموذج الشذوذ يعملان على دلاء 5 دقائق (`floor(ts/300)*300`)، والإغراق على دلاء دقيقة. هذا يجعل وضع التاريخ (أيام في دفعة واحدة) يُفحص كاملًا لا آخر 5 دقائق منه فقط. القيد: هجوم يقع على حدّ دلوين قد ينقسم بينهما؛ يُذكر في التقييم.
- **الزمن زمن الحدث لا الساعة:** الدلاء والدمج (15 دقيقة) وتجميع الحوادث (30 دقيقة) كلها بأوقات الأحداث، فيعمل التاريخ المُعاد بنفس منطق البث المباشر.
- **إعادة فحص الدلو:** كل دفعة تُفحص على كل الدلاء التي تلمسها من قاعدة البيانات (لا الدفعة وحدها)، فهجوم موزع على دفعتين يُرى كاملًا. الدمج يأخذ `max` للعدد عند إعادة فحص نفس الدلو، ويجمع عند دلو جديد.
- **الشذوذ لا يُنبّه على ما تدرّب عليه:** يُقيَّم فقط ما بعد `trained_until`، وبحد أدنى 5 طلبات في النافذة، حتى لا يطلق وضع التاريخ ~1% تنبيهات كاذبة على بيانات تدريبه.
- **حلقة المحلل تقرأ أدواتها من الـ Workspace:** `tool_specs` و`read_tools` و`run_tool` و`describe` و`rules_proposals` و`system_prompt`. `agent.tools.Workspace` يوفرها لـ CICIDS، و`LogWorkspace` للسجلات.
- **مخطط التقرير بحسب الأنواع:** `report_schema(attack_types)` بدل `REPORT_SCHEMA` الثابت، لأن أنواع هجمات السجلات تختلف عن CICIDS.
- **التحقيق التلقائي:** طابور لكل منشأة؛ عند انتهاء تحقيق يبدأ التالي. الحادثة تُغلق إذا لم يبقَ مقترح تنفيذي معلّق، وإلا عند قرار صاحب المنشأة على آخره.

## خريطة الملفات

| الملف | جديد/تعديل | المسؤولية |
|---|---|---|
| `ingest/__init__.py` | جديد | فارغ |
| `ingest/parsers.py` | جديد | `parse_web(line)` و`parse_firewall(line, year)` ← dict أو None |
| `ingest/store.py` | جديد | `LogStore`: جداول الأحداث والتنبيهات والحوادث والحالة في `tenant.db`، الاحتفاظ، الدمج والتجميع |
| `ingest/rules.py` | جديد | `web_rules(events)` و`firewall_rules(events)` ← قائمة تنبيهات |
| `ingest/anomaly.py` | جديد | `window_features` و`AnomalyDetector` (تعلم، تدريب، تقييم، تفسير، حالة) |
| `ingest/pipeline.py` | جديد | `process_batch(store, detector, source, text, year)` |
| `ingest/evaluate.py` | جديد | تقييم الكشف بالمولّد |
| `simulate_logs.py` | جديد | مولّد السجلات (مكتبة + CLI) |
| `agent/tools.py` | تعديل | `report_schema()`؛ أساليب الـ Workspace |
| `agent/analyst.py` | تعديل | الحلقة والمحادثة تقرآن من الـ Workspace |
| `agent/log_tools.py` | جديد | `LogIncident` و`LogWorkspace` وأدوات السجلات |
| `agent/demo.py` | تعديل | مسار ثابت لحوادث السجلات |
| `tenancy/auth.py` | تعديل | `ingest_tenant` |
| `tenancy/store.py` | تعديل | `logs(tid)` و`anomaly_path(tid)` |
| `tenancy/api.py` | تعديل | الاستقبال، المصادر، الحوادث، طابور التحقيق، إغلاق الحادثة |
| `web/*` | تعديل | المصادر والحوادث في «منشأتي»، فتح حادثة في المحلل |
| `tests/test_ingest_*.py` و`tests/test_log_agent.py` و`tests/test_ingest_api.py` | جديد | الاختبارات |

---

## المهمة 1: المحللات (`ingest/parsers.py`)

- `parse_web(line)`: Combined وCommon. يرجع `{ts, ip, method, path, status, bytes, referer, ua}` (`ts` ثوانٍ UTC، `bytes` صفر لـ `-`، المسار حتى 2048 حرفًا) أو None عند فشل التحليل أو عنوان غير صالح.
- `parse_firewall(line, year)`: يبحث عن `SRC=` و`DST=` و`PROTO=` و`DPT=` والإجراء من `[UFW BLOCK|ALLOW|AUDIT]` أو كلمات `BLOCK/DROP/REJECT` في بادئة iptables (الافتراضي BLOCK)، والوقت من بادئة syslog مع السنة المعطاة UTC. يرجع `{ts, action, src, dst, proto, dport}` أو None.
- **الاختبارات (`tests/test_ingest_parsers.py`):** سطر Combined كامل؛ Common بلا محيل؛ منطقة زمنية `+0300` تُحوَّل لـ UTC؛ حجم `-`؛ سطر مشوه ← None؛ IP غير صالح ← None؛ UFW BLOCK بمنفذ؛ سطر بلا `DPT` (ICMP) ← `dport=None`؛ سطر ليس جدارًا ← None.

## المهمة 2: تخزين السجلات (`ingest/store.py`)

`LogStore(path)` ينشئ الجداول في نفس `tenant.db`:
- `insert_web(events)` و`insert_fw(events)` ← العدد.
- `prune(now, keep_seconds=7*86400, max_rows=500_000)`.
- `web_between(start, end, ip=None)` و`fw_between(...)` ← قوائم dict مرتبة بالوقت.
- `source_stats()` ← `{"web": {"events", "last_ts"}, "firewall": {...}}`.
- `add_alert(alert)` ← `(alert_id, incident_id, new_incident)`: دمج (النوع، العنوان) خلال 15 دقيقة، ثم إلحاق بحادثة غير مغلقة حُدّثت خلال 30 دقيقة أو فتح حادثة؛ خطورة الحادثة = الأعلى.
- `alerts(incident_id)` و`incidents(limit=50)` و`incident(id)` و`set_incident_status(id, status)`.
- `rule_alert_spans()` ← فترات (عنوان، من، إلى) لتنبيهات القواعد (لاستبعادها من تدريب الشذوذ).
- `state_get(key, default)` و`state_set(key, value)`.
- معرّف الحادثة نصي `log-<n>`.
- **الاختبارات (`tests/test_ingest_store.py`):** إدراج واسترجاع بنافذة وعنوان؛ الاحتفاظ بالمدة وبالحد الأقصى؛ دمج نفس التنبيه خلال 15 دقيقة وفصله بعدها؛ تنبيهان متقاربان في حادثة واحدة ومتباعدان (أكثر من 30 دقيقة) في حادثتين؛ حادثة مغلقة لا تُلحق بها تنبيهات جديدة؛ خطورة الحادثة الأعلى.

## المهمة 3: القواعد (`ingest/rules.py`)

- ثوابت العتبات والأنماط كما في المستند (`LOGIN_RE`، `SENSITIVE_RE`، `INJECTION_RE` بعد `unquote_plus` مرتين).
- كل تنبيه: `{type, source, ip, first_ts, last_ts, count, severity, evidence[<=5], details}`.
- **الاختبارات (`tests/test_ingest_rules.py`):** لكل قاعدة: عند العتبة يُطلق وتحتها بواحد لا يُطلق؛ `injection` بترميز URL مزدوج؛ مسار عادي فيه `select` كلمةً لا يُطلق؛ العدّ لكل عنوان منفصل؛ الشاهد لا يتجاوز 5.

## المهمة 4: نموذج الشذوذ (`ingest/anomaly.py`)

- `window_features(events)` ← DataFrame بـ `ip, bucket` والخصائص السبع.
- `AnomalyDetector(model_path)`:
  - `update(store, start, end)` ← قائمة تنبيهات `anomaly`: يحسب نوافذ كل التاريخ ناقص نوافذ تنبيهات القواعد، يدرّب إن بلغ 200 ولم يُدرَّب أو تضاعف العدد، ثم يقيّم نوافذ `[start, end]` الأحدث من `trained_until` بحد 5 طلبات.
  - `status(store)` ← `{"state": "learning"|"ready", "windows", "needed"}` من حالة `LogStore`.
  - التفسير: أعلى 3 خصائص |z| مقابل متوسط وانحراف التدريب.
- **الاختبارات (`tests/test_ingest_anomaly.py`):** لا تدريب ولا تنبيه تحت 200 نافذة؛ بعد تعلم ترافيك منتظم تُلتقط نافذة شاذة بوضوح (طلبات كثيرة ومسارات كثيرة ونسبة 4xx عالية) مع خصائص مفسِّرة؛ نوافذ التدريب نفسها لا تُنبَّه؛ النموذج يُحفظ ويُحمَّل.

## المهمة 5: خط المعالجة (`ingest/pipeline.py`)

`process_batch(store, detector, source, text, year)` ← `{accepted, rejected, alerts, incidents: {id: new}}`: تحليل ← إدراج ← احتفاظ ← قواعد على الدلاء الملموسة من قاعدة البيانات ← شذوذ (للويب) ← `add_alert`.
- **الاختبارات (`tests/test_ingest_pipeline.py`):** دفعة نظيفة بلا تنبيهات؛ هجوم تخمين يفتح حادثة؛ هجوم موزع على دفعتين يُكتشف؛ إعادة نفس الدفعة لا تضاعف التنبيهات (دمج)؛ سطور مشوهة تُعدّ مرفوضة.

## المهمة 6: حلقة محلل تقرأ أدواتها من الـ Workspace

- `agent/tools.py`: `report_schema(types)`؛ `TOOL_SPECS` يبقى (لـ CICIDS)؛ `Workspace` يكتسب `tool_specs` و`read_tools` و`system_prompt=None` وأساليب `run_tool` و`describe` و`rules_proposals`.
- `agent/analyst.py`: `investigate` و`chat` و`_fail` تستخدم أساليب الـ Workspace؛ `system = ws.system_prompt or SYSTEM_INVESTIGATE`.
- **التحقق:** الاختبارات الـ 56 كما هي تنجح (لا اختبارات جديدة؛ هذه مهمة إعادة هيكلة).

## المهمة 7: أدوات السجلات والعرض التجريبي

- `agent/log_tools.py`: `LogIncident(id, kind="log", family=None)`، `LogWorkspace(store, incident_id, allowlist, detector)` بالأدوات السبع وتعريفاتها و`SYSTEM_LOG` ومدد الحظر، و`sync_incident_status()`.
- `agent/demo.py`: يتعرف على السجلات من وجود `source_activity` في الأدوات، ومسار ثابت وقوالب عربية لأنواع السجلات.
- `tests/fakes.py`: لا تغيير. `Run` يتعامل مع `family=None`.
- **الاختبارات (`tests/test_log_agent.py`):** تحقيق بوضع العرض على حادثة تخمين ← تقرير بنوع `brute_force` ومقترح `block_ip` بمدة 60؛ حادثة شذوذ وحده ← بلا مقترح تنفيذي؛ عنوان في قائمة السماح ← `none`؛ `source_activity` لعنوان خارج الحادثة ← خطأ أداة؛ فحص الهلوسة على التقرير يمر؛ `sync_incident_status` يغلق عند انتهاء المعلّقات.

## المهمة 8: الـ API

- `tenancy/auth.py`: `ingest_tenant` (مفتاح الاستقبال فقط، 403 لمفتاح اللوحة).
- `tenancy/store.py`: `logs(tid)` و`anomaly_path(tid)`.
- `tenancy/api.py`:
  - `POST /ingest/{source}` (async): حد 5MB من `Content-Length` والجسم، و20,000 سطر (413)، و60 طلبًا/دقيقة لكل منشأة (429)، والمعالجة في `run_in_threadpool`، ثم إدراج الحوادث الجديدة في طابور التحقيق.
  - `GET /sources` و`GET /incidents` و`GET /incidents/{id}`.
  - طابور لكل منشأة: `_enqueue` و`_start_next`؛ التحقيق في خيط، وعند انتهائه `sync_incident_status` ثم التالي.
  - `agent/decide`: بعد القرار، `sync_incident_status` إن كانت حادثة سجلات.
- **الاختبارات (`tests/test_ingest_api.py`):** مفتاح اللوحة مرفوض على الاستقبال (403) والاستقبال مرفوض على اللوحة (403)؛ 413 للحجم والسطور؛ `source` غير معروف 404؛ هجوم تخمين ← حادثة تُحقَّق تلقائيًا حتى `investigating` بمقترح، والموافقة تغلقها؛ سجلات وحوادث A غير مرئية لـ B (404 وقوائم فارغة)؛ `/sources` يعكس العدد وآخر وقت وحالة التعلم.

## المهمة 9: المولّد والتقييم

- `simulate_logs.py`: `generate(start, minutes, rng, attacks, attack_at)` ← `(web_lines, fw_lines, labels)`؛ CLI بالخيارات `--history-days` و`--live` و`--attack` و`--attack-at` و`--url` و`--key` و`--out` و`--seed` و`--labels`؛ الإرسال بـ `urllib` على دفعات.
- `ingest/evaluate.py`: بذور 1..5؛ لكل بذرة يوم تاريخ + 30 دقيقة بكل الهجمات + 30 دقيقة نظيفة على `LogStore` مؤقت؛ المقاييس كما في المستند؛ `eval_results/log_detection.json` و`.md`.
- **الاختبارات (`tests/test_simulator.py`):** نفس البذرة ← نفس السطور؛ كل السطور تُحلَّل؛ كل هجوم يُلتقط بقاعدته المقصودة على عنوانه عبر `process_batch`؛ ترافيك نظيف لساعة بلا تنبيهات قواعد.
- **التحقق:** `project/bin/python -m ingest.evaluate` وقراءة الجدول.

## المهمة 10: الواجهة والتوثيق

- «منشأتي»: بطاقة المصادر (العدد وآخر وقت)، حالة نموذج الشذوذ (شريط تعلّم/جاهز)، قائمة الحوادث (الحالة والخطورة والأنواع والوقت) مع تحديث كل 10 ثوانٍ أثناء فتح الصفحة؛ مثال `curl` على `/api/v1/ingest/web` بلا وسم «قيد التطوير».
- المحلل: `openIncident(id)` يفتح بث تحقيق الحادثة؛ إعادة هيكلة البدء إلى `streamIncident(id)`؛ عرض «حادثة حقيقية من سجلات منشأتك» حين لا توجد حقيقة؛ قسم «محاكاة» لزر CICIDS.
- README: قسم «ربط السجلات» بأمثلة `curl` والمولّد ونتائج التقييم.
- **التحقق في المتصفح:** تسجيل منشأة ← المولّد بوضع التاريخ ثم البث بهجوم ← المصادر وحالة «جاهز» ← حادثة تظهر ← فتحها ← التقرير والموافقة ← الحادثة تُغلق. الجوال والوضعان، بلا أخطاء console.
