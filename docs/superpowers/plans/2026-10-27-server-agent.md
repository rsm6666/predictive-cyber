# خطة تنفيذ: وكيل الخادم (الجزء 5)

> طلب صاحب المشروع التنفيذ مباشرة بعد الخطة ومتتابعًا بلا توقف، فهي تحدد الملفات والواجهات وحالات الاختبار، والكود يُكتب بالاختبار أولًا مع commit لكل مهمة.

- **مستند التصميم:** [2026-10-27-server-agent-design.md](../specs/2026-10-27-server-agent-design.md)
- **الفرع:** `platform-core`

## قرارات تقنية

- **`sensor/flows.py` تدريجي:** `Packet` (حقول الحزمة المطلوبة فقط) و`from_scapy(pkt)` و`FlowTable.add(packet)` و`FlowTable.rows()` ← لكل تدفق `{src, dst, sport, dport, proto, start, end, f: [77 رقمًا بترتيب FEATURES]}`. الوكيل ينشئ جدولًا جديدًا لكل نافذة، فيُقسم التدفق العابر للحد تلقائيًا. `live_capture.build_flows/flows_to_df` تصبحان غلافًا رقيقًا فوقه بنفس المخرجات (`_src`، `_dst`، `_dport`، `_proto`) حتى لا يتغير `behavioral_detector` و`live_monitor` و`capture_helper`.
- **صيغة الدفعة:** `{agent: {host, version}, window_start, window_end, truncated, flows: [...]}` بـ gzip؛ الخصائص مصفوفة لا قاموس (أصغر بكثير).
- **ملف pcap:** يُعاد بتوقيته النسبي منتهيًا «الآن» (حتى لا يُرفض كنافذة قديمة).
- **التخزين:** `net_flows(ts, src, dst, dport, proto, f TEXT)` و`net_windows(start, end, received_at, flows, truncated, total_flows, unique_dst_ports, unique_src_ips, avg_flow_duration, avg_packet_size, total_fwd_packets, total_bwd_packets)` في `tenant.db`، احتفاظ 7 أيام وسقف 500 ألف تدفق.
- **الحوادث:** `LogStore.add_alert(a, kind="log")` يأخذ النوع، والتجميع داخل النوع فقط؛ التنبيهات الشبكية بـ `kind="network"`.
- **تكييف DDoS لسياق الخادم:** قاعدة «≥ 20 مصدرًا لهدف واحد» تعمل كل دقيقة على خادم عام؛ في المنصة تتطلب أيضًا ≥ 1000 تدفق نحو الهدف في النافذة و≥ 5 أضعاف وسيط النوافذ السابقة (3 نوافذ سابقة على الأقل)، حتى لا يكفي خادم مزدحم وحده. `behavioral_detector.py` نفسه بلا تغيير.
- **إعادة تشغيل CICIDS (`simulate_flows.py`):** كل الوجهات ← عنوان الخادم، كل مهاجم ← عنوان عام ثابت، التدفقات الطبيعية ← مجمع كبير من العملاء؛ البروتوكول TCP (العيّنة بلا عمود بروتوكول). يُقاس: الطبيعي وحده ← صفر حوادث.
- **المحلل:** `NetWorkspace(Workspace)` يضيف `sync_incident_status`، و`_start_next` يبني مساحة العمل حسب نوع الحادثة؛ أداة التنبؤ ترد «غير متاح بعد» قبل 10 نوافذ؛ عنوان تقرير Telegram لا يضيف «(محاكاة)» لحوادث `network`.

## خريطة الملفات

| الملف | المسؤولية |
|---|---|
| `sensor/flows.py` | الحزم ← التدفقات ← 77 خاصية |
| `sensor/agent.py` | المصدر (واجهة/pcap)، النوافذ، الحد، المخزن المحلي، الإرسال، استثناء المنصة |
| `simulate_flows.py` | إعادة تشغيل CICIDS عبر نفس كود الإرسال |
| `live_capture.py` | غلاف فوق `sensor/flows.py` |
| `netdetect/store.py` | `NetStore`: التدفقات والنوافذ والاحتفاظ وحالة الوكيل |
| `netdetect/validate.py` | فك الضغط بحد، والتحقق من الدفعة |
| `netdetect/detect.py` | الكاشف السلوكي (أنواع `net_*`) + النموذج بحاجز الأدلة + التنبؤ |
| `netdetect/workspace.py` | `NetIncident` و`NetWorkspace` من بيانات المنشأة |
| `tenancy/api.py` | `POST /ingest/flows`، حالة الوكيل في `/sources`، الطابور حسب النوع |
| `web/*` | بطاقة «وكيل الخادم»، مؤشر LSTM، تعليمات التثبيت، أسماء الأنواع |
| `netdetect/evaluate.py` | قياس الكشف على إعادة التشغيل ← `docs/results/network_detection.md` |

## المهام

1. **خصائص التدفقات** (`tests/test_sensor_flows.py`): مصافحة TCP ← تدفق واحد باتجاه صحيح وأعداد وأعلام وأحجام صحيحة؛ UDP وICMP؛ منافذ مختلفة ← تدفقات مختلفة؛ تطابق مع `live_capture` الأصلي قبل استبداله؛ `live_capture` يبقى بنفس الأعمدة.
2. **الوكيل والمحاكي** (`tests/test_sensor_agent.py`): تقسيم pcap إلى نوافذ دقيقة؛ النافذة الفارغة تُرسل؛ فشل الإرسال ← المخزن ثم الإعادة بالترتيب؛ حد المخزن؛ حد 5000 ← `truncated`؛ استثناء اتصال المنصة؛ المحاكي يبني دفعات صالحة بعناوين عامة.
3. **الاستقبال والكشف** (`tests/test_netdetect.py`، `tests/test_netdetect_api.py`): صلاحيات المفاتيح؛ حجم وقنبلة ضغط؛ تحقق (أرقام غير محدودة، عناوين، أوقات)؛ عزل المنشآت؛ إعادة تشغيل فحص/إغراق ← حادثة `network` بالنوع الصحيح؛ طبيعي ← لا شيء؛ مصدر دون الحاجز ← لا `net_model`؛ DDoS بلا حجم ← لا شيء؛ عدم التجميع مع الأنواع الأخرى؛ حالة الوكيل والتنبؤ في `/sources`.
4. **المحلل على الحوادث الشبكية** (`tests/test_net_agent.py`): `DemoClient` يحقق في حادثة شبكية ويقترح حظرًا؛ التنبؤ قبل 10 نوافذ؛ الموافقة ← `action.execute`؛ إغلاق الحادثة بعد البت؛ عنوان Telegram بلا «(محاكاة)».
5. **الواجهة والتوثيق والقياس:** بطاقة الوكيل والمؤشر والتعليمات؛ README؛ `netdetect/evaluate.py` ونتائجه. تحقق في المتصفح: تسجيل ← `simulate_flows.py` طبيعي ثم هجوم ← حادثة شبكية ← تقرير المحلل ← موافقة ← المنفّذ التجريبي يطبع أمر `ufw`.
