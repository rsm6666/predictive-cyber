# نظام التنبؤ بالهجمات السيبرانية — Predictive Cybersecurity System

نظام أمن سيبراني يعمل على مستويين: **كشف** الهجمات لحظة وقوعها، و**تنبؤ** ببداية الهجوم قبل وقوعه — ويعمل على ترافيك شبكة حقيقي، لا على بيانات محاكاة فقط.

## المميزات

- **كشف لحظي بطبقتين:** نموذج تعلّم آلي + كاشف سلوكي يرصد **٩ أنواع هجوم** (فحص منافذ، فحص UDP، فحص متخفٍّ، مسح شبكة، تخمين كلمة مرور، إغراق SYN، DoS، إغراق ICMP، DDoS).
- **تنبؤ استباقي:** مجموعة من ٥ نماذج LSTM تتوقّع بداية الهجوم في النافذة الزمنية القادمة.
- **توصية أمنية ذكية:** نموذج لغوي محلّي (Ollama) يولّد توصية استجابة عربية — بلا إرسال بيانات لأي خدمة خارجية.
- **واجهة احترافية:** لوحة ويب تعرض الكشف والتنبؤ على شبكتك الحقيقية وعلى بيانات CICIDS.

## النماذج الثلاثة

1. كاشف ثنائي (Random Forest) — هجوم/طبيعي.
2. مصنّف نوع الهجوم (Random Forest، ٧ فئات) — Macro-F1 ≈ 0.95.
3. نموذج التنبؤ (مجموعة ٥ LSTM) — تقييم بتقسيم زمني صارم.

## المتطلبات

- Python 3.11+ ، Linux / WSL
- الحزم: fastapi uvicorn scikit-learn tensorflow scapy pandas numpy joblib ollama
- nmap و tcpdump (للفحص الحي)
- Ollama مع النموذج qwen2.5:14b (للتوصية)

## التشغيل

    python3 -m venv project && source project/bin/activate
    pip install fastapi uvicorn scikit-learn tensorflow scapy pandas numpy joblib ollama
    python train_baseline_model.py
    python train_attack_type_model.py
    python train_final_lstm.py
    python prepare_dashboard_data.py
    uvicorn api_server:app --port 8000
    # ثم افتح: http://localhost:8000/app/

## ملاحظة عن البيانات والنماذج

الداتاست (CICIDS2017) والنماذج المدرّبة غير مرفوعة (حجمها كبير، مستثناة عبر .gitignore). تُعاد بتشغيل سكربتات التدريب أعلاه.

## إخلاء مسؤولية

أدوات الهجوم (attack_test.py) مخصّصة لاختبار جهازك/شبكتك الخاصة فقط بغرض التحقق من النظام. لا تُستخدم ضد أي طرف دون إذن.
