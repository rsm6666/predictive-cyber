"""
===================================================================
run.py — بوابة واحدة لكل أوامر المشروع
===================================================================
بدل ما تتذكر اسم كل سكربت، استخدم أمرًا واحدًا:

  python run.py setup          تثبيت كل المكتبات المطلوبة (مرة وحدة)
  python run.py check          فحص: أي ملفات/نماذج موجودة وأيها ناقص

  --- التدريب (شغّلها بالترتيب مرة وحدة) ---
  python run.py train-baseline تدريب الكشف اللحظي (Random Forest)
  python run.py train-type     تدريب تحديد نوع الهجوم
  python run.py train-lstm     تدريب الإنذار المبكر (مجموعة LSTM)
  python run.py train-all      الثلاثة بالتتابع

  --- العروض (بعد التدريب) ---
  python run.py explain        تفسير قرارات النموذج (أمثلة)
  python run.py act            طبقة الاستجابة (Sandbox) — موافقة يدوية
  python run.py act-auto       طبقة الاستجابة — موافقة آلية
  python run.py experiments    تجارب تحسين LSTM العلمية

  --- الداشبورد ---
  python run.py prep           تجهيز بيانات الداشبورد (مرة وحدة بعد التدريب)
  python run.py dashboard      تشغيل الداشبورد

الفكرة: الملفات تبقى منفصلة بالخلفية (كل تدريب ينتج نموذجه المحفوظ
مرة وحدة)، وأنت تتعامل مع أمر واحد بسيط.
===================================================================
"""

import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent

# كل أمر -> (الوصف, قائمة الأوامر التي تُنفَّذ)
COMMANDS = {
    "setup":          ("تثبيت المكتبات",
                       [[sys.executable, "-m", "pip", "install",
                         "pandas", "numpy", "scikit-learn", "joblib", "matplotlib",
                         "tensorflow", "streamlit", "ollama", "pyarrow",
                         "kagglehub", "nids_datasets",
                         "anthropic", "python-dotenv", "pytest"]]),
    "train-baseline": ("تدريب الكشف اللحظي", [["train_baseline_model.py"]]),
    "train-type":     ("تدريب نوع الهجوم", [["train_attack_type_model.py"]]),
    "train-lstm":     ("تدريب الإنذار المبكر", [["train_final_lstm.py"]]),
    "explain":        ("تفسير القرارات", [["explain_decision.py"]]),
    "act":            ("طبقة الاستجابة (يدوي)", [["act_demo.py"]]),
    "act-auto":       ("طبقة الاستجابة (آلي)", [["act_demo.py", "--auto-approve"]]),
    "experiments":    ("تجارب تحسين LSTM", [["improve_lstm_experiments.py"]]),
    "prep":           ("تجهيز بيانات الداشبورد", [["prepare_dashboard_data.py"]]),
}

# أوامر مركّبة أو خاصة
TRAIN_ALL = ["train-baseline", "train-type", "train-lstm"]

# الملفات/المخرجات التي يفحصها "check"
ARTIFACTS = {
    "نموذج الكشف اللحظي": "baseline_rf_model.joblib",
    "نموذج نوع الهجوم": "attack_type_model.joblib",
    "نماذج الإنذار المبكر": "lstm_final_meta.joblib",
    "بيانات الداشبورد": "dashboard_cache/lstm_windows.parquet",
}


def run_script(args):
    """يشغّل سكربت بايثون من مجلد المشروع، ويعيد رمز الخروج."""
    script = HERE / args[0]
    if not script.exists():
        print(f"❌ الملف غير موجود: {args[0]}")
        return 1
    return subprocess.call([sys.executable, str(script), *args[1:]], cwd=HERE)


def cmd_check():
    print("فحص حالة المشروع:\n")
    print("الملفات البرمجية:")
    scripts = ["train_baseline_model.py", "train_attack_type_model.py",
               "train_final_lstm.py", "train_lstm_model.py", "explain_decision.py",
               "sandbox_firewall.py", "act_demo.py", "prepare_dashboard_data.py",
               "app.py"]
    for s in scripts:
        mark = "✅" if (HERE / s).exists() else "❌ ناقص"
        print(f"  {mark} {s}")
    print("\nالنماذج والبيانات المُنتَجة:")
    for name, path in ARTIFACTS.items():
        exists = (HERE / path).exists()
        mark = "✅ جاهز" if exists else "⬜ لم يُنتَج بعد (شغّل التدريب)"
        print(f"  {mark} — {name}")
    print("\nالترتيب المقترح لأول مرة:")
    print("  python run.py setup  →  train-all  →  prep  →  dashboard")


def cmd_dashboard():
    print("تشغيل الداشبورد... افتح الرابط الذي سيظهر بالمتصفح.")
    print("(للإيقاف: Ctrl+C)\n")
    return subprocess.call(
        [sys.executable, "-m", "streamlit", "run", str(HERE / "app.py")], cwd=HERE)


def main():
    if len(sys.argv) < 2 or sys.argv[1] in ("-h", "--help", "help"):
        print(__doc__)
        return 0

    cmd = sys.argv[1]
    extra = sys.argv[2:]

    if cmd == "check":
        cmd_check()
        return 0
    if cmd == "dashboard":
        return cmd_dashboard()
    if cmd == "train-all":
        for step in TRAIN_ALL:
            desc, cmds = COMMANDS[step]
            print(f"\n{'='*60}\n▶ {desc}\n{'='*60}")
            code = run_script(cmds[0])
            if code != 0:
                print(f"\n❌ توقف عند: {step} (رمز {code})")
                return code
        print("\n✅ اكتمل كل التدريب.")
        return 0
    if cmd in COMMANDS:
        desc, cmds = COMMANDS[cmd]
        print(f"▶ {desc}\n")
        code = 0
        for c in cmds:
            code = run_script(c + extra) if cmd in ("act", "act-auto") else run_script(c)
        return code

    print(f"❌ أمر غير معروف: {cmd}\n")
    print(__doc__)
    return 1


if __name__ == "__main__":
    sys.exit(main())
