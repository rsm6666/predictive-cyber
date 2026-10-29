"""
سكربت تحميل بيانات CICIDS2017 (مستوى Flow) مع عمود الوقت الحقيقي
====================================================================
شغّله بـ: python download_flows.py

بعد ما يخلص، بيطبع لك المسار النهائي لملف الـ parquet الناتج.
"""

from nids_datasets import Dataset

print("جاري تحميل بيانات Network-Flows لـ CIC-IDS2017 (فيها Timestamp حقيقي)...")

data = Dataset(dataset="CIC-IDS2017", subset=["Network-Flows"], files="all")
data.download()

print("\n✅ خلص التحميل!")
print("دوّر على مجلد باسم: CIC-IDS2017/Network-Flows/")
print("جوا بتلقى ملف .parquet — هذا هو اللي بنستخدمه بالخطوة الجاية.")
