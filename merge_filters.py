import requests
import os
import time

# جميع الروابط
urls = [
    "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/ultimate.txt",
    "https://hole.cert.pl/domains/v2/domains.txt",  # أقوى قائمة برمجيات خبيثة (تحديث يومي)
    "https://phishing.army/download/phishing_army_blocklist.txt",  # تصيد احتيالي (تحديث فوري)
    "https://raw.githubusercontent.com/AssoEchap/stalkerware-indicators/master/generated/quad9_blocklist.txt",  # برامج تجسس
    "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/domains/native.tiktok.txt",  # تتبع تيك توك
    "https://perflyst.github.io/PiHoleBlocklist/AmazonFireTV.txt"  # إعلانات أجهزة الذكية
]

# أقصى عدد للفلاتر في كل ملف
MAX_LINES_PER_FILE = 2_000_000

# الحد الأقصى لطول السطر المسموح به قبل التقسيم
MAX_LINE_LENGTH = 5000

def split_long_line(line):
    """
    تقسم السطر الطويل جدًا إلى أجزاء أصغر مع الحفاظ على التنسيق
    """
    if len(line) <= MAX_LINE_LENGTH:
        return [line]
    
    # إذا كان السطر يحتوي على قائمة نطاقات مفصولة بـ | أو ,
    separators = ['|', ',', '^', '$']
    for sep in separators:
        if sep in line:
            parts = line.split(sep)
            if len(parts) > 1:
                # نعيد بناء السطور مع المحافظة على المحرف الفاصل
                result = []
                current_line = parts[0]
                for part in parts[1:]:
                    if len(current_line + sep + part) <= MAX_LINE_LENGTH:
                        current_line += sep + part
                    else:
                        result.append(current_line)
                        current_line = part
                if current_line:
                    result.append(current_line)
                return result
    # إذا لم نجد محرفًا مناسبًا للتقسيم، نقسم بالسطول الثابت
    return [line[i:i+MAX_LINE_LENGTH] for i in range(0, len(line), MAX_LINE_LENGTH)]

# استخدام مجموعة لإزالة التكرار
all_lines = set()

# تحميل ودمج الفلاتر
for url in urls:
    try:
        print(f"⏳ جاري تحميل: {url}")
        response = requests.get(url, timeout=30)
        response.raise_for_status()
        lines = response.text.splitlines()
        for line in lines:
            clean_line = line.strip()
            if clean_line and not clean_line.startswith(('!', '#', '@@')):  # تجاهل التعليقات والاستثناءات
                # تقسيم السطور الطويلة
                for split_line in split_long_line(clean_line):
                    all_lines.add(split_line)
        time.sleep(0.2)  # تأخير 0.2 ثانية بين كل طلب
    except Exception as e:
        print(f"❌ خطأ في تحميل {url}: {e}")

# تحويل المجموعة إلى قائمة
all_lines = list(all_lines)
total_lines = len(all_lines)
print(f"✅ تم تحميل {total_lines} فلتر فريد (بعد التقسيم).")

# إنشاء مجلد للإخراج إن لم يكن موجودًا
output_dir = "merged_filters"
os.makedirs(output_dir, exist_ok=True)

# حفظ جميع الفلاتر في ملف واحد
all_file_path = os.path.join(output_dir, "all_filters.txt")
with open(all_file_path, "w", encoding="utf-8") as f:
    f.write("\n".join(all_lines))
print(f"🗂️ تم حفظ كل الفلاتر في ملف شامل: {all_file_path}")

# تقسيم إلى ملفات حسب الحجم
file_index = 1
for i in range(0, total_lines, MAX_LINES_PER_FILE):
    chunk = all_lines[i:i + MAX_LINES_PER_FILE]
    filename = os.path.join(output_dir, f"filters_part_{file_index}.txt")
    with open(filename, "w", encoding="utf-8") as f:
        f.write("\n".join(chunk))
    print(f"📁 تم إنشاء الملف: {filename} ({len(chunk)} فلاتر)")
    file_index += 1

print("🎉 تم الانتهاء من تحميل ودمج الفلاتر بنجاح.")
