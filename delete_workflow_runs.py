import requests
import time
import os

def delete_all_workflow_runs():
    """حذف جميع workflow runs في الريبو"""
    
    # جلب التوكن من GitHub Actions (يعمل تلقائياً)
    token = os.environ.get('GITHUB_TOKEN')
    if not token:
        print("❌ GITHUB_TOKEN غير موجود")
        return False
    
    # جلب معلومات الريبو من GitHub Actions
    repo = os.environ.get('GITHUB_REPOSITORY')
    if not repo:
        print("❌ GITHUB_REPOSITORY غير موجود")
        return False
    
    headers = {
        'Authorization': f'Bearer {token}',
        'Accept': 'application/vnd.github.v3+json'
    }
    
    deleted_count = 0
    failed_count = 0
    page = 1
    
    print(f"🚀 بدء حذف جميع workflow runs في {repo}")
    print("=" * 50)
    
    while True:
        # جلب الـ runs من الصفحة الحالية
        url = f"https://api.github.com/repos/{repo}/actions/runs"
        params = {
            'per_page': 100,
            'page': page
        }
        
        try:
            response = requests.get(url, headers=headers, params=params)
            response.raise_for_status()
            data = response.json()
            
            runs = data.get('workflow_runs', [])
            if not runs:
                print(f"\n✨ اكتمل الحذف! تم حذف {deleted_count} run")
                break
            
            print(f"\n📊 الصفحة {page}: وجدت {len(runs)} run")
            
            # حذف كل run في الصفحة
            for run in runs:
                run_id = run['id']
                run_name = run.get('name', 'Unnamed')
                created_at = run.get('created_at', 'Unknown')
                conclusion = run.get('conclusion', 'Unknown')
                
                delete_url = f"https://api.github.com/repos/{repo}/actions/runs/{run_id}"
                
                try:
                    delete_response = requests.delete(delete_url, headers=headers)
                    
                    if delete_response.status_code == 204:
                        deleted_count += 1
                        print(f"   ✅ [{deleted_count}] حذف run #{run_id} - {run_name} ({conclusion}) - {created_at[:10]}")
                    else:
                        failed_count += 1
                        print(f"   ❌ فشل حذف run #{run_id} - HTTP {delete_response.status_code}")
                    
                    # تجاوز rate limits
                    time.sleep(0.5)
                    
                except Exception as e:
                    failed_count += 1
                    print(f"   ❌ خطأ في حذف run #{run_id}: {str(e)}")
            
            page += 1
            
            # تأخير بين الصفحات
            time.sleep(1)
            
        except Exception as e:
            print(f"❌ خطأ في جلب الـ runs: {str(e)}")
            break
    
    print("=" * 50)
    print(f"\n📊 الإحصائيات النهائية:")
    print(f"   ✅ تم حذف: {deleted_count} run")
    print(f"   ❌ فشل حذف: {failed_count} run")
    
    return deleted_count > 0

if __name__ == "__main__":
    print("🔧 بدء تشغيل سكربت حذف workflow runs...\n")
    success = delete_all_workflow_runs()
    
    if success:
        print("\n🎉 تم حذف جميع الـ workflow runs بنجاح!")
    else:
        print("\n⚠️ انتهى السكربت مع بعض الأخطاء")
