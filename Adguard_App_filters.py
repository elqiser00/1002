import requests
import time
import os
import sys

def delete_all_workflow_runs(dry_run=False):
    token = os.environ.get('GITHUB_TOKEN')
    repo = os.environ.get('GITHUB_REPOSITORY')
    if not token or not repo:
        print("❌ GITHUB_TOKEN أو GITHUB_REPOSITORY غير موجود")
        return False

    headers = {
        'Authorization': f'Bearer {token}',
        'Accept': 'application/vnd.github.v3+json'
    }

    deleted = 0
    failed = 0
    page = 1

    print(f"🚀 بدء {'عرض' if dry_run else 'حذف'} جميع workflow runs في {repo}")
    print("=" * 50)

    while True:
        url = f"https://api.github.com/repos/{repo}/actions/runs"
        params = {'per_page': 100, 'page': page}
        try:
            resp = requests.get(url, headers=headers, params=params)
            resp.raise_for_status()
            data = resp.json()
            runs = data.get('workflow_runs', [])
            if not runs:
                break

            print(f"\n📄 الصفحة {page}: {len(runs)} run(s)")

            for run in runs:
                run_id = run['id']
                name = run.get('name', 'Unnamed')
                created = run.get('created_at', '')[:10]
                conclusion = run.get('conclusion', 'N/A')

                if dry_run:
                    print(f"   [DRY] سوف يتم حذف #{run_id}: {name} ({conclusion}) - {created}")
                else:
                    del_url = f"https://api.github.com/repos/{repo}/actions/runs/{run_id}"
                    del_resp = requests.delete(del_url, headers=headers)
                    if del_resp.status_code == 204:
                        deleted += 1
                        print(f"   ✅ #{run_id} تم حذفه")
                    else:
                        failed += 1
                        print(f"   ❌ #{run_id} فشل - HTTP {del_resp.status_code}")
                    time.sleep(0.5)  # تجاوز حدود السرعة

            page += 1
            time.sleep(1)

        except Exception as e:
            print(f"❌ خطأ: {e}")
            break

    print("\n" + "=" * 50)
    if dry_run:
        print(f"✨ وضع التجربة: سوف يتم حذف {deleted} run (لم يتم حذف أي شيء فعلياً)")
    else:
        print(f"✨ اكتمل: تم حذف {deleted} run, فشل {failed} run")
    return True

if __name__ == "__main__":
    dry = '--dry-run' in sys.argv
    delete_all_workflow_runs(dry_run=dry)
