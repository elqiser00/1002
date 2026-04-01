import requests
import os
import time

def delete_all_workflow_runs():
    token = os.environ.get('GITHUB_TOKEN')
    repo = os.environ.get('GITHUB_REPOSITORY')
    if not token or not repo:
        print("❌ Missing GITHUB_TOKEN or GITHUB_REPOSITORY")
        return False

    headers = {'Authorization': f'Bearer {token}', 'Accept': 'application/vnd.github.v3+json'}
    deleted = 0
    page = 1

    while True:
        url = f"https://api.github.com/repos/{repo}/actions/runs?per_page=100&page={page}"
        resp = requests.get(url, headers=headers)
        if resp.status_code != 200:
            print(f"❌ Failed to fetch runs: {resp.status_code}")
            break
        data = resp.json()
        runs = data.get('workflow_runs', [])
        if not runs:
            break
        for run in runs:
            run_id = run['id']
            del_url = f"https://api.github.com/repos/{repo}/actions/runs/{run_id}"
            del_resp = requests.delete(del_url, headers=headers)
            if del_resp.status_code == 204:
                deleted += 1
                print(f"✅ Deleted run {run_id}")
            else:
                print(f"❌ Failed to delete {run_id}: {del_resp.status_code}")
            time.sleep(0.5)
        page += 1
        time.sleep(1)
    print(f"✅ Done. Deleted {deleted} runs.")
    return True

if __name__ == "__main__":
    delete_all_workflow_runs()
