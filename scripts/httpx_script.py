import subprocess
import sys
import sqlite3

DATABASE = 'results.db'

def run_httpx(target):
    if target.startswith("http://"):
        result = subprocess.run(["httpx", f"{target}"], capture_output=True, text=True)
    else:
        result = subprocess.run(["httpx", "--no-verify", f"https://www.{target}"], capture_output=True, text=True)
    
    if result.stdout:
        with sqlite3.connect(DATABASE) as conn:
            c = conn.cursor()
            c.execute('INSERT INTO httpx_results (target, result) VALUES (?, ?)', (target, result.stdout))
            conn.commit()

if __name__ == "__main__":
    target = sys.argv[1]
    run_httpx(target)
