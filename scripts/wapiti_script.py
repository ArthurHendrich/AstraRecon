import subprocess
import sys
import sqlite3

DATABASE = 'results.db'

def run_wapiti(target):
    result = subprocess.run(["wapiti", "-u", target, "-v", "2"], capture_output=True, text=True)
    if result.stdout:
        with sqlite3.connect(DATABASE) as conn:
            c = conn.cursor()
            c.execute('INSERT INTO wapiti_results (target, result) VALUES (?, ?)', (target, result.stdout))
            conn.commit()

if __name__ == "__main__":
    target = sys.argv[1]
    run_wapiti(target)
