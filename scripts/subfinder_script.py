import subprocess
import sys
import sqlite3

DATABASE = 'results.db'

def run_subfinder(target):
    result = subprocess.run(["subfinder", "--all", "--silent", "-d", target], capture_output=True, text=True)
    if result.stdout:
        with sqlite3.connect(DATABASE) as conn:
            c = conn.cursor()
            c.execute('INSERT INTO subfinder_results (target, result) VALUES (?, ?)', (target, result.stdout))
            conn.commit()

if __name__ == "__main__":
    target = sys.argv[1]
    run_subfinder(target)
