import subprocess
import sys
import sqlite3

DATABASE = 'results.db'

def run_gospider(subdomain):
    result = subprocess.run(["gospider", "-s", subdomain], capture_output=True, text=True)
    if result.stdout:
        with sqlite3.connect(DATABASE) as conn:
            c = conn.cursor()
            c.execute('INSERT INTO gospider_results (subdomain, result) VALUES (?, ?)', (subdomain, result.stdout))
            conn.commit()

if __name__ == "__main__":
    subdomain = sys.argv[1]
    run_gospider(subdomain)
