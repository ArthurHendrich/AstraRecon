import subprocess
import sys
import sqlite3

DATABASE = 'results.db'

def run_tlsx(target):
    result = subprocess.run(["tlsx", "-silent", "-un", "-re", "-mm", "-ss", "-ex", "-ve", "-tps", "-wc", "-ja3", "-jarm", "-hash", "md5,sha1,sha265", "-tv", "-so", target], capture_output=True, text=True)
    if result.stdout:
        with sqlite3.connect(DATABASE) as conn:
            c = conn.cursor()
            c.execute('INSERT INTO tlsx_results (target, result) VALUES (?, ?)', (target, result.stdout))
            conn.commit()

if __name__ == "__main__":
    target = sys.argv[1]
    run_tlsx(target)
