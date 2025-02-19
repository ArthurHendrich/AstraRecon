import subprocess
import os
import shutil
import sqlite3

DATABASE = 'results.db'

def clone_nuclei_templates():
    print("[+] Cloning Nuclei templates...")
    clone_dir = 'nuclei-templates'
    dest_dir = '/sec/root/nuclei-templates'
    process = subprocess.Popen(["git", "clone", "https://github.com/projectdiscovery/nuclei-templates"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    stdout, stderr = process.communicate()
    
    if process.returncode == 0:
        print("[+] Nuclei templates cloned successfully.")
        if os.path.exists(dest_dir):
            shutil.rmtree(dest_dir)
        shutil.move(clone_dir, dest_dir)
        
        # Save to database
        for root, _, files in os.walk(dest_dir):
            for file in files:
                file_path = os.path.join(root, file)
                with open(file_path, 'r') as f:
                    content = f.read()
                with sqlite3.connect(DATABASE) as conn:
                    c = conn.cursor()
                    c.execute('INSERT INTO nuclei_templates (filename, content) VALUES (?, ?)', (file, content))
                    conn.commit()
    else:
        print(f"[!] Failed to clone Nuclei templates. Error: {stderr.strip()}")

if __name__ == "__main__":
    clone_nuclei_templates()
