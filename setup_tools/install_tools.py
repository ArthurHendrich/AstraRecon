import threading
import time
import os
import subprocess
import requests
import sys
import sqlite3
from flask import Flask, request, jsonify, render_template
from concurrent.futures import ThreadPoolExecutor

DATABASE = 'results.db'
app = Flask(__name__)

def init_db(script_name):
    with sqlite3.connect(DATABASE) as conn:
        with open(f'db/{script_name}', 'r') as f:
            conn.executescript(f.read())
        conn.commit()

# Initialize the database for installed tools
init_db('init_installed_tools.sql')

def add_installed_tool(tool_name, install_method, status):
    with sqlite3.connect(DATABASE) as conn:
        c = conn.cursor()
        c.execute('INSERT INTO installed_tools (tool_name, install_method, status) VALUES (?, ?, ?)', 
                  (tool_name, install_method, status))
        conn.commit()

def fetch_banner():
    try:
        response = requests.get("https://pastebin.com/raw/aFa3946m", verify=False)
        return response.text
    except requests.RequestException as e:
        print(f"Error during request to Pastebin: {e}", file=sys.stderr)
        return ""
  
banner = fetch_banner()

def check_installed(tool, install_method):
    if install_method == "go":
        tool_name = tool.split('/')[2]
        result = subprocess.run(["which", tool_name], capture_output=True, text=True)
    else: 
        result = subprocess.run(["which", tool], capture_output=True, text=True)
    return result.returncode == 0

def install_tool(tool, progress, lock, estimated_time, install_method="go"):
    tool_name = tool.split('/')[2] if install_method == "go" else tool
    start_time = time.time()
    process = None
    status = "Failed"

    if install_method == "go":
        process = subprocess.Popen(["go", "install", "-v", tool], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    else: 
        process = subprocess.Popen(["sudo", "apt", "install", tool, "-y"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    while process.poll() is None:
        elapsed_time = time.time() - start_time
        progress_percent = min(int((elapsed_time / estimated_time) * 100), 100)
        with lock:
            progress[tool_name] = progress_percent
        time.sleep(1)

    with lock:
        if process.returncode == 0:
            status = "Installed"
            progress[tool_name] = 100
        else:
            progress[tool_name] = -1
        add_installed_tool(tool_name, install_method, status)

@app.route('/install_tools', methods=['POST'])
def install_tools():
    go_tools = request.json.get('go_tools', [])
    apt_tools = request.json.get('apt_tools', [])
    estimated_times = request.json.get('estimated_times', {})
    progress = {}
    lock = threading.Lock()
    threads = []

    for tool in apt_tools:
        if not check_installed(tool, "apt"):
            est_time = estimated_times.get(tool, 60)
            thread = threading.Thread(target=install_tool, args=(tool, progress, lock, est_time, "apt"), name=tool)
            threads.append(thread)
            thread.start()

    for tool in go_tools:
        if not check_installed(tool, "go"):
            est_time = estimated_times.get(tool.split('/')[2], 60)
            thread = threading.Thread(target=install_tool, args=(tool, progress, lock, est_time, "go"), name=tool.split('/')[2])
            threads.append(thread)
            thread.start()

    while any(thread.is_alive() for thread in threads):
        with lock:
            os.system('clear')  
            print(banner)
            for tool, status in progress.items():
                status_str = f"{status}%" if status >= 0 else "Failed"
                print(f"[-] {tool}: Installing {status_str}")
        time.sleep(1)

    print("All tools installed successfully.")
    return jsonify({"message": "All tools installed successfully."})

if __name__ == "__main__":
    app.run(debug=True)
