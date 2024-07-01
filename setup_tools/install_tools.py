import threading
import time
import os
import subprocess
import requests
import sys
import sqlite3
from flask import Flask, request, jsonify

DATABASE = 'results.db'
app = Flask(__name__)
LOG_FILE = 'install_log.txt'

def init_db():
    with sqlite3.connect(DATABASE) as conn:
        scripts = [
            'init_installed_tools.sql',
            'init_asnmap.sql',
            'init_assetfinder.sql',
            'init_brute_wordlists.sql',
            'init_directory_wordlists.sql',
            'init_fuzz_wordlists.sql',
            'init_gospider.sql',
            'init_httpx.sql',
            'init_katana.sql',
            'init_naabu.sql',
            'init_nuclei_templates.sql',
            'init_subfinder.sql',
            'init_tlsx.sql',
            'init_wapiti.sql'
        ]
        for script in scripts:
            with open(f'db/{script}', 'r') as f:
                conn.executescript(f.read())
        conn.commit()

init_db()

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
        log_message(f"Error during request to Pastebin: {e}")
        return ""

banner = fetch_banner()

def log_message(message):
    with open(LOG_FILE, 'a') as f:
        f.write(message + '\n')
    print(message)  # Print the log message for debugging purposes

def check_installed(tool, install_method):
    if install_method == "go":
        tool_name = tool.split('/')[2]
        result = subprocess.run(["which", tool_name], capture_output=True, text=True)
    else: 
        result = subprocess.run(["which", tool], capture_output=True, text=True)
    return result.returncode == 0

go_tools = [
    "github.com/projectdiscovery/katana/cmd/katana@latest",
    "github.com/projectdiscovery/alterx/cmd/alterx@latest",
    "github.com/projectdiscovery/cdncheck/cmd/cdncheck@latest",
    "github.com/projectdiscovery/dnsx/cmd/dnsx@latest",
    "github.com/projectdiscovery/httpx/cmd/httpx@latest",
    "github.com/projectdiscovery/dnsprobe@latest",
    "github.com/projectdiscovery/asnmap/cmd/asnmap@latest",
    "github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest",
    "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest",
    "github.com/tomnomnom/assetfinder@latest",
    "github.com/ProjectAnte/dnsgen/cmd/dnsgen@latest",
    "github.com/jaeles-project/gospider@latest",  
    "github.com/tomnomnom/waybackurls@latest",
    "github.com/hakluke/hakrawler@latest",
    "github.com/projectdiscovery/naabu/v2/cmd/naabu@latest",
    "github.com/projectdiscovery/tlsx/cmd/tlsx@latest"
]

apt_tools = [
    "curl",
    "git",
    "python3-pip"
]

def install_tool(tool, progress, lock, estimated_time, install_method="go"):
    tool_name = tool.split('/')[2] if install_method == "go" else tool
    start_time = time.time()
    process = None
    status = "Failed"

    log_message(f"Starting installation of {tool_name} using {install_method} method.")

    if install_method == "go":
        process = subprocess.Popen(["go", "install", "-v", tool], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    else: 
        process = subprocess.Popen(["sudo", "apt", "install", tool, "-y"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    while process.poll() is None:
        elapsed_time = time.time() - start_time
        progress_percent = min(int((elapsed_time / estimated_time) * 100), 100)
        with lock:
            progress[tool_name] = progress_percent
            log_message(f"{tool_name}: {progress_percent}%")
        time.sleep(1)

    with lock:
        if process.returncode == 0:
            status = "Installed"
            progress[tool_name] = 100
            log_message(f"{tool_name}: Installation complete")
        else:
            progress[tool_name] = -1
            log_message(f"{tool_name}: Installation failed")
        add_installed_tool(tool_name, install_method, status)

@app.route('/install_tools', methods=['POST'])
def install_tools():
    os.remove(LOG_FILE) if os.path.exists(LOG_FILE) else None
    estimated_times = request.json.get('estimated_times', {})
    progress = {}
    lock = threading.Lock()
    threads = []

    log_message("Starting tools installation process.")

    for tool in apt_tools:
        if not check_installed(tool, "apt"):
            est_time = estimated_times.get(tool, 60)
            thread = threading.Thread(target=install_tool, args=(tool, progress, lock, est_time, "apt"), name=tool)
            threads.append(thread)
            thread.start()
        else:
            log_message(f"{tool} is already installed.")

    for tool in go_tools:
        if not check_installed(tool, "go"):
            est_time = estimated_times.get(tool.split('/')[2], 60)
            thread = threading.Thread(target=install_tool, args=(tool, progress, lock, est_time, "go"), name=tool.split('/')[2])
            threads.append(thread)
            thread.start()
        else:
            log_message(f"{tool.split('/')[2]} is already installed.")

    while any(thread.is_alive() for thread in threads):
        time.sleep(1)

    log_message("Tools installation process completed.")
    return jsonify({"message": "All tools installation process started. Check the progress in the interface."})

@app.route('/install_log', methods=['GET'])
def get_install_log():
    if os.path.exists(LOG_FILE):
        with open(LOG_FILE, 'r') as f:
            return jsonify({"log": f.read().splitlines()})
    return jsonify({"log": []})

if __name__ == "__main__":
    # run db
    init_db()
    app.run(debug=True)

