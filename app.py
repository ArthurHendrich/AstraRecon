from flask import Flask, request, jsonify
import subprocess
import sqlite3

app = Flask(__name__)
DATABASE = 'results.db'

def run_script(script, *args):
    command = ['python', script] + list(args)
    result = subprocess.run(command, capture_output=True, text=True)
    return result.stdout

def get_db_connection():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn

@app.route('/')
def index():
    return "Welcome to the Cybersecurity Tools API"

@app.route('/run/<tool>', methods=['POST'])
def run_tool(tool):
    target = request.json.get('target')
    additional_args = request.json.get('args', [])
    script_mapping = {
        'alienvault': 'scripts/alienvault_script.py',
        'anubis': 'scripts/anubis_script.py',
        'asnmap': 'scripts/asnmap_script.py',
        'assetfinder': 'scripts/assetfinder_script.py',
        'censys': 'scripts/censys_script.py',
        'cert_spotter': 'scripts/cert_spotter_script.py',
        'crtsh': 'scripts/crtsh_script.py',
        'gospider': 'scripts/gospider_script.py',
        'hackertarget': 'scripts/hackertarget_script.py',
        'httpx': 'scripts/httpx_script.py',
        'katana': 'scripts/katana_script.py',
        'naabu': 'scripts/naabu_script.py',
        'rapiddns': 'scripts/rapiddns_script.py',
        'security_trails': 'scripts/security_trails_script.py',
        'shodan': 'scripts/shodan_script.py',
        'spyse': 'scripts/spyse_script.py',
        'subfinder': 'scripts/subfinder_script.py',
        'tlsx': 'scripts/tlsx_script.py',
        'urlscan': 'scripts/urlscan_script.py',
        'virus_total': 'scripts/virus_total_script.py',
        'wapiti': 'scripts/wapiti_script.py',
    }

    if tool in script_mapping:
        script_path = script_mapping[tool]
        result = run_script(script_path, target, *additional_args)
        return jsonify({"result": result})
    else:
        return jsonify({"error": "Tool not found"}), 404

@app.route('/run_wordlists', methods=['POST'])
def run_wordlists():
    action = request.json.get('action')
    script_mapping = {
        'download_directory_wordlists': 'scripts/wordlists/download_directory_wordlists_script.py',
        'download_wordlists_brute': 'scripts/wordlists/download_wordlists_brute_script.py',
        'download_wordlists_fuzz': 'scripts/wordlists/download_wordlists_fuzz_script.py',
        'clone_nuclei_templates': 'scripts/wordlists/clone_nuclei_templates_script.py'
    }

    if action in script_mapping:
        script_path = script_mapping[action]
        result = run_script(script_path)
        return jsonify({"result": result})
    else:
        return jsonify({"error": "Action not found"}), 404

@app.route('/run_setup_tools', methods=['POST'])
def run_setup_tools():
    script_path = 'scripts/setup_tools/install_tools.py'
    result = run_script(script_path)
    return jsonify({"result": result})

@app.route('/results/<tool>', methods=['GET'])
def get_results(tool):
    table_mapping = {
        'alienvault': 'alienvault_results',
        'anubis': 'anubis_results',
        'asnmap': 'asnmap_results',
        'assetfinder': 'assetfinder_results',
        'censys': 'censys_results',
        'cert_spotter': 'cert_spotter_results',
        'crtsh': 'crtsh_results',
        'gospider': 'gospider_results',
        'hackertarget': 'hackertarget_results',
        'httpx': 'httpx_results',
        'katana': 'katana_results',
        'naabu': 'naabu_results',
        'rapiddns': 'rapiddns_results',
        'security_trails': 'security_trails_results',
        'shodan': 'shodan_results',
        'spyse': 'spyse_results',
        'subfinder': 'subfinder_results',
        'tlsx': 'tlsx_results',
        'urlscan': 'urlscan_results',
        'virus_total': 'virus_total_results',
        'wapiti': 'wapiti_results',
        'directory_wordlists': 'directory_wordlists',
        'brute_wordlists': 'brute_wordlists',
        'fuzz_wordlists': 'fuzz_wordlists',
        'nuclei_templates': 'nuclei_templates'
    }

    if tool in table_mapping:
        table_name = table_mapping[tool]
        conn = get_db_connection()
        results = conn.execute(f'SELECT * FROM {table_name}').fetchall()
        conn.close()
        return jsonify([dict(row) for row in results])
    else:
        return jsonify({"error": "Tool not found"}), 404

if __name__ == "__main__":
    app.run(debug=True)
