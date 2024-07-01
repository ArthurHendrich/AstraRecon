from flask import Flask, request, jsonify, render_template
import sqlite3
import subprocess
import re
import os

app = Flask(__name__)
DATABASE = 'results.db'

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

def format_target(target):
    """Formata o target para garantir que está no formato correto (ex: example.com)."""
    target = target.strip()
    if target.startswith("http://") or target.startswith("https://"):
        target = target.split("//")[1]
    return target

def run_script_and_process_results(script, tool, target, apply_regex=False):
    target = format_target(target)
    command = ['python', script, target]
    result = subprocess.run(command, capture_output=True, text=True)
    
    # Salvar resultados no banco de dados
    with sqlite3.connect(DATABASE) as conn:
        c = conn.cursor()
        c.execute(f'INSERT INTO {tool}_results (target, result) VALUES (?, ?)', (target, result.stdout))
        conn.commit()

    # Aplicar regex se necessário
    if apply_regex:
        regex_pattern = r'(\/)((?:[a-zA-Z\-_\.0-9{}]+))(\/)*((?:[a-zA-Z\-_:\.0-9{}]+))(\/)((?:[a-zA-Z\-_\/:\.0-9{}]+))'
        matches = re.findall(regex_pattern, result.stdout)
        
        with sqlite3.connect(DATABASE) as conn:
            c = conn.cursor()
            for match in matches:
                c.execute('INSERT INTO regex_results (tool, target, match) VALUES (?, ?, ?)', (tool, target, ''.join(match)))
            conn.commit()

    return result.stdout

def get_subdomains_from_db(target):
    target = format_target(target)
    subs = set()
    with sqlite3.connect(DATABASE) as conn:
        c = conn.cursor()
        for table in table_mapping.values():
            if table.endswith('_results'):
                rows = c.execute(f'SELECT subdomain FROM {table} WHERE target = ?', (target,)).fetchall()
                for row in rows:
                    subs.add(row[0])
    return list(subs)

@app.route('/')
def index():
    return render_template('index.html', title="Home", table_mapping=table_mapping)

@app.route('/run/<tool>', methods=['POST'])
def run_tool(tool):
    target = request.json.get('target')
    target = format_target(target)
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
        'wapiti': 'scripts/wapiti_script.py'
    }

    regex_tools = ['httpx', 'gospider', 'wapiti']

    if tool in script_mapping:
        apply_regex = tool in regex_tools
        result = run_script_and_process_results(script_mapping[tool], tool, target, apply_regex)
        return jsonify({"result": result})
    else:
        return jsonify({"error": "Tool not found"}), 404

@app.route('/subdomain_enumeration', methods=['GET', 'POST'])
def subdomain_enumeration():
    if request.method == 'POST':
        target = request.form.get('target')
        target = format_target(target)
        run_script_and_process_results('scripts/subfinder_script.py', 'subfinder', target)
        run_script_and_process_results('scripts/assetfinder_script.py', 'assetfinder', target)
        run_script_and_process_results('scripts/httpx_script.py', 'httpx', target, apply_regex=True)
        results = get_results_from_db('subfinder', target) + get_results_from_db('assetfinder', target) + get_results_from_db('httpx', target)
        return render_template('subdomain_enumeration.html', title="Subdomain Enumeration", results=results)
    return render_template('subdomain_enumeration.html', title="Subdomain Enumeration")

@app.route('/recon_hostname_fqdn', methods=['GET', 'POST'])
def recon_hostname_fqdn():
    if request.method == 'POST':
        target = request.form.get('target')
        target = format_target(target)
        subs = get_subdomains_from_db(target)
        for sub in subs:
            sub = sub.strip()
            run_script_and_process_results('scripts/whatweb_script.py', 'whatweb', sub)
            run_script_and_process_results('scripts/wafw00f_script.py', 'wafw00f', sub)
            run_script_and_process_results('scripts/httpx_script.py', 'httpx', sub, apply_regex=True)
            run_script_and_process_results('scripts/cmseek_script.py', 'cmseek', sub)
            run_script_and_process_results('scripts/waybackurls_script.py', 'waybackurls', sub)
            run_script_and_process_results('scripts/hakrawler_script.py', 'hakrawler', sub)
            run_script_and_process_results('scripts/naabu_script.py', 'naabu', sub)
            run_script_and_process_results('scripts/asnmap_script.py', 'asnmap', sub)
            run_script_and_process_results('scripts/tlsx_script.py', 'tlsx', sub)
            run_script_and_process_results('scripts/gospider_script.py', 'gospider', sub)
            run_script_and_process_results('scripts/wapiti_script.py', 'wapiti', sub)
            run_script_and_process_results('scripts/katana_script.py', 'katana', sub)
        results = get_results_from_db('whatweb', target) + get_results_from_db('wafw00f', target) + get_results_from_db('httpx', target) + get_results_from_db('cmseek', target) + get_results_from_db('waybackurls', target) + get_results_from_db('hakrawler', target) + get_results_from_db('naabu', target) + get_results_from_db('asnmap', target) + get_results_from_db('tlsx', target) + get_results_from_db('gospider', target) + get_results_from_db('wapiti', target) + get_results_from_db('katana', target)
        return render_template('recon_hostname_fqdn.html', title="Recon Hostname FQDN", results=results)
    return render_template('recon_hostname_fqdn.html', title="Recon Hostname FQDN")

@app.route('/results/<tool>', methods=['GET'])
def get_tool_results(tool):
    if tool in table_mapping:
        table_name = table_mapping[tool]
        conn = get_db_connection()
        results = conn.execute(f'SELECT * FROM {table_name}').fetchall()
        conn.close()
        return render_template('tool_results.html', title=f"Results for {tool}", tool_name=tool, results=[dict(row) for row in results])
    else:
        return jsonify({"error": "Tool not found"}), 404

@app.route('/concatenate_sort_outputs', methods=['POST'])
def concatenate_sort_outputs():
    input_tables = request.json.get('input_tables')
    output_table = request.json.get('output_table')
    combined_lines = set()
    with sqlite3.connect(DATABASE) as conn:
        c = conn.cursor()
        for table in input_tables:
            rows = c.execute(f'SELECT result FROM {table}').fetchall()
            for row in rows:
                combined_lines.update(row[0].splitlines())
        sorted_lines = sorted(combined_lines)
        c.execute(f'CREATE TABLE IF NOT EXISTS {output_table} (result TEXT)')
        for line in sorted_lines:
            c.execute(f'INSERT INTO {output_table} (result) VALUES (?)', (line,))
        conn.commit()
    return jsonify({"result": "Completed", "table": output_table})

@app.route('/filter_output', methods=['POST'])
def filter_output():
    input_table = request.json.get('input_table')
    output_table = request.json.get('output_table')
    filter_keyword = request.json.get('filter_keyword')
    with sqlite3.connect(DATABASE) as conn:
        c = conn.cursor()
        rows = c.execute(f'SELECT result FROM {input_table} WHERE result LIKE ?', ('%' + filter_keyword + '%',)).fetchall()
        c.execute(f'CREATE TABLE IF NOT EXISTS {output_table} (result TEXT)')
        for row in rows:
            c.execute(f'INSERT INTO {output_table} (result) VALUES (?)', (row[0],))
        conn.commit()
    return jsonify({"result": "Completed", "table": output_table})

def get_results_from_db(tool, target):
    target = format_target(target)
    if tool in table_mapping:
        table_name = table_mapping[tool]
        conn = get_db_connection()
        results = conn.execute(f'SELECT * FROM {table_name} WHERE target = ?', (target,)).fetchall()
        conn.close()
        return [dict(row) for row in results]
    else:
        return []

def get_db_connection():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn

if __name__ == "__main__":
    app.run(debug=True)
