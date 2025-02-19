#!/usr/bin/env python3
from flask import Flask, request, jsonify, render_template
import sqlite3
import subprocess
import re
import os
import time
import requests
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List
import sys
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from dotenv import load_dotenv

print("Script starting...")  # Debug line
sys.stdout.flush()

# Load environment variables from .env file
load_dotenv()

# Setup logging immediately
log_dir = Path('logs')
log_dir.mkdir(exist_ok=True)
print(f"Created log directory at {log_dir}")  # Debug line
sys.stdout.flush()

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(log_dir / 'recon.log'),
        logging.StreamHandler(sys.stdout)
    ]
)

logger = logging.getLogger('recon_app')
logger.info("Logging initialized")  # Debug line

app = Flask(__name__)
DATABASE = 'results.db'

table_mapping = {
    'alienvault': 'alienvault_results',
    'anubis': 'anubis_results',
    'censys': 'censys_results',
    'cert_spotter': 'cert_spotter_results',
    'crtsh': 'crtsh_results',
    'hackertarget': 'hackertarget_results',
    'rapiddns': 'rapiddns_results',
    'security_trails': 'security_trails_results',
    'shodan': 'shodan_results',
    'urlscan': 'urlscan_results',
    'virus_total': 'virus_total_results'
}

# Active tools mapping
active_tools_mapping = {
    'asnmap': 'asnmap_results',
    'assetfinder': 'assetfinder_results',
    'gospider': 'gospider_results',
    'httpx': 'httpx_results',
    'katana': 'katana_results',
    'naabu': 'naabu_results',
    'subfinder': 'subfinder_results',
    'tlsx': 'tlsx_results',
    'wapiti': 'wapiti_results',
    'whatweb': 'whatweb_results',
    'wafw00f': 'wafw00f_results',
    'waybackurls': 'waybackurls_results',
    'hakrawler': 'hakrawler_results',
    'cmseek': 'cmseek_results'
}

# Wordlist tools mapping
wordlist_mapping = {
    'directory_wordlists': 'directory_wordlists',
    'brute_wordlists': 'brute_wordlists',
    'fuzz_wordlists': 'fuzz_wordlists',
    'nuclei_templates': 'nuclei_templates'
}

# Add API configuration section
API_KEYS = {
    'cert_spotter': {
        'required': ['CERTSPOTTER_API_KEY'],
        'optional': False
    },
    'security_trails': {
        'required': ['SECURITY_TRAILS_API_KEY'],
        'optional': False
    },
    'shodan': {
        'required': ['SHODAN_API_KEY'],
        'optional': False
    },
    'urlscan': {
        'required': ['URLSCAN_API_KEY'],
        'optional': True
    },
    'virus_total': {
        'required': ['VIRUSTOTAL_API_KEY'],
        'optional': False
    }
}

# Rate limiting configuration
RATE_LIMITS = {
    'hackertarget': {'calls': 1, 'period': 5},    # 1 call per 5 seconds
    'censys': {'calls': 2, 'period': 1},          # 2 calls per second
    'shodan': {'calls': 1, 'period': 1},          # 1 call per second
    'urlscan': {'calls': 1, 'period': 2},         # 1 call per 2 seconds
    'virus_total': {'calls': 4, 'period': 60},    # 4 calls per minute
    'security_trails': {'calls': 10, 'period': 60},# 10 calls per minute
    'cert_spotter': {'calls': 10, 'period': 60},  # 10 calls per minute
    'alienvault': {'calls': 5, 'period': 60}      # 5 calls per minute
}

@dataclass
class RateLimiter:
    last_call: float = 0
    calls_made: int = 0
    last_reset: float = time.time()

    def can_call(self, tool: str) -> bool:
        now = time.time()
        if tool not in RATE_LIMITS:
            return True

        limit = RATE_LIMITS[tool]
        if now - self.last_reset >= limit['period']:
            self.calls_made = 0
            self.last_reset = now

        if self.calls_made < limit['calls']:
            return True

        sleep_time = limit['period'] - (now - self.last_reset)
        if sleep_time > 0:
            time.sleep(sleep_time)
        self.calls_made = 0
        self.last_reset = time.time()
        return True
    def record_call(self, tool: str):
        self.last_call = time.time()
        self.calls_made += 1

class ReconResult:
    def __init__(self, tool_name: str, target: str):
        self.tool_name = tool_name
        self.target = target
        self.start_time = None
        self.end_time = None
        self.status = "pending"
        self.error = None
        self.subdomains = set()

    def to_dict(self):
        return {
            "tool": self.tool_name,
            "target": self.target,
            "duration": f"{self.end_time - self.start_time:.2f}s" if self.end_time else None,
            "status": self.status,
            "error": str(self.error) if self.error else None,
            "subdomains_found": len(self.subdomains)
        }

class ReconManager:
    def __init__(self, database: str = 'results.db'):
        self.database = database
        self.rate_limiters: Dict[str, RateLimiter] = {}
        self.setup_database()
        self.setup_logging()

    def setup_logging(self):
        log_dir = Path('logs')
        log_dir.mkdir(exist_ok=True)
        
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(log_dir / 'recon.log'),
                logging.StreamHandler(sys.stdout)  # Also log to stdout
            ]
        )
        self.logger = logging.getLogger('recon_manager')

    def setup_database(self):
        try:
            with sqlite3.connect(self.database) as conn:
                c = conn.cursor()
                # Create a table to track tool executions
                c.execute('''CREATE TABLE IF NOT EXISTS tool_executions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    tool TEXT,
                    target TEXT,
                    start_time TIMESTAMP,
                    end_time TIMESTAMP,
                    status TEXT,
                    error TEXT,
                    subdomains_found INTEGER
                )''')
                
                # Create tables for all tools
                for table in table_mapping.values():
                    c.execute(f'''CREATE TABLE IF NOT EXISTS {table} (
                        domain TEXT,
                        subdomain TEXT,
                        UNIQUE(domain, subdomain)
                    )''')
                
                # Create tables for active tools
                for table in active_tools_mapping.values():
                    c.execute(f'''CREATE TABLE IF NOT EXISTS {table} (
                        domain TEXT,
                        subdomain TEXT,
                        UNIQUE(domain, subdomain)
                    )''')
                
                # Create regex results table
                c.execute('''CREATE TABLE IF NOT EXISTS regex_results (
                    tool TEXT,
                    target TEXT,
                    match TEXT,
                    UNIQUE(tool, target, match)
                )''')
                
                conn.commit()
        except sqlite3.Error as e:
            self.logger.error(f"Database initialization error: {str(e)}")
            raise

    def get_rate_limiter(self, tool: str) -> RateLimiter:
        if tool not in self.rate_limiters:
            self.rate_limiters[tool] = RateLimiter()
        return self.rate_limiters[tool]

    def run_tool(self, tool: str, script: str, target: str) -> ReconResult:
        result = ReconResult(tool, target)
        result.start_time = time.time()
        
        try:
            # Check API keys if needed
            if tool in API_KEYS:
                self._check_api_keys(tool)

            # Apply rate limiting
            rate_limiter = self.get_rate_limiter(tool)
            if not rate_limiter.can_call(tool):
                raise Exception(f"Rate limit exceeded for {tool}")
            
            self.logger.info(f"Starting {tool} scan for {target}")
            
            # Run the tool and record the call
            output = self._run_script(script, target)
            rate_limiter.record_call(tool)
            
            # Process and save results
            subdomains = self._process_output(tool, output, target)
            self._save_results(tool, target, subdomains)
            
            result.subdomains = set(subdomains)
            result.status = "completed"
            
        except Exception as e:
            result.status = "failed"
            result.error = str(e)
            self.logger.error(f"Error in {tool} for {target}: {e}")
        
        finally:
            result.end_time = time.time()
            self._log_execution(result)
            return result

    def _check_api_keys(self, tool: str):
        if tool not in API_KEYS:
            return
        
        missing_keys = [key for key in API_KEYS[tool]['required'] if not os.getenv(key)]
        if missing_keys and not API_KEYS[tool]['optional']:
            raise ValueError(f"Missing required API keys for {tool}: {', '.join(missing_keys)}")

    def _run_script(self, script: str, target: str) -> str:
        try:
            result = subprocess.run(
                ['python3', script, target],
                capture_output=True,
                text=True,
                timeout=300  # 5 minutes timeout
            )
            if result.returncode != 0:
                raise Exception(f"Script failed with error: {result.stderr}")
            return result.stdout
        except subprocess.TimeoutExpired:
            raise Exception("Script execution timed out")

    def _process_output(self, tool: str, output: str, target: str) -> List[str]:
        subdomains = set()
        for line in output.splitlines():
            subdomain = line.strip().lower()
            if subdomain and subdomain.endswith(target):
                subdomains.add(subdomain)
        return list(subdomains)

    def _save_results(self, tool: str, target: str, subdomains: List[str]):
        table = f"{tool}_results"
        with sqlite3.connect(self.database) as conn:
            c = conn.cursor()
            c.execute(f'CREATE TABLE IF NOT EXISTS {table} (domain TEXT, subdomain TEXT, UNIQUE(domain, subdomain))')
            for subdomain in subdomains:
                c.execute(f'INSERT OR IGNORE INTO {table} (domain, subdomain) VALUES (?, ?)', 
                         (target, subdomain))
            conn.commit()

    def _log_execution(self, result: ReconResult):
        with sqlite3.connect(self.database) as conn:
            c = conn.cursor()
            c.execute('''INSERT INTO tool_executions 
                        (tool, target, start_time, end_time, status, error, subdomains_found)
                        VALUES (?, ?, ?, ?, ?, ?, ?)''',
                     (result.tool_name, result.target, 
                      datetime.fromtimestamp(result.start_time),
                      datetime.fromtimestamp(result.end_time),
                      result.status, result.error, len(result.subdomains)))
            conn.commit()

def fetch_banner():
    try:
        response = requests.get("https://pastebin.com/raw/aFa3946m", verify=True)
        return response.text
    except requests.RequestException as e:
        logging.warning(f"Could not fetch banner: {e}")
        return "AstraRecon - Reconnaissance Tool"

banner = fetch_banner()

def format_target(target):
    """Formata o target para garantir que está no formato correto (ex: example.com)."""
    target = target.strip()
    if target.startswith("http://") or target.startswith("https://"):
        target = target.split("//")[1]
    return target

def run_script_and_process_results(script, tool, target=None, apply_regex=False):
    try:
        if target:
            target = format_target(target)
            command = ['python3', script, target]
        else:
            command = ['python3', script]
            
        result = subprocess.run(command, capture_output=True, text=True, timeout=300)
        
        if result.returncode != 0:
            logging.error(f"Script {script} failed with error: {result.stderr}")
            return ""
        
        # Save results to database
        try:
            with sqlite3.connect(DATABASE) as conn:
                c = conn.cursor()
                if target:
                    c.execute(f'CREATE TABLE IF NOT EXISTS {tool}_results (target TEXT, result TEXT)')
                    c.execute(f'INSERT INTO {tool}_results (target, result) VALUES (?, ?)', 
                            (target, result.stdout))
                else:
                    c.execute(f'CREATE TABLE IF NOT EXISTS {tool}_results (result TEXT)')
                    c.execute(f'INSERT INTO {tool}_results (result) VALUES (?)', 
                            (result.stdout,))
                conn.commit()
        except sqlite3.Error as e:
            logging.error(f"Database error while saving results for {tool}: {str(e)}")

        # Process regex if needed
        if apply_regex and result.stdout:
            try:
                regex_pattern = r'(\/)((?:[a-zA-Z\-_\.0-9{}]+))(\/)*((?:[a-zA-Z\-_:\.0-9{}]+))(\/)((?:[a-zA-Z\-_\/:\.0-9{}]+))'
                matches = re.findall(regex_pattern, result.stdout)
                
                with sqlite3.connect(DATABASE) as conn:
                    c = conn.cursor()
                    c.execute('CREATE TABLE IF NOT EXISTS regex_results (tool TEXT, target TEXT, match TEXT, UNIQUE(tool, target, match))')
                    for match in matches:
                        try:
                            c.execute('INSERT OR IGNORE INTO regex_results (tool, target, match) VALUES (?, ?, ?)', 
                                    (tool, target, ''.join(match)))
                        except sqlite3.Error as e:
                            logging.error(f"Error inserting regex match for {tool}: {str(e)}")
                    conn.commit()
            except Exception as e:
                logging.error(f"Error processing regex for {tool}: {str(e)}")

        return result.stdout
        
    except subprocess.TimeoutExpired:
        logging.error(f"Script {script} timed out after 300 seconds")
        return ""
    except Exception as e:
        logging.error(f"Error running script {script}: {str(e)}")
        return ""

def get_results_from_db(tool: str, target: str) -> List[dict]:
    """Get results for a specific tool and target from the database."""
    with sqlite3.connect(DATABASE) as conn:
        conn.row_factory = sqlite3.Row
        c = conn.cursor()
        
        # Check if tool is in passive or active tools
        table_name = None
        if tool in table_mapping:
            table_name = table_mapping[tool]
        elif tool in active_tools_mapping:
            table_name = active_tools_mapping[tool]
            
        if not table_name:
            return []
            
        try:
            results = c.execute(f'SELECT * FROM {table_name} WHERE domain = ?', (target,)).fetchall()
            return [dict(row) for row in results]
        except sqlite3.Error as e:
            logging.error(f"Database error when fetching results for {tool}: {str(e)}")
            return []

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
    return render_template('index.html', title="Home", table_mapping=table_mapping, banner=banner)

@app.route('/run/<tool>', methods=['POST'])
def run_tool(tool):
    target = request.json.get('target')
    target = format_target(target)
    
    # Combine all tool mappings
    all_script_mappings = {
        # Passive recon tools
        'alienvault': 'scripts/alienvault_script.py',
        'anubis': 'scripts/anubis_script.py',
        'censys': 'scripts/censys_script.py',
        'cert_spotter': 'scripts/cert_spotter_script.py',
        'crtsh': 'scripts/crtsh_script.py',
        'hackertarget': 'scripts/hackertarget_script.py',
        'rapiddns': 'scripts/rapiddns_script.py',
        'security_trails': 'scripts/security_trails_script.py',
        'shodan': 'scripts/shodan_script.py',
        'urlscan': 'scripts/urlscan_script.py',
        'virus_total': 'scripts/virus_total_script.py',
        
        # Active recon tools
        'asnmap': 'scripts/asnmap_script.py',
        'assetfinder': 'scripts/assetfinder_script.py',
        'gospider': 'scripts/gospider_script.py',
        'httpx': 'scripts/httpx_script.py',
        'katana': 'scripts/katana_script.py',
        'naabu': 'scripts/naabu_script.py',
        'subfinder': 'scripts/subfinder_script.py',
        'tlsx': 'scripts/tlsx_script.py',
        'wapiti': 'scripts/wapiti_script.py',
        'whatweb': 'scripts/whatweb_script.py',
        'wafw00f': 'scripts/wafw00f_script.py',
        'waybackurls': 'scripts/waybackurls_script.py',
        'hakrawler': 'scripts/hakrawler_script.py',
        'cmseek': 'scripts/cmseek_script.py'
    }

    # Tools that require regex processing
    regex_tools = ['httpx', 'gospider', 'wapiti', 'hakrawler', 'waybackurls']

    if tool in all_script_mappings:
        apply_regex = tool in regex_tools
        result = run_script_and_process_results(all_script_mappings[tool], tool, target, apply_regex)
        return jsonify({"result": result})
    else:
        return jsonify({"error": "Tool not found"}), 404

@app.route('/run_wordlist/<wordlist_script>', methods=['POST'])
def run_wordlist_script(wordlist_script):
    wordlist_script_mapping = {
        'clone_nuclei_templates': 'wordlists/clone_nuclei_templates_script.py',
        'download_directory_wordlists': 'wordlists/download_directory_wordlists_script.py',
        'download_wordlists_brute': 'wordlists/download_wordlists_brute_script.py',
        'download_wordlists_fuzz': 'wordlists/download_wordlists_fuzz_script.py'
    }

    if wordlist_script in wordlist_script_mapping:
        result = run_script_and_process_results(wordlist_script_mapping[wordlist_script], wordlist_script)
        return jsonify({"result": result})
    else:
        return jsonify({"error": "Wordlist script not found"}), 404

@app.route('/subdomain_enumeration', methods=['GET', 'POST'])
def subdomain_enumeration():
    if request.method == 'POST':
        target = request.form.get('target')
        target = format_target(target)
        run_script_and_process_results('scripts/subfinder_script.py', 'subfinder', target)
        run_script_and_process_results('scripts/assetfinder_script.py', 'assetfinder', target)
        run_script_and_process_results('scripts/httpx_script.py', 'httpx', target, apply_regex=True)
        results = get_results_from_db('subfinder', target) + get_results_from_db('assetfinder', target) + get_results_from_db('httpx', target)
        return render_template('subdomain_enumeration.html', title="Subdomain Enumeration", results=results, banner=banner)
    return render_template('subdomain_enumeration.html', title="Subdomain Enumeration", banner=banner)

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
        return render_template('recon_hostname_fqdn.html', title="Recon Hostname FQDN", results=results, banner=banner)
    return render_template('recon_hostname_fqdn.html', title="Recon Hostname FQDN", banner=banner)

@app.route('/results/<tool>', methods=['GET'])
def get_tool_results(tool):
    if tool in table_mapping:
        table_name = table_mapping[tool]
        conn = get_db_connection()
        results = conn.execute(f'SELECT * FROM {table_name}').fetchall()
        conn.close()
        return render_template('tool_results.html', title=f"Results for {tool}", tool_name=tool, results=[dict(row) for row in results], banner=banner)
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

@app.route('/install_tools', methods=['POST'])
def install_tools():
    subprocess.Popen(["python", "setup_tools/install_tools.py"])
    return jsonify({"message": "Installation started. Check the terminal for progress."})

@app.route('/install_log', methods=['GET'])
def get_install_log():
    if os.path.exists('install_log.txt'):
        with open('install_log.txt', 'r') as f:
            return jsonify({"log": f.read().splitlines()})
    return jsonify({"log": []})

@app.route('/soft_recon', methods=['GET', 'POST'])
def soft_recon():
    if request.method == 'POST':
        target = request.form.get('target')
        results = execute_soft_recon(target)
        return jsonify(results)
    return jsonify({"error": "POST method required"})

def get_db_connection():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn

def check_api_keys() -> Dict[str, bool]:
    """Check which API keys are available and valid."""
    api_status = {}
    for tool, config in API_KEYS.items():
        if config['optional']:
            api_status[tool] = all(os.getenv(key) for key in config['required'])
        else:
            api_status[tool] = all(os.getenv(key) for key in config['required'])
            if not api_status[tool]:
                logging.warning(f"Required API keys for {tool} are missing")
    return api_status

def execute_soft_recon(target: str) -> Dict:
    target = format_target(target)
    recon_manager = ReconManager()
    
    # Check API keys status
    api_status = check_api_keys()
    
    # Filter tools based on API key availability
    passive_tools = {
        'alienvault': 'scripts/alienvault_script.py',
        'anubis': 'scripts/anubis_script.py',
        'crtsh': 'scripts/crtsh_script.py',
        'hackertarget': 'scripts/hackertarget_script.py',
        'rapiddns': 'scripts/rapiddns_script.py'
    }
    
    # Add API-dependent tools only if keys are available
    for tool, config in API_KEYS.items():
        if api_status.get(tool, False):
            passive_tools[tool] = f'scripts/{tool}_script.py'
    
    start_time = time.time()
    all_results = []
    unique_subdomains = set()
    failed_tools = []
    skipped_tools = []
    
    recon_manager.logger.info(f"Starting soft recon for {target}")
    
    # Use ThreadPoolExecutor for controlled parallel execution
    with ThreadPoolExecutor(max_workers=5) as executor:
        future_to_tool = {
            executor.submit(recon_manager.run_tool, tool, script, target): tool 
            for tool, script in passive_tools.items()
        }
        
        for future in as_completed(future_to_tool):
            result = future.result()
            all_results.append(result)
            
            if result.status == "completed":
                unique_subdomains.update(result.subdomains)
            else:
                failed_tools.append(result.tool_name)
    
    execution_time = time.time() - start_time
    
    # Add information about skipped tools due to missing API keys
    for tool in API_KEYS:
        if not api_status.get(tool, False) and not API_KEYS[tool]['optional']:
            skipped_tools.append(tool)
    
    summary = {
        "target": target,
        "execution_time": f"{execution_time:.2f}s",
        "total_tools_available": len(passive_tools),
        "tools_skipped": skipped_tools,
        "successful_tools": len(passive_tools) - len(failed_tools),
        "failed_tools": failed_tools,
        "unique_subdomains_found": len(unique_subdomains),
        "tool_results": [r.to_dict() for r in all_results],
        "subdomains": sorted(list(unique_subdomains))
    }
    
    recon_manager.logger.info(f"Completed soft recon for {target}. Found {len(unique_subdomains)} unique subdomains")
    return summary

if __name__ == "__main__":
    if len(sys.argv) > 1:
        # Command-line mode
        if len(sys.argv) != 2:
            print("Usage: python3 app.py <target>")
            sys.exit(1)
        target = sys.argv[1]
        logger.info(f"\nStarting reconnaissance for {target}...")
        
        try:
            logger.info("Initializing recon manager...")
            recon_manager = ReconManager()
            logger.info("Checking API keys...")
            api_status = check_api_keys()
            logger.info("\nAPI Status:")
            for tool, status in api_status.items():
                logger.info(f"- {tool}: {'Available' if status else 'Missing'}")
            
            logger.info("\nExecuting soft recon...")
            results = execute_soft_recon(target)
            logger.info("\n=== Soft Recon Summary ===")
            logger.info(f"Target: {results['target']}")
            logger.info(f"Execution Time: {results['execution_time']}")
            logger.info(f"Tools Run: {results['successful_tools']}/{results['total_tools_available']}")
            
            if results['tools_skipped']:
                logger.info("\nSkipped Tools (Missing API Keys):")
                for tool in results['tools_skipped']:
                    logger.info(f"- {tool}")
            
            if results['failed_tools']:
                logger.info("\nFailed Tools:")
                for tool in results['failed_tools']:
                    logger.info(f"- {tool}")
            
            logger.info(f"\nTotal Unique Subdomains Found: {results['unique_subdomains_found']}")
            if results['unique_subdomains_found'] > 0:
                logger.info("\nSubdomains:")
                for subdomain in sorted(results['subdomains']):
                    logger.info(f"- {subdomain}")
        except Exception as e:
            logger.error(f"Error during reconnaissance: {str(e)}", exc_info=True)
            sys.exit(1)
    else:
        # Web application mode
        app.run(host='0.0.0.0', port=5000, debug=True)
