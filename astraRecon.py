"""

Solving problems if don't find the path of the tools
export PATH=$PATH:/home/kali/go/bin
source ~/.bashrc  # or source ~/.zshrc
sudo ln -s /home/kali/go/bin/subfinder /usr/local/bin/subfinder

developed by: @

"""

import argparse
import subprocess
import threading
import time
import requests
import os
import sys
import re
import shutil
from concurrent.futures import ThreadPoolExecutor
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
filterkeyword = "h3ll0w0rld"
os.environ['PATH'] += os.pathsep + '/home/kali/go/bin'


def safe_request(url):
    try:
        response = requests.get(url, stream=True, verify=False)
        return response
    except requests.RequestException as e:
        print(f"Error during request to {url}: {e}", file=sys.stderr)
        return None

def safe_subprocess_run(command, **kwargs):
    try:
        return subprocess.run(command, capture_output=True, text=True, check=True, **kwargs)
    except subprocess.CalledProcessError as e:
        print(f"Error running command {command}: {e}", file=sys.stderr)
        return None

def log_message(message, log_file="script.log"):
    with open(log_file, "a") as f:
        f.write(message + "\n")
        
def download_link(url):
    log_message(f"Downloading {url.split('/')[-1]}...")
    response = safe_request(url)
    if response and response.status_code == 200:
        file_size = int(response.headers.get('content-length', 0))
        chunk_size = 1024  # 1 KiB
        with open(url.split("/")[-1], "wb") as f, tqdm(
            total=file_size, unit='iB', unit_scale=True
        ) as bar:
            for data in response.iter_content(chunk_size=chunk_size):
                f.write(data)
                bar.update(len(data))
    else:
        log_message(f"Failed to download {url}")


def fetch_banner():
    try:
        response = requests.get("https://pastebin.com/raw/aFa3946m", verify=False)
        return response.text
    except requests.RequestException as e:
        print(f"Error during request to Pastebin: {e}", file=sys.stderr)
        return ""
  
banner = fetch_banner()

def install_tool(tool, progress, lock, estimated_time, install_method="go"):
    tool_name = tool.split('/')[2] if install_method == "go" else tool
    start_time = time.time()
    process = None

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
        progress[tool_name] = 100 if process.returncode == 0 else -1


def check_installed(tool, install_method):
    if install_method == "go":
        tool_name = tool.split('/')[2]
        result = subprocess.run(["which", tool_name], capture_output=True, text=True)
    else: 
        result = subprocess.run(["which", tool], capture_output=True, text=True)
    return result.returncode == 0

def install_go():
    print("[-] Installing Go in the background...")
    process = subprocess.Popen(["sudo", "apt", "install", "golang-go", "-y"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    stdout, stderr = process.communicate()
    
    if process.returncode == 0:
        print("[+] Go installed successfully.")
    else:
        print(f"[!] Failed to install Go. Error: {stderr.strip()}")

def install_tools():
    print("Installing Go tools in the background...")
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
    
    apt_tools = ["dnsgen", "libpcap-dev"]

    estimated_times = {"katana": 60, "alterx": 60, "cdncheck": 60, "dnsx": 60, "dnsprobe@latest": 60, "asnmap": 60, "nuclei": 60, "subfinder": 60, "assetfinder@latest": 60, "gospider@latest": 60, "dnsgen": 60}
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

    while True:
        with lock:
            os.system('clear')  
            print(banner)
            all_completed = True
            for tool, status in progress.items():
                status_str = f"{status}%" if status >= 0 else "Failed"
                print(f"[-] {tool}: Installing {status_str}")
                if status < 100 and status >= 0:
                    all_completed = False
        if all_completed:
            break
        time.sleep(1)

    print("All tools installed successfully.")

    create_and_download('brute', download_wordlists_brute)
    create_and_download('subdomains', download_wordlists_fuzz)
    create_and_download('directorys', download_directory_wordlists)

    clone_nuclei_templates()
    


def create_and_download(directory_name, download_function):
    os.makedirs(directory_name, exist_ok=True)
    current_dir = os.getcwd()
    os.chdir(directory_name)
    download_function()
    os.chdir(current_dir)
    
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
    else:
        print(f"[!] Failed to clone Nuclei templates. Error: {stderr.strip()}")

def download_directory_wordlists():
    directory_wordlists = [
        "https://gist.githubusercontent.com/yassineaboukir/8e12adefbd505ef704674ad6ad48743d/raw/3ea2b7175f2fcf8e6de835c72cb2b2048f73f847/List%2520of%2520API%2520endpoints%2520&%2520objects",
        "https://gist.githubusercontent.com/helcaraxeals/7c45201b1c957ecea82ef7800da4bfa4/raw/b84a7364f33f2eb14aad68149302077649d70acc/api_wordlist.txt",
        "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/common-api-endpoints-mazen160.txt",
        "https://raw.githubusercontent.com/Karanxa/Bug-Bounty-Wordlists/main/api.txt",
        "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/directory-list-2.3-medium.txt",
        "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/directory-list-2.3-big.txt",
        "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/coldfusion.txt",
        "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/big.txt",
        "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/apache.txt",
        "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/api/api-endpoints.txt",
        "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/Common-PHP-Filenames.txt",
        "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/Common-DB-Backups.txt",
        "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/CGIs.txt",
        "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/Logins.fuzz.txt"
    ]

    for url in directory_wordlists:
        download_link(url)

def download_link(url):
    filename = url.split("/")[-1]
    print(f"Downloading {filename}...")
    response = requests.get(url, stream=True, verify=False)
    with open(filename, "wb") as f:
        f.write(response.content)
    print(f"Downloaded {filename}.")

def download_wordlists_brute():
    wordlists = {
    "https://raw.githubusercontent.com/Karanxa/Bug-Bounty-Wordlists/main/api.txt",
    "https://raw.githubusercontent.com/Karanxa/Bug-Bounty-Wordlists/main/all-files-leaked.txt",
    "https://raw.githubusercontent.com/Karanxa/Bug-Bounty-Wordlists/main/cgi-bin.txt",
    "https://raw.githubusercontent.com/Karanxa/Bug-Bounty-Wordlists/main/cgi-files.txt",
    "https://raw.githubusercontent.com/Karanxa/Bug-Bounty-Wordlists/main/dotfiles.txt",  
    "https://raw.githubusercontent.com/Karanxa/Bug-Bounty-Wordlists/main/git_config.txt", 
    }

    with ThreadPoolExecutor(max_workers=10) as executor:
      for url in wordlists:
          executor.submit(download_link, url)

def download_wordlists_fuzz():
  wordlists = {
    "https://raw.githubusercontent.com/danTaler/WordLists/master/Subdomain.txt",
    "https://raw.githubusercontent.com/theMiddleBlue/DNSenum/master/wordlist/subdomains-top1mil-20000.txt"
  }
  
  with ThreadPoolExecutor(max_workers=10) as executor:
      for url in wordlists:
          executor.submit(download_link, url)

def run_command(command):
    result = safe_subprocess_run(command)
    return result.stdout if result else ""

def run_commands_in_parallel(commands): # 
    with ThreadPoolExecutor(max_workers=50) as executor: 
        futures = [executor.submit(safe_subprocess_run, command) for command in commands]
        results = [future.result() for future in futures]
        return results

def run_subfinder(target):
    result = safe_subprocess_run(["subfinder", "--all", "--silent", "-d", target])
    if result:
        with open(f'subs/subs.{target}.tmp', 'a') as f:
            f.write(result.stdout)

def run_assetfinder(target):
    result = safe_subprocess_run(["assetfinder", "--subs-only", target])
    if result:
        with open(f'subs/subs.{target}.tmp', 'a') as f:
            f.write(result.stdout)

def run_httpx(target):
    if target.startswith("http://"):
        result = safe_subprocess_run(["httpx", f"{target}"])
    else:
        result = safe_subprocess_run(["httpx", "--no-verify", f"https://www.{target}"])
    
    os.makedirs('infos', exist_ok=True)

    if result:
        with open(f'infos/httpx.{target}', 'a') as f:
            f.write(result.stdout)


def run_naabu(target):
    ports = "1883,8889,443,80,3000,6090,9060,8060,21,111,14430,24430,34430,44430,54430,64430,74430,84430,94430,104430,4430,8080,8081,8082,8083,8084,8085,8086,8087,8088,8089,9090,9091,9092,9093,9094,9095,9096,9097,9098,9099,1443,2443,3443,4443,5443,6443,7443,8443,9443,10443,11443,12443,13443,14443,15443,16443,17443,18443,19443,20443,21443,22443,23443,24443,25443,26443,27443,28443,29443,30443,31443,32443,33443,34443,35443,36443,37443,38443,39443,40443,41443,42443,43443,44443,45443,46443,47443,48443,49443,50443,51443,52443,53443,54443,55443,56443,57443,58443,59443,60443,61443,62443,63443,64443,65443,66443,67443,68443,69443,70443,71443,72443,73443,74443,75443,76443,77443,78443,79443,80443,81443,82443,83443,84443,85443,86443,87443,88443,89443,90443,91443,92443,93443,94443,95443,96443,97443,98443,99443,100443"
    run_tool_and_save_output(["naabu", "-silent", "-p", ports, target], f'infos/ports-subs.{target}')

def run_asnmap(target):
    run_tool_and_save_output(["asnmap", "-json", "-silent", target], f'infos/asnmap.{target}')

def run_tlsx(target):
    run_tool_and_save_output(["tlsx", "-silent", "-un", "-re", "-mm", "-ss", "-ex", "-ve", "-tps", "-wc", "-ja3", "-jarm", "-hash", "md5,sha1,sha265", "-tv", "-so", target], f'infos/tlsx.{target}')

def run_gospider(subdomain):
    run_tool_and_save_output(["gospider", "-s", subdomain], f'infos/gospider.{subdomain}')

def run_wapiti(target):
    run_tool_and_save_output(["wapiti", "-u", target, "-v", "2"], f'infos/wapiti.{target}')

def run_katana(target):
    run_tool_and_save_output(["katana", target], f'infos/katana.{target}')

def run_curl_regex(target):
    try:
        curl_output = subprocess.run(
            ["curl", "-ks", target],
            capture_output=True, text=True, timeout=10
        ).stdout
        regex_matches = re.findall(r'(\/)((?:[a-zA-Z\-_\r\.0-9\{\}]+))(\/)*((?:[a-zA-Z\-_\:\.0-9\{\}]+))(\/)((?:[a-zA-Z\-_\/\:\.0-9\{\}]+))', curl_output)
        with open(f'infos/regexedAPI.{target}', 'a') as regex_file:
            for match in regex_matches:
                regex_file.write(''.join(match) + '\n')
    except subprocess.TimeoutExpired:
        print(f"[!] Timeout reached for curl on {target}")

def run_tool_and_save_output(command, output_file):
    try:
        result = subprocess.run(command, capture_output=True, text=True, timeout=10)
        with open(output_file, 'a') as file:
            file.write(result.stdout)
    except subprocess.TimeoutExpired:
        print(f"[!] Timeout reached for {' '.join(command)}")

def run_curl_and_process(sub, target):
    try:
        curl_output = subprocess.run(
            ["curl", "-ks", sub],
            capture_output=True, text=True, timeout=10
        ).stdout
        regex_matches = re.findall(r'(\/)((?:[a-zA-Z\-_\.0-9{}]+))(\/)*((?:[a-zA-Z\-_:\.0-9{}]+))(\/)((?:[a-zA-Z\-_\/:\.0-9{}]+))', curl_output)
        with open(f'infos/regexedAPI.{target}', 'a') as regex_file:
            for match in regex_matches:
                regex_file.write(''.join(match) + '\n')
    except subprocess.TimeoutExpired:
        print(f"[!] Timeout reached for curl on {sub}")

def concatenate_sort_outputs(input_files, output_file):
    combined_lines = set()
    for file in input_files:
        with open(file, 'r') as f:
            combined_lines.update(f.readlines())

    sorted_lines = sorted(combined_lines)
    with open(output_file, 'w') as f:
        f.writelines(sorted_lines)
        
def filter_output(input_file, output_file, filter_keyword):
    with open(input_file, 'r') as infile, open(output_file, 'w') as outfile:
        for line in infile:
            if filter_keyword in line:
                outfile.write(line)

def subdomain_enumeration(target):
    os.makedirs('subs', exist_ok=True)
    with open(f'subs/subs.{target}.tmp', 'w') as tmp_file:
        run_subfinder(target)
        run_assetfinder(target)
        run_httpx(target)

        try:
            crt_output = subprocess.run(
                ["curl", "-ks", f"https://crt.sh/?q={target}"],
                capture_output=True, text=True, timeout=10
            ).stdout
            crt_domains = re.findall(r'<TD>([^<]*\.' + re.escape(target) + r')</TD>', crt_output)
            with open(f'subs/subs.{target}.tmp', 'a') as tmp_file:
                tmp_file.writelines("\n".join(crt_domains) + "\n")
        except subprocess.TimeoutExpired:
            print("[!] Timeout reached for crt.sh command")

    with open(f'subs/subs.{target}.tmp') as tmp_file:
        unique_domains = set(filter(lambda x: '@' not in x, tmp_file))
    
    final_file_path = f'subs/subs.{target}'
    with open(final_file_path, 'w') as final_file:
        final_file.writelines(sorted(unique_domains))
        
    concatenate_sort_outputs(['subs/subs.' + target + '.tmp'], 'subs/subs.' + target)
    filter_output('subs/subs.' + target, 'subs/final_subs.' + target, filterkeyword) 

    print(f"\n[-] Total of subdomains found: {len(unique_domains)}")


def recon_hostname_fqdn(target):
    os.makedirs('infos', exist_ok=True)
    subs_file_path = f'subs/subs.{target}'
    if not os.path.exists(subs_file_path):
        print(f"[!] Subdomains file {subs_file_path} does not exist.")
        return


    with open(subs_file_path, 'r') as subs_file:
        for sub in subs_file:
            sub = sub.strip()
            run_tool_and_save_output(["whatweb", sub], f"infos/whatweb.{target}")
            run_tool_and_save_output(["wafw00f", sub], f"infos/wafw00f.{target}")
            run_tool_and_save_output(["httpx", "-sc", "-fr", "-cl", "-ct", "-location", "-favicon", "-jarm", "-rt", "-lc", "-wc", "-title", "-bp", "-server", "-td", "-method", "-websocket", "-ip", "-cname", "-asn", "-cdn", "-probe", sub], f"infos/httpx.{target}")
            run_tool_and_save_output(["cmseek", "-u", sub, "--follow-redirect", "-r"], f"infos/cmseek-result-cms.{target}")
            run_tool_and_save_output(["waybackurls", sub], f"infos/waybackurls.{target}")
            run_tool_and_save_output(["hakrawler", "-url", sub, "-depth", "3", "-plain"], f"infos/hakrawler.{target}")
            run_curl_and_process(sub, target)
            run_naabu(sub)
            run_asnmap(sub)
            run_tlsx(sub)
            run_gospider(sub)
            run_wapiti(sub)
            run_katana(sub)
            run_curl_regex(sub)
            
    try:
        curl_output = subprocess.run(
            ["curl", "-ks", f"{sub}"],
            capture_output=True, text=True, timeout=10
        ).stdout
        regex_matches = re.findall(r'(\/)((?:[a-zA-Z\-_\.0-9{}]+))(\/)*((?:[a-zA-Z\-_:\.0-9{}]+))(\/)((?:[a-zA-Z\-_\/:\.0-9{}]+))', curl_output)
        with open(f'infos/regexedAPI.{target}', 'w') as regex_file:
            for match in regex_matches:
                regex_file.write(''.join(match) + '\n')
    except subprocess.TimeoutExpired:
        print(f"[!] Timeout reached for curl on {sub}")
        
    output_files = [
        f'infos/whatweb.{target}',
        f'infos/wafw00f.{target}',
        f'infos/httpx.{target}',
        f'infos/cmseek-result-cms.{target}',
        f'infos/waybackurls.{target}',
        f'infos/hakrawler.{target}',
        f'infos/regexedAPI.{target}',
        f'infos/ports-subs.{target}',
        f'infos/tlsx.{target}',
        f'infos/gospider.{target}',
        f'infos/wapiti.{target}',
        f'infos/katana.{target}'
    ]
    
    
    concatenate_sort_outputs(output_files, f'infos/combined.{target}')
    filter_output(f'infos/combined.{target}', f'infos/filtered.{target}', filterkeyword)  
    
        
def clean_up_directories():
    if os.path.exists('subdomains'):
        shutil.rmtree('subdomains')
    
    if os.path.exists('brute'):
        shutil.rmtree('brute')

    if os.path.exists('directorys'):
        shutil.rmtree('directorys')
  
def main():
    parser = argparse.ArgumentParser(description='Automated Pentesting Tool')
    parser.add_argument('target', nargs='?', help='The target domain for scanning')
    parser.add_argument('-mode', choices=['subdomain', 'recon', 'install', 'all'], help='Scan mode')

    args = parser.parse_args()

    if args.target is None and args.mode != 'install':
        parser.print_help()
        sys.exit()


    print(banner)

    if args.mode == 'install':
        print("[-] Installing Go")
        install_go()
        print("\n[-] Installing Tools")
        install_tools()
        print("\n[-] Installation was successful")
        sys.exit()
    elif args.mode in ['subdomain', 'all']:
        print("\n[-] Scanning for subdomains\n")
        subdomain_enumeration(args.target)
        sys.exit()
    if args.mode in ['recon', 'all']:
        print("\n[-] Performing Recon")
        recon_hostname_fqdn(args.target)
        sys.exit()



if __name__ == "__main__":
    main()
