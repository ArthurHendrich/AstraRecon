import requests
import json
import sys
import sqlite3

DATABASE = 'results.db'

def crtsh(domain):
    subdomains = set()
    wildcardsubdomains = set()
    url = f"https://crt.sh/?q={domain}&output=json"
    print(f"[#] Fetching Subdomains from crt.sh for {domain}")

    try:
        response = requests.get(url, timeout=25)
        response.raise_for_status()
        content = response.content.decode('UTF-8')

        if content:
            try:
                jsondata = json.loads(content)
                for entry in jsondata:
                    name_value = entry.get('name_value', '')
                    if '\n' in name_value:
                        subname_value = name_value.split('\n')
                        for subname in subname_value:
                            subname = subname.strip()
                            if subname and '*' in subname:
                                wildcardsubdomains.add(subname)
                            elif subname:
                                subdomains.add(subname)
            except json.JSONDecodeError as e:
                print(f"[!] Error decoding JSON for domain {domain} from {url}")

    except requests.exceptions.RequestException as e:
        print(f"[!] Error fetching subdomains for domain {domain} from {url}")

    return subdomains, wildcardsubdomains

def save_results(domain, subdomains, wildcardsubdomains):
    with sqlite3.connect(DATABASE) as conn:
        c = conn.cursor()
        for subdomain in subdomains:
            c.execute('INSERT INTO crtsh_results (domain, subdomain) VALUES (?, ?)', (domain, subdomain))
        for wildcard in wildcardsubdomains:
            c.execute('INSERT INTO crtsh_results (domain, subdomain) VALUES (?, ?)', (domain, wildcard))
        conn.commit()

if __name__ == "__main__":
    domain = sys.argv[1]
    subdomains, wildcardsubdomains = crtsh(domain)
    save_results(domain, subdomains, wildcardsubdomains)
    for subdomain in subdomains:
        print(subdomain)
    for wildcard in wildcardsubdomains:
        print(wildcard)
