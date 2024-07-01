import requests
import json
import sys
import re

def crtsh(domain):
    subdomains = set()
    wildcardsubdomains = set()
    url = f"https://crt.sh/?q={domain}&output=json"
    print(f"[#] Fetching Subdomains from crt.sh for {domain}")

    try:
        response = requests.get(url, timeout=25)
        response.raise_for_status()  # Raise an HTTPError for bad responses
        content = response.content.decode('UTF-8')

        if content:
            try:
                jsondata = json.loads(content)
                for entry in jsondata:
                    name_value = entry.get('name_value', '')
                    if '\n' in name_value:
                        subname_value = name_value.split('\n')
                        for subname in subname_value:
                            subname = subname.strip()  # Remove leading/trailing spaces
                            if subname and '*' in subname:
                                wildcardsubdomains.add(subname)
                            elif subname:
                                subdomains.add(subname)
            except json.JSONDecodeError as e:
                print(f"[!] Error decoding JSON for domain {domain} from {url}")

    except requests.exceptions.RequestException as e:
        print(f"[!] Error fetching subdomains for domain {domain} from {url}")

    return subdomains, wildcardsubdomains

if __name__ == "__main__":
    domain = sys.argv[1]
    subdomains, wildcardsubdomains = crtsh(domain)
    for subdomain in subdomains:
        print(subdomain)
    for wildcard in wildcardsubdomains:
        print(wildcard)
