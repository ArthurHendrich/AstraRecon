import requests
import sys

def virus_total(domain, api_key):
    url = f"https://www.virustotal.com/api/v3/domains/{domain}"
    headers = {"x-apikey": api_key}
    print(f"[#] Fetching Subdomains from VirusTotal for {domain}")

    try:
        response = requests.get(url, headers=headers)
        response.raise_for_status()
        data = response.json()

        subdomains = [subdomain['name'] for subdomain in data['data']['attributes']['subdomains']]
        return subdomains

    except requests.exceptions.RequestException as e:
        print(f"[!] Error fetching data from {url}: {e}")
        return []

if __name__ == "__main__":
    domain = sys.argv[1]
    api_key = sys.argv[2]
    subdomains = virus_total(domain, api_key)
    for subdomain in subdomains:
        print(subdomain)
