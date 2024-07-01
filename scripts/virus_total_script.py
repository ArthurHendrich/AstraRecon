import requests
import sys
import sqlite3

DATABASE = 'results.db'

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

def save_results(domain, subdomains):
    with sqlite3.connect(DATABASE) as conn:
        c = conn.cursor()
        for subdomain in subdomains:
            c.execute('INSERT INTO virus_total_results (domain, subdomain) VALUES (?, ?)', (domain, subdomain))
        conn.commit()

if __name__ == "__main__":
    domain = sys.argv[1]
    api_key = sys.argv[2]
    subdomains = virus_total(domain, api_key)
    save_results(domain, subdomains)
    for subdomain in subdomains:
        print(subdomain)
