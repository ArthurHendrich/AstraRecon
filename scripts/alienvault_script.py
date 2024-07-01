import requests
import sys
import sqlite3

DATABASE = 'results.db'

def alienvault(domain):
    url = f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns"
    print(f"[#] Fetching Subdomains from otx.alienvault.com for {domain}")

    try:
        response = requests.get(url)
        response.raise_for_status()  # Check for HTTP errors

        data = response.json()

        if "passive_dns" in data:
            subdomains = [entry["hostname"] for entry in data["passive_dns"] if "hostname" in entry]
            return subdomains
        else:
            print("[X] No passive DNS data found.")
            return []

    except requests.exceptions.RequestException as e:
        print(f"[!] Error fetching data from {url}: {e}")
        return []

def save_results(domain, subdomains):
    with sqlite3.connect(DATABASE) as conn:
        c = conn.cursor()
        for subdomain in subdomains:
            c.execute('INSERT INTO alienvault_results (domain, subdomain) VALUES (?, ?)', (domain, subdomain))
        conn.commit()

if __name__ == "__main__":
    domain = sys.argv[1]
    subdomains = alienvault(domain)
    save_results(domain, subdomains)
    for subdomain in subdomains:
        print(subdomain)
