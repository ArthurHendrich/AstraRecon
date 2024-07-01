import requests
import sys
import sqlite3

DATABASE = 'results.db'

def urlscan(domain):
    url = f"https://urlscan.io/api/v1/search/?q={domain}"
    print(f"[#] Fetching Subdomains from urlscan.io for {domain}")

    try:
        response = requests.get(url)
        response.raise_for_status()
        data = response.json()

        if "results" in data:
            subdomains = [entry["domain"] for entry in data["results"] if "domain" in entry]
            return subdomains
        else:
            print("[X] No subdomains found.")
            return []

    except requests.exceptions.RequestException as e:
        print(f"[!] Error fetching data from {url}: {e}")
        return []

def save_results(domain, subdomains):
    with sqlite3.connect(DATABASE) as conn:
        c = conn.cursor()
        for subdomain in subdomains:
            c.execute('INSERT INTO urlscan_results (domain, subdomain) VALUES (?, ?)', (domain, subdomain))
        conn.commit()

if __name__ == "__main__":
    domain = sys.argv[1]
    subdomains = urlscan(domain)
    save_results(domain, subdomains)
    for subdomain in subdomains:
        print(subdomain)
