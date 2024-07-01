import requests
import sys
import sqlite3

DATABASE = 'results.db'

def spyse(domain, api_key):
    url = f"https://api.spyse.com/v4/data/domain/subdomains?domain={domain}&apikey={api_key}"
    print(f"[#] Fetching Subdomains from Spyse for {domain}")

    try:
        response = requests.get(url)
        response.raise_for_status()
        data = response.json()

        subdomains = [item['domain'] for item in data['data']]
        return subdomains

    except requests.exceptions.RequestException as e:
        print(f"[!] Error fetching data from {url}: {e}")
        return []

def save_results(domain, subdomains):
    with sqlite3.connect(DATABASE) as conn:
        c = conn.cursor()
        for subdomain in subdomains:
            c.execute('INSERT INTO spyse_results (domain, subdomain) VALUES (?, ?)', (domain, subdomain))
        conn.commit()

if __name__ == "__main__":
    domain = sys.argv[1]
    api_key = sys.argv[2]
    subdomains = spyse(domain, api_key)
    save_results(domain, subdomains)
    for subdomain in subdomains:
        print(subdomain)
