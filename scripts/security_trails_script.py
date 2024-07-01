import requests
import sys
import sqlite3

DATABASE = 'results.db'

def security_trails(domain, api_key):
    url = f"https://api.securitytrails.com/v1/domain/{domain}/subdomains"
    headers = {"Authorization": f"ApiKey {api_key}"}
    print(f"[#] Fetching Subdomains from SecurityTrails for {domain}")

    try:
        response = requests.get(url, headers=headers)
        response.raise_for_status()
        data = response.json()

        subdomains = [subdomain for subdomain in data['subdomains']]
        return subdomains

    except requests.exceptions.RequestException as e:
        print(f"[!] Error fetching data from {url}: {e}")
        return []

def save_results(domain, subdomains):
    with sqlite3.connect(DATABASE) as conn:
        c = conn.cursor()
        for subdomain in subdomains:
            c.execute('INSERT INTO security_trails_results (domain, subdomain) VALUES (?, ?)', (domain, subdomain))
        conn.commit()

if __name__ == "__main__":
    domain = sys.argv[1]
    api_key = sys.argv[2]
    subdomains = security_trails(domain, api_key)
    save_results(domain, subdomains)
    for subdomain in subdomains:
        print(subdomain)
