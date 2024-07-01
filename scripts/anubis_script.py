import requests
import sys
import sqlite3

DATABASE = 'results.db'

def anubis(domain):
    url = f"https://jldc.me/anubis/subdomains/{domain}"
    print(f"[#] Fetching Subdomains from anubis for {domain}")

    try:
        response = requests.get(url)
        response.raise_for_status()
        subdomains = response.json()

        if isinstance(subdomains, list):
            return subdomains
        else:
            print(f"Anubis response for {domain} is not in the expected format.")
            return []

    except requests.RequestException as e:
        print(f"[!] Error Getting subdomains from {url}: {e}")
        return []

def save_results(domain, subdomains):
    with sqlite3.connect(DATABASE) as conn:
        c = conn.cursor()
        for subdomain in subdomains:
            c.execute('INSERT INTO anubis_results (domain, subdomain) VALUES (?, ?)', (domain, subdomain))
        conn.commit()

if __name__ == "__main__":
    domain = sys.argv[1]
    subdomains = anubis(domain)
    save_results(domain, subdomains)
    for subdomain in subdomains:
        print(subdomain)
