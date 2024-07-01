import requests
import sys
import sqlite3

DATABASE = 'results.db'

def hackertarget(domain):
    url = f"https://api.hackertarget.com/hostsearch/?q={domain}"
    print(f"[#] Fetching Subdomains from hackertarget.com for {domain}")

    try:
        response = requests.get(url)
        response.raise_for_status()
        data = response.text

        if data:
            subdomains = [line.split(",")[0] for line in data.splitlines()]
            return subdomains
        else:
            print("[X] No subdomains Found")
            return []

    except requests.exceptions.RequestException as e:
        print(f"[!] Error fetching data from {url}: {e}")
        return []

def save_results(domain, subdomains):
    with sqlite3.connect(DATABASE) as conn:
        c = conn.cursor()
        for subdomain in subdomains:
            c.execute('INSERT INTO hackertarget_results (domain, subdomain) VALUES (?, ?)', (domain, subdomain))
        conn.commit()

if __name__ == "__main__":
    domain = sys.argv[1]
    subdomains = hackertarget(domain)
    save_results(domain, subdomains)
    for subdomain in subdomains:
        print(subdomain)
