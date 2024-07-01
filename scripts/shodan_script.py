import requests
import sys
import sqlite3

DATABASE = 'results.db'

def shodan(domain, api_key):
    url = f"https://api.shodan.io/shodan/host/search?query=hostname:{domain}&key={api_key}"
    print(f"[#] Fetching Subdomains from Shodan for {domain}")

    try:
        response = requests.get(url)
        response.raise_for_status()
        data = response.json()

        subdomains = [result['hostnames'][0] for result in data['matches'] if 'hostnames' in result]
        return subdomains

    except requests.exceptions.RequestException as e:
        print(f"[!] Error fetching data from {url}: {e}")
        return []

def save_results(domain, subdomains):
    with sqlite3.connect(DATABASE) as conn:
        c = conn.cursor()
        for subdomain in subdomains:
            c.execute('INSERT INTO shodan_results (domain, subdomain) VALUES (?, ?)', (domain, subdomain))
        conn.commit()

if __name__ == "__main__":
    domain = sys.argv[1]
    api_key = sys.argv[2]
    subdomains = shodan(domain, api_key)
    save_results(domain, subdomains)
    for subdomain in subdomains:
        print(subdomain)
