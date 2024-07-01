import requests
import sys
import sqlite3
from bs4 import BeautifulSoup

DATABASE = 'results.db'

def rapiddns(domain):
    url = f"https://rapiddns.io/subdomain/{domain}?full=1#result"
    print(f"[#] Fetching Subdomains from rapiddns.io for {domain}")

    try:
        page = requests.get(url, verify=False)
        soup = BeautifulSoup(page.text, 'lxml')

        subdomains = []
        website_table = soup.find("table", {"class": "table table-striped table-bordered"})
        website_table_items = website_table.find_all('tbody')
        for tbody in website_table_items:
            tr = tbody.find_all('tr')
            for td in tr:
                subdomain = td.find_all('td')[0].text.strip()
                subdomains.append(subdomain)

        return subdomains

    except requests.RequestException as e:
        print(f"[!] Error Getting subdomains from {url}: {e}")
        return []

def save_results(domain, subdomains):
    with sqlite3.connect(DATABASE) as conn:
        c = conn.cursor()
        for subdomain in subdomains:
            c.execute('INSERT INTO rapiddns_results (domain, subdomain) VALUES (?, ?)', (domain, subdomain))
        conn.commit()

if __name__ == "__main__":
    domain = sys.argv[1]
    subdomains = rapiddns(domain)
    save_results(domain, subdomains)
    for subdomain in subdomains:
        print(subdomain)
