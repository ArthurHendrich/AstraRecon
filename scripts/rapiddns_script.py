import requests
import sys
from bs4 import BeautifulSoup

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

if __name__ == "__main__":
    domain = sys.argv[1]
    subdomains = rapiddns(domain)
    for subdomain in subdomains:
        print(subdomain)
