import requests
import sys

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

if __name__ == "__main__":
    domain = sys.argv[1]
    api_key = sys.argv[2]
    subdomains = spyse(domain, api_key)
    for subdomain in subdomains:
        print(subdomain)
