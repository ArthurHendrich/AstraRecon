import requests
import sys

def censys(domain, api_id, api_secret):
    url = f"https://search.censys.io/api/v2/subdomains?q={domain}"
    auth = (api_id, api_secret)
    print(f"[#] Fetching Subdomains from Censys for {domain}")

    try:
        response = requests.get(url, auth=auth)
        response.raise_for_status()
        data = response.json()

        subdomains = [result['name'] for result in data['results']]
        return subdomains

    except requests.exceptions.RequestException as e:
        print(f"[!] Error fetching data from {url}: {e}")
        return []

if __name__ == "__main__":
    domain = sys.argv[1]
    api_id = sys.argv[2]
    api_secret = sys.argv[3]
    subdomains = censys(domain, api_id, api_secret)
    for subdomain in subdomains:
        print(subdomain)
