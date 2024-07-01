import requests
import sys

def cert_spotter(domain):
    url = f"https://certspotter.com/api/v1/issuances?domain={domain}"
    print(f"[#] Fetching Subdomains from CertSpotter for {domain}")

    try:
        response = requests.get(url)
        response.raise_for_status()
        data = response.json()

        subdomains = [entry['name'] for entry in data['certificates']]
        return subdomains

    except requests.exceptions.RequestException as e:
        print(f"[!] Error fetching data from {url}: {e}")
        return []

if __name__ == "__main__":
    domain = sys.argv[1]
    subdomains = cert_spotter(domain)
    for subdomain in subdomains:
        print(subdomain)
