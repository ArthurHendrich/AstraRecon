import requests
import sys

def urlscan(domain):
    url = f"https://urlscan.io/api/v1/search/?q={domain}"
    print(f"[#] Fetching Subdomains from urlscan.io for {domain}")

    try:
        response = requests.get(url)
        response.raise_for_status()
        data = response.json()

        if "results" in data:
            subdomains = [entry["domain"] for entry in data["results"] if "domain" in entry]
            return subdomains
        else:
            print("[X] No subdomains found.")
            return []

    except requests.exceptions.RequestException as e:
        print(f"[!] Error fetching data from {url}: {e}")
        return []

if __name__ == "__main__":
    domain = sys.argv[1]
    subdomains = urlscan(domain)
    for subdomain in subdomains:
        print(subdomain)
