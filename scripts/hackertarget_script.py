import requests
import sys

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

if __name__ == "__main__":
    domain = sys.argv[1]
    subdomains = hackertarget(domain)
    for subdomain in subdomains:
        print(subdomain)
