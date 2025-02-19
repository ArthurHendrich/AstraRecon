import requests
import sys
import sqlite3
import logging
from typing import List, Optional
from requests.exceptions import RequestException, Timeout, TooManyRedirects

DATABASE = 'results.db'

def setup_logging():
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler('recon.log'),
            logging.StreamHandler()
        ]
    )
    return logging.getLogger('alienvault')

def alienvault(domain: str) -> List[str]:
    logger = setup_logging()
    url = f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns"
    logger.info(f"Starting AlienVault scan for {domain}")
    
    try:
        response = requests.get(url, timeout=30)
        response.raise_for_status()
        
        data = response.json()
        if not isinstance(data, dict):
            logger.error(f"Unexpected response format from AlienVault for {domain}")
            return []

        if "passive_dns" not in data:
            logger.warning(f"No passive DNS data found for {domain}")
            return []

        subdomains = []
        for entry in data["passive_dns"]:
            if isinstance(entry, dict) and "hostname" in entry:
                hostname = entry["hostname"].strip().lower()
                if hostname and hostname.endswith(domain):
                    subdomains.append(hostname)

        logger.info(f"Found {len(subdomains)} subdomains for {domain}")
        return list(set(subdomains))

    except Timeout:
        logger.error(f"Timeout while fetching data from AlienVault for {domain}")
    except TooManyRedirects:
        logger.error(f"Too many redirects while accessing AlienVault for {domain}")
    except RequestException as e:
        logger.error(f"Request failed for {domain}: {str(e)}")
    except ValueError as e:
        logger.error(f"JSON parsing failed for {domain}: {str(e)}")
    except Exception as e:
        logger.error(f"Unexpected error during AlienVault scan for {domain}: {str(e)}")
    
    return []

def save_results(domain: str, subdomains: List[str]) -> None:
    logger = setup_logging()
    try:
        with sqlite3.connect(DATABASE) as conn:
            c = conn.cursor()
            c.execute('CREATE TABLE IF NOT EXISTS alienvault_results (domain TEXT, subdomain TEXT, UNIQUE(domain, subdomain))')
            for subdomain in subdomains:
                try:
                    c.execute('INSERT OR IGNORE INTO alienvault_results (domain, subdomain) VALUES (?, ?)', 
                            (domain, subdomain))
                except sqlite3.Error as e:
                    logger.error(f"Error inserting subdomain {subdomain}: {str(e)}")
            conn.commit()
    except sqlite3.Error as e:
        logger.error(f"Database error: {str(e)}")
    except Exception as e:
        logger.error(f"Unexpected error while saving results: {str(e)}")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python3 alienvault_script.py <domain>")
        sys.exit(1)
    
    domain = sys.argv[1].lower()
    subdomains = alienvault(domain)
    save_results(domain, subdomains)
    for subdomain in sorted(subdomains):
        print(subdomain)
