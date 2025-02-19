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
    return logging.getLogger('anubis')

def anubis(domain: str) -> List[str]:
    logger = setup_logging()
    url = f"https://jldc.me/anubis/subdomains/{domain}"
    logger.info(f"Starting Anubis scan for {domain}")
    
    try:
        response = requests.get(url, timeout=30)
        response.raise_for_status()
        
        subdomains = response.json()
        if not isinstance(subdomains, list):
            logger.error(f"Unexpected response format from Anubis for {domain}")
            return []

        # Filter and clean subdomains
        valid_subdomains = []
        for subdomain in subdomains:
            if isinstance(subdomain, str):
                subdomain = subdomain.strip().lower()
                if subdomain and subdomain.endswith(domain):
                    valid_subdomains.append(subdomain)

        logger.info(f"Found {len(valid_subdomains)} subdomains for {domain}")
        return list(set(valid_subdomains))

    except Timeout:
        logger.error(f"Timeout while fetching data from Anubis for {domain}")
    except TooManyRedirects:
        logger.error(f"Too many redirects while accessing Anubis for {domain}")
    except RequestException as e:
        logger.error(f"Request failed for {domain}: {str(e)}")
    except ValueError as e:
        logger.error(f"JSON parsing failed for {domain}: {str(e)}")
    except Exception as e:
        logger.error(f"Unexpected error during Anubis scan for {domain}: {str(e)}")
    
    return []

def save_results(domain: str, subdomains: List[str]) -> None:
    logger = setup_logging()
    try:
        with sqlite3.connect(DATABASE) as conn:
            c = conn.cursor()
            c.execute('CREATE TABLE IF NOT EXISTS anubis_results (domain TEXT, subdomain TEXT, UNIQUE(domain, subdomain))')
            for subdomain in subdomains:
                try:
                    c.execute('INSERT OR IGNORE INTO anubis_results (domain, subdomain) VALUES (?, ?)', 
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
        print("Usage: python3 anubis_script.py <domain>")
        sys.exit(1)
    
    domain = sys.argv[1].lower()
    subdomains = anubis(domain)
    save_results(domain, subdomains)
    for subdomain in sorted(subdomains):
        print(subdomain)
