import requests
import sys
import sqlite3
import logging
from typing import List, Optional
from requests.exceptions import RequestException, Timeout, TooManyRedirects
from bs4 import BeautifulSoup

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
    return logging.getLogger('rapiddns')

def rapiddns(domain: str) -> List[str]:
    logger = setup_logging()
    url = f"https://rapiddns.io/subdomain/{domain}"
    logger.info(f"Starting RapidDNS scan for {domain}")
    
    try:
        # Add custom headers to mimic browser behavior
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Connection': 'keep-alive',
        }
        
        response = requests.get(url, headers=headers, timeout=30)
        response.raise_for_status()
        
        if response.status_code == 200:
            soup = BeautifulSoup(response.text, 'html.parser')
            table = soup.find('table', {'class': 'table'})
            
            if not table:
                logger.warning(f"No results table found for {domain}")
                return []

            subdomains = set()
            rows = table.find_all('tr')
            
            for row in rows[1:]:  # Skip header row
                cols = row.find_all('td')
                if cols and len(cols) > 0:
                    subdomain = cols[0].text.strip().lower()
                    if subdomain and subdomain.endswith(domain):
                        subdomains.add(subdomain)

            logger.info(f"Found {len(subdomains)} subdomains for {domain}")
            return list(subdomains)
        else:
            logger.error(f"Unexpected status code {response.status_code} from RapidDNS")
            return []

    except Timeout:
        logger.error(f"Timeout while fetching data from RapidDNS for {domain}")
    except TooManyRedirects:
        logger.error(f"Too many redirects while accessing RapidDNS for {domain}")
    except RequestException as e:
        if hasattr(e.response, 'status_code'):
            if e.response.status_code == 429:
                logger.error("RapidDNS rate limit exceeded")
            else:
                logger.error(f"Request failed with status code {e.response.status_code}")
        else:
            logger.error(f"Request failed for {domain}: {str(e)}")
    except Exception as e:
        logger.error(f"Unexpected error during RapidDNS scan for {domain}: {str(e)}")
    
    return []

def save_results(domain: str, subdomains: List[str]) -> None:
    logger = setup_logging()
    try:
        with sqlite3.connect(DATABASE) as conn:
            c = conn.cursor()
            c.execute('CREATE TABLE IF NOT EXISTS rapiddns_results (domain TEXT, subdomain TEXT, UNIQUE(domain, subdomain))')
            for subdomain in subdomains:
                try:
                    c.execute('INSERT OR IGNORE INTO rapiddns_results (domain, subdomain) VALUES (?, ?)', 
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
        print("Usage: python3 rapiddns_script.py <domain>")
        sys.exit(1)
    
    domain = sys.argv[1].lower()
    subdomains = rapiddns(domain)
    save_results(domain, subdomains)
    for subdomain in sorted(subdomains):
        print(subdomain)
