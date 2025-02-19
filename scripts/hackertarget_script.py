import requests
import sys
import sqlite3
import logging
import time
from typing import List, Optional
from requests.exceptions import RequestException, Timeout, TooManyRedirects

DATABASE = 'results.db'
RATE_LIMIT_DELAY = 5  # HackerTarget has strict rate limits

def setup_logging():
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler('recon.log'),
            logging.StreamHandler()
        ]
    )
    return logging.getLogger('hackertarget')

def hackertarget(domain: str) -> List[str]:
    logger = setup_logging()
    url = f"https://api.hackertarget.com/hostsearch/?q={domain}"
    logger.info(f"Starting HackerTarget scan for {domain}")
    
    try:
        # Add delay to respect rate limits
        time.sleep(RATE_LIMIT_DELAY)
        
        response = requests.get(url, timeout=30)
        response.raise_for_status()
        
        content = response.text
        if "error" in content.lower() or "api count exceeded" in content.lower():
            logger.error(f"API limit exceeded or error in response: {content}")
            return []
            
        if not content or content.strip() == "":
            logger.warning(f"No results found for {domain}")
            return []

        subdomains = set()
        for line in content.split('\n'):
            if ',' in line:  # HackerTarget returns "hostname,ip" format
                hostname = line.split(',')[0].strip().lower()
                if hostname and hostname.endswith(domain):
                    subdomains.add(hostname)

        logger.info(f"Found {len(subdomains)} subdomains for {domain}")
        return list(subdomains)

    except Timeout:
        logger.error(f"Timeout while fetching data from HackerTarget for {domain}")
    except TooManyRedirects:
        logger.error(f"Too many redirects while accessing HackerTarget for {domain}")
    except RequestException as e:
        if hasattr(e.response, 'status_code'):
            if e.response.status_code == 429:
                logger.error("HackerTarget API rate limit exceeded")
            else:
                logger.error(f"Request failed with status code {e.response.status_code}")
        else:
            logger.error(f"Request failed for {domain}: {str(e)}")
    except Exception as e:
        logger.error(f"Unexpected error during HackerTarget scan for {domain}: {str(e)}")
    
    return []

def save_results(domain: str, subdomains: List[str]) -> None:
    logger = setup_logging()
    try:
        with sqlite3.connect(DATABASE) as conn:
            c = conn.cursor()
            c.execute('CREATE TABLE IF NOT EXISTS hackertarget_results (domain TEXT, subdomain TEXT, UNIQUE(domain, subdomain))')
            for subdomain in subdomains:
                try:
                    c.execute('INSERT OR IGNORE INTO hackertarget_results (domain, subdomain) VALUES (?, ?)', 
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
        print("Usage: python3 hackertarget_script.py <domain>")
        sys.exit(1)
    
    domain = sys.argv[1].lower()
    subdomains = hackertarget(domain)
    save_results(domain, subdomains)
    for subdomain in sorted(subdomains):
        print(subdomain)
