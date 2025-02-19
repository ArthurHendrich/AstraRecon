import requests
import sys
import sqlite3
import logging
import os
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
    return logging.getLogger('security_trails')

def get_securitytrails_api_key() -> str:
    """Get SecurityTrails API key from environment variable."""
    api_key = os.getenv('SECURITY_TRAILS_API_KEY')
    if not api_key:
        raise ValueError("SecurityTrails API key not found in environment variables")
    return api_key

def security_trails(domain: str) -> List[str]:
    logger = setup_logging()
    logger.info(f"Starting SecurityTrails scan for {domain}")
    
    try:
        api_key = get_securitytrails_api_key()
        url = f"https://api.securitytrails.com/v1/domain/{domain}/subdomains"
        headers = {
            'APIKEY': api_key,
            'Accept': 'application/json',
        }
        
        response = requests.get(url, headers=headers, timeout=30)
        response.raise_for_status()
        
        data = response.json()
        
        if not isinstance(data, dict) or 'subdomains' not in data:
            logger.error(f"Unexpected response format from SecurityTrails for {domain}")
            return []

        subdomains = set()
        for subdomain in data['subdomains']:
            if isinstance(subdomain, str):
                full_domain = f"{subdomain.strip()}.{domain}".lower()
                if full_domain.endswith(domain):
                    subdomains.add(full_domain)

        logger.info(f"Found {len(subdomains)} subdomains for {domain}")
        return list(subdomains)

    except ValueError as e:
        logger.error(f"API key error: {str(e)}")
    except Timeout:
        logger.error(f"Timeout while fetching data from SecurityTrails for {domain}")
    except TooManyRedirects:
        logger.error(f"Too many redirects while accessing SecurityTrails for {domain}")
    except RequestException as e:
        if hasattr(e.response, 'status_code'):
            if e.response.status_code == 401:
                logger.error("Invalid SecurityTrails API key")
            elif e.response.status_code == 429:
                logger.error("SecurityTrails API rate limit exceeded")
            else:
                logger.error(f"Request failed with status code {e.response.status_code}")
        else:
            logger.error(f"Request failed for {domain}: {str(e)}")
    except Exception as e:
        logger.error(f"Unexpected error during SecurityTrails scan for {domain}: {str(e)}")
    
    return []

def save_results(domain: str, subdomains: List[str]) -> None:
    logger = setup_logging()
    try:
        with sqlite3.connect(DATABASE) as conn:
            c = conn.cursor()
            c.execute('CREATE TABLE IF NOT EXISTS security_trails_results (domain TEXT, subdomain TEXT, UNIQUE(domain, subdomain))')
            for subdomain in subdomains:
                try:
                    c.execute('INSERT OR IGNORE INTO security_trails_results (domain, subdomain) VALUES (?, ?)', 
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
        print("Usage: python3 security_trails_script.py <domain>")
        sys.exit(1)
    
    domain = sys.argv[1].lower()
    subdomains = security_trails(domain)
    save_results(domain, subdomains)
    for subdomain in sorted(subdomains):
        print(subdomain)
