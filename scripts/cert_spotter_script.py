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
    return logging.getLogger('cert_spotter')

def get_certspotter_api_key() -> str:
    """Get CertSpotter API key from environment variable."""
    api_key = os.getenv('CERTSPOTTER_API_KEY')
    if not api_key:
        raise ValueError("CertSpotter API key not found in environment variables")
    return api_key

def cert_spotter(domain: str) -> List[str]:
    logger = setup_logging()
    logger.info(f"Starting CertSpotter scan for {domain}")
    
    try:
        api_key = get_certspotter_api_key()
        url = f"https://api.certspotter.com/v1/issuances"
        params = {
            "domain": domain,
            "include_subdomains": "true",
            "expand": "dns_names"
        }
        headers = {"Authorization": f"Bearer {api_key}"}
        
        response = requests.get(
            url,
            params=params,
            headers=headers,
            timeout=30
        )
        response.raise_for_status()
        
        data = response.json()
        if not isinstance(data, list):
            logger.error(f"Unexpected response format from CertSpotter for {domain}")
            return []

        subdomains = set()
        for cert in data:
            if isinstance(cert, dict) and "dns_names" in cert:
                for name in cert["dns_names"]:
                    name = name.strip().lower()
                    if name and name.endswith(domain):
                        subdomains.add(name)

        logger.info(f"Found {len(subdomains)} subdomains for {domain}")
        return list(subdomains)

    except ValueError as e:
        logger.error(f"API key error: {str(e)}")
    except Timeout:
        logger.error(f"Timeout while fetching data from CertSpotter for {domain}")
    except TooManyRedirects:
        logger.error(f"Too many redirects while accessing CertSpotter for {domain}")
    except RequestException as e:
        if e.response and e.response.status_code == 401:
            logger.error("Invalid CertSpotter API key")
        elif e.response and e.response.status_code == 429:
            logger.error("CertSpotter API rate limit exceeded")
        else:
            logger.error(f"Request failed for {domain}: {str(e)}")
    except Exception as e:
        logger.error(f"Unexpected error during CertSpotter scan for {domain}: {str(e)}")
    
    return []

def save_results(domain: str, subdomains: List[str]) -> None:
    logger = setup_logging()
    try:
        with sqlite3.connect(DATABASE) as conn:
            c = conn.cursor()
            c.execute('CREATE TABLE IF NOT EXISTS cert_spotter_results (domain TEXT, subdomain TEXT, UNIQUE(domain, subdomain))')
            for subdomain in subdomains:
                try:
                    c.execute('INSERT OR IGNORE INTO cert_spotter_results (domain, subdomain) VALUES (?, ?)', 
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
        print("Usage: python3 cert_spotter_script.py <domain>")
        sys.exit(1)
    
    domain = sys.argv[1].lower()
    subdomains = cert_spotter(domain)
    save_results(domain, subdomains)
    for subdomain in sorted(subdomains):
        print(subdomain)
