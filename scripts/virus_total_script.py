import requests
import sys
import sqlite3
import logging
import os
import time
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
    return logging.getLogger('virus_total')

def get_virustotal_api_key() -> str:
    """Get VirusTotal API key from environment variable."""
    api_key = os.getenv('VIRUSTOTAL_API_KEY')
    if not api_key:
        raise ValueError("VirusTotal API key not found in environment variables")
    return api_key

def virus_total(domain: str) -> List[str]:
    logger = setup_logging()
    logger.info(f"Starting VirusTotal scan for {domain}")
    
    try:
        api_key = get_virustotal_api_key()
        url = f"https://www.virustotal.com/vtapi/v2/domain/report"
        params = {
            'apikey': api_key,
            'domain': domain
        }
        
        response = requests.get(url, params=params, timeout=30)
        response.raise_for_status()
        
        data = response.json()
        if not isinstance(data, dict):
            logger.error(f"Unexpected response format from VirusTotal for {domain}")
            return []

        subdomains = set()
        
        # Extract subdomains from different sections
        if 'subdomains' in data:
            for subdomain in data['subdomains']:
                if isinstance(subdomain, str):
                    subdomain = subdomain.strip().lower()
                    if subdomain and subdomain.endswith(domain):
                        subdomains.add(subdomain)
        
        # Check for undetected subdomains
        if 'undetected_subdomains' in data:
            for subdomain in data['undetected_subdomains']:
                if isinstance(subdomain, str):
                    subdomain = subdomain.strip().lower()
                    if subdomain and subdomain.endswith(domain):
                        subdomains.add(subdomain)
        
        # Check for detected subdomains
        if 'detected_subdomains' in data:
            for subdomain in data['detected_subdomains']:
                if isinstance(subdomain, str):
                    subdomain = subdomain.strip().lower()
                    if subdomain and subdomain.endswith(domain):
                        subdomains.add(subdomain)

        logger.info(f"Found {len(subdomains)} subdomains for {domain}")
        return list(subdomains)

    except ValueError as e:
        logger.error(f"API key error: {str(e)}")
    except Timeout:
        logger.error(f"Timeout while fetching data from VirusTotal for {domain}")
    except TooManyRedirects:
        logger.error(f"Too many redirects while accessing VirusTotal for {domain}")
    except RequestException as e:
        if hasattr(e.response, 'status_code'):
            if e.response.status_code == 401:
                logger.error("Invalid VirusTotal API key")
            elif e.response.status_code == 429:
                logger.error("VirusTotal API rate limit exceeded")
            elif e.response.status_code == 403:
                logger.error("VirusTotal API access forbidden - check your plan limits")
            else:
                logger.error(f"Request failed with status code {e.response.status_code}")
        else:
            logger.error(f"Request failed for {domain}: {str(e)}")
    except Exception as e:
        logger.error(f"Unexpected error during VirusTotal scan for {domain}: {str(e)}")
    
    return []

def save_results(domain: str, subdomains: List[str]) -> None:
    logger = setup_logging()
    try:
        with sqlite3.connect(DATABASE) as conn:
            c = conn.cursor()
            c.execute('CREATE TABLE IF NOT EXISTS virus_total_results (domain TEXT, subdomain TEXT, UNIQUE(domain, subdomain))')
            for subdomain in subdomains:
                try:
                    c.execute('INSERT OR IGNORE INTO virus_total_results (domain, subdomain) VALUES (?, ?)', 
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
        print("Usage: python3 virus_total_script.py <domain>")
        sys.exit(1)
    
    domain = sys.argv[1].lower()
    subdomains = virus_total(domain)
    save_results(domain, subdomains)
    for subdomain in sorted(subdomains):
        print(subdomain)
