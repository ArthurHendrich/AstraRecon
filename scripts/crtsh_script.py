import requests
import sys
import sqlite3
import logging
from typing import List, Optional
from requests.exceptions import RequestException, Timeout, TooManyRedirects
import time
from bs4 import BeautifulSoup
import re

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
    return logging.getLogger('crtsh')

def scrape_crtsh_html(domain: str, logger) -> List[str]:
    """Fallback method using HTML scraping when JSON API fails."""
    url = f"https://crt.sh/?q=%.{domain}"
    
    try:
        response = requests.get(
            url,
            timeout=60,
            headers={
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8'
            }
        )
        response.raise_for_status()
        
        soup = BeautifulSoup(response.text, 'html.parser')
        subdomains = set()
        
        # Find the table with certificate information
        for td in soup.find_all('td'):
            if td.get('style') == 'text-align:center':
                continue
                
            text = td.get_text().strip().lower()
            if text and domain in text:
                # Split on newlines and common separators
                names = re.split(r'[\n\r\s,;]+', text)
                for name in names:
                    name = name.strip('*. ')
                    if name and name.endswith(domain):
                        subdomains.add(name)
        
        return list(subdomains)
        
    except Exception as e:
        logger.error(f"HTML scraping failed: {str(e)}")
        return []

def crtsh(domain: str) -> List[str]:
    logger = setup_logging()
    json_url = f"https://crt.sh/?q=%.{domain}&output=json"
    logger.info(f"Starting crt.sh scan for {domain}")
    
    try:
        # Try JSON API first
        session = requests.Session()
        response = session.get(
            json_url,
            timeout=60,
            headers={
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
                'Accept': 'application/json'
            }
        )
        response.raise_for_status()
        
        data = response.json()
        if not isinstance(data, list):
            raise ValueError("Invalid JSON response format")

        subdomains = set()
        for cert in data:
            if isinstance(cert, dict):
                # Extract from name_value field
                if 'name_value' in cert:
                    names = cert['name_value'].split('\n')
                    for name in names:
                        name = name.strip().lower()
                        if name and name.endswith(domain):
                            subdomains.add(name)
                
                # Extract from common_name field
                if 'common_name' in cert and cert['common_name']:
                    name = cert['common_name'].strip().lower()
                    if name and name.endswith(domain):
                        subdomains.add(name)

    except (Timeout, RequestException, ValueError) as e:
        logger.warning(f"JSON API failed, falling back to HTML scraping: {str(e)}")
        subdomains = set(scrape_crtsh_html(domain, logger))

    logger.info(f"Found {len(subdomains)} subdomains for {domain}")
    return list(subdomains)

def save_results(domain: str, subdomains: List[str]) -> None:
    logger = setup_logging()
    try:
        with sqlite3.connect(DATABASE) as conn:
            c = conn.cursor()
            c.execute('CREATE TABLE IF NOT EXISTS crtsh_results (domain TEXT, subdomain TEXT, UNIQUE(domain, subdomain))')
            for subdomain in subdomains:
                try:
                    c.execute('INSERT OR IGNORE INTO crtsh_results (domain, subdomain) VALUES (?, ?)', 
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
        print("Usage: python3 crtsh_script.py <domain>")
        sys.exit(1)
    
    domain = sys.argv[1].lower()
    subdomains = crtsh(domain)
    save_results(domain, subdomains)
    for subdomain in sorted(subdomains):
        print(subdomain)
