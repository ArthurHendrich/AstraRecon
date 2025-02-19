import requests
import sys
import sqlite3
import logging
from typing import List, Optional
from requests.exceptions import RequestException, Timeout, TooManyRedirects
from bs4 import BeautifulSoup
import time
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
    return logging.getLogger('censys')

def censys(domain: str) -> List[str]:
    logger = setup_logging()
    logger.info(f"Starting Censys web scraping for {domain}")
    
    try:
        base_url = "https://search.censys.io/search"
        params = {
            'resource': 'hosts',
            'sort': 'RELEVANCE',
            'per_page': '100',
            'virtual_hosts': 'EXCLUDE',
            'q': domain
        }
        
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Connection': 'keep-alive',
        }

        subdomains = set()
        page = 1
        
        while True:
            params['page'] = page
            logger.info(f"Scraping page {page}")
            
            try:
                response = requests.get(base_url, params=params, headers=headers, timeout=30)
                response.raise_for_status()
                
                soup = BeautifulSoup(response.text, 'html.parser')
                
                # Find all result items
                results = soup.find_all('div', class_='SearchResult')
                
                if not results:
                    logger.info("No more results found")
                    break
                
                # Extract subdomains from each result
                for result in results:
                    # Look for hostnames in the result text
                    hostname_elements = result.find_all(string=re.compile(f'.*{domain}.*'))
                    
                    for element in hostname_elements:
                        text = element.strip().lower()
                        # Use regex to find potential subdomains
                        matches = re.findall(rf'([a-zA-Z0-9-_.]+\.{domain})', text)
                        subdomains.update(matches)
                
                # Check if there's a next page
                next_button = soup.find('a', string='Next »')
                if not next_button:
                    logger.info("Reached last page")
                    break
                
                page += 1
                # Add delay between pages to avoid rate limiting
                time.sleep(2)
                
            except Exception as e:
                logger.error(f"Error processing page {page}: {str(e)}")
                break

        logger.info(f"Found {len(subdomains)} subdomains for {domain}")
        return list(subdomains)

    except Timeout:
        logger.error(f"Timeout while scraping Censys for {domain}")
    except TooManyRedirects:
        logger.error(f"Too many redirects while accessing Censys for {domain}")
    except RequestException as e:
        if hasattr(e.response, 'status_code'):
            if e.response.status_code == 429:
                logger.error("Rate limit exceeded")
            else:
                logger.error(f"Request failed with status code {e.response.status_code}")
        else:
            logger.error(f"Request failed for {domain}: {str(e)}")
    except Exception as e:
        logger.error(f"Unexpected error during Censys scraping for {domain}: {str(e)}")
    
    return []

def save_results(domain: str, subdomains: List[str]) -> None:
    logger = setup_logging()
    try:
        with sqlite3.connect(DATABASE) as conn:
            c = conn.cursor()
            c.execute('CREATE TABLE IF NOT EXISTS censys_results (domain TEXT, subdomain TEXT, UNIQUE(domain, subdomain))')
            for subdomain in subdomains:
                try:
                    c.execute('INSERT OR IGNORE INTO censys_results (domain, subdomain) VALUES (?, ?)', 
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
        print("Usage: python3 censys_script.py <domain>")
        sys.exit(1)
    
    domain = sys.argv[1].lower()
    subdomains = censys(domain)
    save_results(domain, subdomains)
    for subdomain in sorted(subdomains):
        print(subdomain)
