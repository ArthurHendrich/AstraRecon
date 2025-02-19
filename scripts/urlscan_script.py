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
    return logging.getLogger('urlscan')

def get_urlscan_api_key() -> Optional[str]:
    """Get URLScan API key from environment variable."""
    return os.getenv('URLSCAN_API_KEY')  # Optional, can be None

def urlscan(domain: str) -> List[str]:
    logger = setup_logging()
    logger.info(f"Starting URLScan scan for {domain}")
    
    try:
        api_key = get_urlscan_api_key()
        url = "https://urlscan.io/api/v1/search/"
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
        }
        
        if api_key:
            headers['API-Key'] = api_key
            logger.info("Using authenticated URLScan API access")
        else:
            logger.warning("Using unauthenticated URLScan API access - rate limits will be strict")
        
        params = {
            'q': f'domain:{domain}',
            'size': 100
        }
        
        subdomains = set()
        page = 0
        total_results = 0
        
        while True:
            # Add delay to respect rate limits
            if page > 0:
                time.sleep(3 if not api_key else 1)  # Longer delay for unauthenticated requests
            
            params['offset'] = page * 100
            response = requests.get(url, headers=headers, params=params, timeout=30)
            response.raise_for_status()
            
            data = response.json()
            if not isinstance(data, dict) or 'results' not in data:
                logger.error(f"Unexpected response format from URLScan for {domain}")
                break

            results = data['results']
            if not results:
                break

            for result in results:
                if isinstance(result, dict):
                    # Extract from page properties
                    if 'page' in result and isinstance(result['page'], dict):
                        page_domain = result['page'].get('domain', '').strip().lower()
                        if page_domain and page_domain.endswith(domain):
                            subdomains.add(page_domain)
                    
                    # Extract from task data
                    if 'task' in result and isinstance(result['task'], dict):
                        task_domain = result['task'].get('domain', '').strip().lower()
                        if task_domain and task_domain.endswith(domain):
                            subdomains.add(task_domain)

            total_results += len(results)
            
            # Check if we've reached the end of results
            if len(results) < 100 or total_results >= 10000:  # URLScan limit
                break
                
            page += 1

        logger.info(f"Found {len(subdomains)} subdomains for {domain}")
        return list(subdomains)

    except Timeout:
        logger.error(f"Timeout while fetching data from URLScan for {domain}")
    except TooManyRedirects:
        logger.error(f"Too many redirects while accessing URLScan for {domain}")
    except RequestException as e:
        if hasattr(e.response, 'status_code'):
            if e.response.status_code == 401:
                logger.error("Invalid URLScan API key")
            elif e.response.status_code == 429:
                logger.error("URLScan API rate limit exceeded")
            else:
                logger.error(f"Request failed with status code {e.response.status_code}")
        else:
            logger.error(f"Request failed for {domain}: {str(e)}")
    except Exception as e:
        logger.error(f"Unexpected error during URLScan scan for {domain}: {str(e)}")
    
    return []

def save_results(domain: str, subdomains: List[str]) -> None:
    logger = setup_logging()
    try:
        with sqlite3.connect(DATABASE) as conn:
            c = conn.cursor()
            c.execute('CREATE TABLE IF NOT EXISTS urlscan_results (domain TEXT, subdomain TEXT, UNIQUE(domain, subdomain))')
            for subdomain in subdomains:
                try:
                    c.execute('INSERT OR IGNORE INTO urlscan_results (domain, subdomain) VALUES (?, ?)', 
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
        print("Usage: python3 urlscan_script.py <domain>")
        sys.exit(1)
    
    domain = sys.argv[1].lower()
    subdomains = urlscan(domain)
    save_results(domain, subdomains)
    for subdomain in sorted(subdomains):
        print(subdomain)
