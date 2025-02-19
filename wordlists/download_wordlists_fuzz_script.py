import requests
from concurrent.futures import ThreadPoolExecutor
import sqlite3

DATABASE = 'results.db'

def download_link(url):
    filename = url.split("/")[-1]
    print(f"Downloading {filename}...")
    response = requests.get(url, stream=True, verify=False)
    content = response.content.decode('utf-8')
    with sqlite3.connect(DATABASE) as conn:
        c = conn.cursor()
        c.execute('INSERT INTO fuzz_wordlists (filename, content) VALUES (?, ?)', (filename, content))
        conn.commit()
    print(f"Downloaded {filename}.")

def download_wordlists_fuzz():
    wordlists = {
        "https://raw.githubusercontent.com/danTaler/WordLists/master/Subdomain.txt",
        "https://raw.githubusercontent.com/theMiddleBlue/DNSenum/master/wordlist/subdomains-top1mil-20000.txt"
    }

    with ThreadPoolExecutor(max_workers=10) as executor:
        executor.map(download_link, wordlists)

if __name__ == "__main__":
    download_wordlists_fuzz()
