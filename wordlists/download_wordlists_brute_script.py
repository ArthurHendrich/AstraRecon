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
        c.execute('INSERT INTO brute_wordlists (filename, content) VALUES (?, ?)', (filename, content))
        conn.commit()
    print(f"Downloaded {filename}.")

def download_wordlists_brute():
    wordlists = {
        "https://raw.githubusercontent.com/Karanxa/Bug-Bounty-Wordlists/main/api.txt",
        "https://raw.githubusercontent.com/Karanxa/Bug-Bounty-Wordlists/main/all-files-leaked.txt",
        "https://raw.githubusercontent.com/Karanxa/Bug-Bounty-Wordlists/main/cgi-bin.txt",
        "https://raw.githubusercontent.com/Karanxa/Bug-Bounty-Wordlists/main/cgi-files.txt",
        "https://raw.githubusercontent.com/Karanxa/Bug-Bounty-Wordlists/main/dotfiles.txt",  
        "https://raw.githubusercontent.com/Karanxa/Bug-Bounty-Wordlists/main/git_config.txt"
    }

    with ThreadPoolExecutor(max_workers=10) as executor:
        executor.map(download_link, wordlists)

if __name__ == "__main__":
    download_wordlists_brute()
