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
        c.execute('INSERT INTO directory_wordlists (filename, content) VALUES (?, ?)', (filename, content))
        conn.commit()
    print(f"Downloaded {filename}.")

def download_directory_wordlists():
    directory_wordlists = [
        "https://gist.githubusercontent.com/yassineaboukir/8e12adefbd505ef704674ad6ad48743d/raw/3ea2b7175f2fcf8e6de835c72cb2b2048f73f847/List%2520of%2520API%2520endpoints%2520&%2520objects",
        "https://gist.githubusercontent.com/helcaraxeals/7c45201b1c957ecea82ef7800da4bfa4/raw/b84a7364f33f2eb14aad68149302077649d70acc/api_wordlist.txt",
        "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/common-api-endpoints-mazen160.txt",
        "https://raw.githubusercontent.com/Karanxa/Bug-Bounty-Wordlists/main/api.txt",
        "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/directory-list-2.3-medium.txt",
        "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/directory-list-2.3-big.txt",
        "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/coldfusion.txt",
        "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/big.txt",
        "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/apache.txt",
        "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/api/api-endpoints.txt",
        "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/Common-PHP-Filenames.txt",
        "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/Common-DB-Backups.txt",
        "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/CGIs.txt",
        "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/Logins.fuzz.txt"
    ]

    with ThreadPoolExecutor(max_workers=10) as executor:
        executor.map(download_link, directory_wordlists)

if __name__ == "__main__":
    download_directory_wordlists()
