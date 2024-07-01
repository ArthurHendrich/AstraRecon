import subprocess
import sys

def run_httpx(target):
    if target.startswith("http://"):
        result = subprocess.run(['httpx', target], capture_output=True, text=True)
    else:
        result = subprocess.run(['httpx', '--no-verify', f'https://www.{target}'], capture_output=True, text=True)
    return result.stdout

if __name__ == "__main__":
    target = sys.argv[1]
    output = run_httpx(target)
    print(output)
