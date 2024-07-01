import subprocess
import sys

def run_assetfinder(target):
    result = subprocess.run(['assetfinder', '--subs-only', target], capture_output=True, text=True)
    return result.stdout

if __name__ == "__main__":
    target = sys.argv[1]
    output = run_assetfinder(target)
    print(output)
