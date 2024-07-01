import subprocess
import sys

def run_tlsx(target):
    result = subprocess.run(["tlsx", "-silent", "-un", "-re", "-mm", "-ss", "-ex", "-ve", "-tps", "-wc", "-ja3", "-jarm", "-hash", "md5,sha1,sha265", "-tv", "-so", target], capture_output=True, text=True)
    if result.stdout:
        with open(f'infos/tlsx.{target}', 'a') as f:
            f.write(result.stdout)

if __name__ == "__main__":
    target = sys.argv[1]
    run_tlsx(target)
