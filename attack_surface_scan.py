#!/usr/bin/env python3
import subprocess
import sys
import json

def scan(target):
    result = subprocess.run(['nmap', '-sV', target], capture_output=True, text=True)
    return result.stdout

if __name__ == "__main__":
    target = sys.stdin.read().strip()
    results = scan(target)
    print(json.dumps({"results": results}))
