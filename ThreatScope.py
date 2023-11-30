#!/usr/bin/env python3

import requests
from io import StringIO
import csv

def fetch_ssl_blacklist():
    url = "https://sslbl.abuse.ch/blacklist/sslipblacklist_aggressive.csv"

    try:
        response = requests.get(url)
        response.raise_for_status()

        data = StringIO(response.text)
        headers = None
        
        while True:
            line = data.readline()

            if 'Firstseen,DstIP,DstPort' in line:
                headers = line.strip('# \r\n').split(',')
                break

        csv_reader = csv.DictReader(data, fieldnames=headers)

        blacklist = [row for row in csv_reader if row]
        return blacklist

    except requests.RequestException as e:
        print(f"Error fetching data: {e}. This error is no good.")
        return []

def generate_ssl_blacklist_html():
    print("hold")

def main():
    print(fetch_ssl_blacklist())

if __name__ == "__main__":
    main()
