#!/usr/bin/env python3

import requests
from io import StringIO
import csv
from jinja2 import Template

def fetch_ssl_blacklist(url):

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
        print(f"Error fetching data: {e}.")
        return []

def generate_ssl_blacklist_html():
    url = "https://sslbl.abuse.ch/blacklist/sslipblacklist_aggressive.csv"
    data = fetch_ssl_blacklist(url)
    
    html_template = """
    <!DOCTYPE html>
    <html>
    <head>
        <title>SSL Blacklist</title>
        <style>
            #drawer { cursor: pointer; padding: 10px; margin-top: 5px; background-color: #f0f0f0; border: 1px solid #d0d0d0; }
            #content { display: none; padding: 10px; background-color: #fff; }
            table { width: 100%; border-collapse: collapse; }
            th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
            th { background-color: #f2f2f2; }
        </style>
    </head>
    <body>
        <div id="drawer" onclick="document.getElementById('content').style.display = document.getElementById('content').style.display === 'block' ? 'none' : 'block';">
            <h1>SSL IP Blacklist</h1>
        </div>
        <div id="content">
            <table>
                <tr>
                    <th>First Seen</th>
                    <th>Destination IP</th>
                    <th>Destination Port</th>
                </tr>
                {% for item in data %}
                <tr>
                    <td>{{ item['Firstseen'] }}</td>
                    <td>{{ item['DstIP'] }}</td>
                    <td>{{ item['DstPort'] }}</td>
                </tr>
                {% endfor %}
            </table>
        </div>
    </body>
    </html>
    """

    template = Template(html_template)
    html_content = template.render(data=data)

    with open("ssl_blacklist.html", "w") as file:
        file.write(html_content)

    print("HTML file generated: ssl_blacklist.html")

def main():
    generate_ssl_blacklist_html()

if __name__ == "__main__":
    main()
