#!/usr/bin/env python3

import requests
from io import StringIO
import csv
from jinja2 import Template
import nvdlib
from datetime import datetime, timedelta

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
        print(f"Error fetching data: {e}.")
        return []

def fetch_recent_cves_with_nvdlib():
    end_date = datetime.now()
    start_date = end_date - timedelta(days=1)

    cves = nvdlib.searchCVE(pubStartDate=start_date, pubEndDate=end_date)

    cve_list = []
    for cve in cves:
        cve_id = cve.id
        description = next((desc.value for desc in cve.descriptions if desc.lang == 'en'), '')
        cve_url = f"https://nvd.nist.gov/vuln/detail/{cve_id}"
        cve_list.append((cve_id, description, cve_url))

    return cve_list

def generate_html(ssl_blacklist, cve_data):
    
    html_template = """
    <!DOCTYPE html>
    <html>
    <head>
        <title>Threat Intelligence Report</title>
        <style>
            body {
                font-family: 'Arial', sans-serif;
                line-height: 1.6;
                color: #333;
                background-color: #f4f4f4;
                padding: 20px;
                margin: 0;
            }
            .drawer {
                cursor: pointer;
                padding: 15px;
                margin: 10px 0;
                background-color: #0056b3;
                color: #ffffff;
                border-radius: 5px;
                border: 1px solid #ccc;
                box-shadow: 0 2px 5px rgba(0, 0, 0, 0.2);
                position: relative;
                transition: all 0.3s ease;
            }
            .drawer:hover {
                background-color: #003d82;
            }
            .drawer::after {
                content: '▼';
                font-size: 12px;
                position: absolute;
                right: 10px;
                top: 50%;
                transform: translateY(-50%);
                transition: transform 0.3s ease;
            }
            .drawer.open::after {
                transform: translateY(-50%) rotate(180deg);
            }
            .content {
                display: none;
                padding: 10px;
                background-color: #fff;
                box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);
                border-radius: 5px;
            }
            table {
                width: 100%;
                border-collapse: collapse;
                margin-top: 10px;
            }
            th, td {
                border: 1px solid #ddd;
                padding: 12px;
                text-align: left;
            }
            th {
                background-color: #e9ecef;
            }
            a {
                text-decoration: none;
                color: #007bff;
            }
            a:hover {
                text-decoration: underline;
            }
        </style>
        <script>
            function toggleVisibility(id, drawerId) {
                var content = document.getElementById(id);
                var drawer = document.getElementById(drawerId);
                var isOpen = content.style.display === 'block';
                content.style.display = isOpen ? 'none' : 'block';
                if (isOpen) {
                    drawer.classList.remove('open');
                } else {
                    drawer.classList.add('open');
                }
            }
        </script>
    </head>
    <body>
        <div id="drawer-ssl" class="drawer" onclick="toggleVisibility('content-ssl', 'drawer-ssl')">SSL Blacklist</div>
        <div id="content-ssl" class="content">
            <table>
                <tr>
                    <th>First Seen</th>
                    <th>Destination IP</th>
                    <th>Destination Port</th>
                </tr>
                {% for item in ssl_blacklist %}
                <tr>
                    <td>{{ item['Firstseen'] }}</td>
                    <td>{{ item['DstIP'] }}</td>
                    <td>{{ item['DstPort'] }}</td>
                </tr>
                {% endfor %}
            </table>
        </div>

        <div id="drawer-cve" class="drawer" onclick="toggleVisibility('content-cve', 'drawer-cve')">CVE Report</div>
        <div id="content-cve" class="content">
            <table>
                <tr>
                    <th>Title</th>
                    <th>Description</th>
                    <th>Link</th>
                </tr>
                {% for cve_id, description, cve_url in cve_data %}
                <tr>
                    <td>{{ cve_id }}</td>
                    <td>{{ description }}</td>
                    <td><a href="{{ cve_url }}" target="_blank">{{ cve_url }}</a></td>
                </tr>
                {% endfor %}
            </table>
        </div>
    </body>
    </html>
    """

    template = Template(html_template)
    html_content = template.render(ssl_blacklist=ssl_blacklist, cve_data=cve_data)

    with open("threat_intelligence_report.html", "w") as file:
        file.write(html_content)

    print("Threat Intelligence Report has been generated!: threat_intelligence_report.html")


def main():
    generate_html(fetch_ssl_blacklist(), fetch_recent_cves_with_nvdlib())

if __name__ == "__main__":
    main()
