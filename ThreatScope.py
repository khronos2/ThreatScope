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

def fetch_recent_malware_urls():
    url = "https://urlhaus.abuse.ch/downloads/csv_recent/"

    try:
        response = requests.get(url)
        response.raise_for_status()

        data = StringIO(response.text)
        headers = None

        while True:
            line = data.readline()

            if 'id,dateadded,url,url_status,last_online,threat,tags,urlhaus_link,reporter' in line:
                headers = line.strip('# \r\n').split(',')
                break

        csv_reader = csv.DictReader(data, fieldnames=headers)

        blacklist = [row for row in csv_reader if row]
        return blacklist

    except requests.RequestException as e:
        print(f"Error fetching data: {e}.")
        return []

def fetch_known_c2():
    def generate_url(date):
        year_month = date.strftime("%Y-%m")
        year_month_day = date.strftime("%Y-%m-%d")
        return f"https://raw.githubusercontent.com/ThreatMon/ThreatMon-Daily-C2-Feeds/main/{year_month}/ThreatMon-C2-Feed-{year_month_day}.txt"

    current_date = datetime.now()

    url = generate_url(current_date)

    try:
        response = requests.get(url)
        response.raise_for_status()
    except requests.HTTPError as e:
        if e.response.status_code == 404:
            previous_day = current_date - timedelta(days=1)
            url = generate_url(previous_day)
            response = requests.get(url)
            response.raise_for_status()
        else:
            print(f"Error fetching data: {e}.")
            return []

    data = StringIO(response.text)
    c2_list = [row.strip() for row in data if row.strip()]
    return c2_list

def generate_html(ssl_blacklist, cve_data, recent_malware, known_c2):
    
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
                overflow-x: auto;
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
                white-space: nowrap;
            }
            th, td {
                border: 1px solid #ddd;
                padding: 12px;
                text-align: left;
                max-width: 120px;
                white-space: normal;
                overflow: hidden;
                text-overflow: ellipsis;
                word-wrap: break-word;
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
                    <td>{{ description | escape}}</td>
                    <td><a href="{{ cve_url }}" target="_blank">{{ cve_url }}</a></td>
                </tr>
                {% endfor %}
            </table>
        </div>

        <div id="drawer-malware" class="drawer" onclick="toggleVisibility('content-malware', 'drawer-malware')">Recent Malware URLs (30 Days)</div>
        <div id="content-malware" class="content">
            <table>
                <tr>
                    <th>ID</th>
                    <th>Date Added</th>
                    <th>URL</th>
                    <th>URL Status</th>
                    <th>Last Online</th>
                    <th>Threat</th>
                    <th>Tags</th>
                    <th>URLHaus Link</th>
                    <th>Reporter</th>
                </tr>
                {% for item in recent_malware %}
                <tr>
                    <td>{{ item['id'] }}</td>
                    <td>{{ item['dateadded'] }}</td>
                    <td>{{ item['url'] }}</td>
                    <td>{{ item['url_status'] }}</td>
                    <td>{{ item['last_online'] }}</td>
                    <td>{{ item['threat'] }}</td>
                    <td>{{ item['tags'] }}</td>
                    <td>{{ item['urlhaus_link'] }}</td>
                    <td>{{ item['reporter'] }}</td>
                </tr>
                {% endfor %}
            </table>
        </div>

        <div id="drawer-c2" class="drawer" onclick="toggleVisibility('content-c2', 'drawer-c2')">Threatmon Known C2</div>
        <div id="content-c2" class="content">
            <table>
                <tr>
                    <th>C2</th>
                </tr>
                {% for c2 in known_c2 %}
                <tr>
                    <td>{{ c2}}</td>
                </tr>
                {% endfor %}
            </table>
        </div>
    </body>
    </html>
    """

    template = Template(html_template)
    html_content = template.render(ssl_blacklist=ssl_blacklist, cve_data=cve_data, recent_malware=recent_malware, known_c2=known_c2)

    with open("threat_intelligence_report.html", "w") as file:
        file.write(html_content)

    print("Threat Intelligence Report has been generated!: threat_intelligence_report.html")


def main():
    generate_html(fetch_ssl_blacklist(), fetch_recent_cves_with_nvdlib(), fetch_recent_malware_urls(),fetch_known_c2())

if __name__ == "__main__":
    main()
