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
        seven_days_ago = datetime.now() - timedelta(days=7)
        blacklist = []

        for row in csv_reader:
            if row:
                try:
                    first_seen_datetime = datetime.strptime(row['Firstseen'], "%Y-%m-%d %H:%M:%S")
                    if first_seen_datetime.date() >= seven_days_ago.date():
                        blacklist.append(row)
                except ValueError:
                    continue

        return blacklist

    except requests.RequestException as e:
        print(f"Error fetching data: {e}.")
        return []

def fetch_recent_cves_with_nvdlib():
    end_date = datetime.now()
    start_date = end_date - timedelta(days=1)

    try:
        cves = nvdlib.searchCVE(pubStartDate=start_date, pubEndDate=end_date)
    except ConnectionError as e:
        if 'Max retries exceeded' in str(e) and 'Failed to establish a new connection' in str(e):
            print("Rate limit on NVD Database likely exceeded. Please wait 1 minute and try to run the script again")

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
        seven_days_ago = datetime.now() - timedelta(days=7)
        recent_malware = []

        for row in csv_reader:
            if row:
                try:
                    date_added = datetime.strptime(row['dateadded'], "%Y-%m-%d %H:%M:%S")
                    if date_added.date() >= seven_days_ago.date():
                        recent_malware.append(row)
                except ValueError:
                    continue

        return recent_malware

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

def fetch_ip_blocklist():
    url = "https://lists.blocklist.de/lists/all.txt"

    try:
        response = requests.get(url)
        response.raise_for_status()
    except requests.RequestException as e:
        print(f"Error fetching data: {e}.")
        return []

    data = StringIO(response.text)
    ip_list = [row.strip() for row in data if row.strip()]
    return ip_list

def fetch_cisa_known_exploits():
    url = "https://www.cisa.gov/sites/default/files/csv/known_exploited_vulnerabilities.csv"

    try:
        response = requests.get(url)
        response.raise_for_status()

        data = StringIO(response.text)
        headers = None

        while True:
            line = data.readline()
            if 'cveID,vendorProject,product,vulnerabilityName,dateAdded,shortDescription,requiredAction,dueDate,knownRansomwareCampaignUse,notes' in line:
                headers = line.strip('# \r\n').split(',')
                break

        csv_reader = csv.DictReader(data, fieldnames=headers)
        seven_days_ago = datetime.now() - timedelta(days=7)
        cisa_known_exploits = []

        for row in csv_reader:
            if row:
                try:
                    date_added = datetime.strptime(row['dateAdded'], "%Y-%m-%d")
                    if date_added.date() >= seven_days_ago.date():
                        cisa_known_exploits.append(row)
                except ValueError:
                    continue

        return cisa_known_exploits

    except requests.RequestException as e:
        print(f"Error fetching data: {e}.")
        return []

def generate_html(ssl_blacklist, cve_data, recent_malware, known_c2, cisa_known_exploits, ip_blocklist):
    current_date = datetime.now().strftime("%m-%d-%Y")
    report_name = "threat_intelligence_report_" + current_date + ".html"
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
            header {
                background-color: #008080;
                color: white;
                text-align: center;
                padding: 10px 0;
                font-size: 24px;
                border-bottom: 3px solid #008085;
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
            input[type="text"] {
                width: 220px;
                padding: 8px;
                margin-bottom: 10px;
                border: 1px solid #ccc;
                border-radius: 4px;
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

            function filterTable(event) {
                var filter = event.target.value.toUpperCase();
                var rows = document.querySelector("#" + event.target.getAttribute("data-table") + " tbody").rows;

                for (var i = 1; i < rows.length; i++) {
                    var containsText = false;
                    for (var j = 0; j < rows[i].cells.length; j++){
                        if (rows[i].cells[j].textContent.toUpperCase().indexOf(filter) > -1) {
                            containsText = true;
                            break;
                        }
                    }
                    rows[i].style.display = containsText ? "" : "none";
                }
            }
        </script>
    </head>
    <body>
        <header>
            ThreatScope Generated Report for {{ current_date }}
        </header>

        <div id="drawer-ssl" class="drawer" onclick="toggleVisibility('content-ssl', 'drawer-ssl')">SSL Blacklist (7 Days)</div>
        <div id="content-ssl" class="content">
            <input type="text" onkeyup="filterTable(event)" placeholder="Filter SSL Blacklist..." data-table="sslTable">
            <table id="sslTable">
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

        <div id="drawer-cve" class="drawer" onclick="toggleVisibility('content-cve', 'drawer-cve')">CVE Report (24 Hours)</div>
        <div id="content-cve" class="content">
            <input type="text" onkeyup="filterTable(event)" placeholder="Search for CVEs..." data-table="cveTable">
            <table id="cveTable">
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

        <div id="drawer-malware" class="drawer" onclick="toggleVisibility('content-malware', 'drawer-malware')">Recent Malware URLs (7 Days)</div>
        <div id="content-malware" class="content">
            <input type="text" onkeyup="filterTable(event)" placeholder="Search for Recent Malware URLs..." data-table="malwareTable">
            <table id="malwareTable">
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

        <div id="drawer-c2" class="drawer" onclick="toggleVisibility('content-c2', 'drawer-c2')">Threatmon Known C2 (24 Hours)</div>
        <div id="content-c2" class="content">
            <input type="text" onkeyup="filterTable(event)" placeholder="Search for Known C2 Nodes..." data-table="c2Table">
            <table id="c2Table">
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

        <div id="drawer-exploits" class="drawer" onclick="toggleVisibility('content-exploits', 'drawer-exploits')">CISA Known Exploits (7 Days)</div>
        <div id="content-exploits" class="content">
            <input type="text" onkeyup="filterTable(event)" placeholder="Search for CISA Known Exploits..." data-table="cisaTable">
            <table id="cisaTable">
                <tr>
                    <th>CVE ID</th>
                    <th>Vendor/th>
                    <th>Product</th>
                    <th>Vulnerability Name</th>
                    <th>Date Added</th>
                    <th>Description</th>
                    <th>Required Action</th>
                    <th>Due Date</th>
                    <th>Known Ransomware Campaign Usage</th>
                    <th>Notes</th>
                </tr>
                {% for item in cisa_known_exploits %}
                <tr>
                    <td>{{ item['cveID'] }}</td>
                    <td>{{ item['vendorProject'] }}</td>
                    <td>{{ item['product'] }}</td>
                    <td>{{ item['vulnerabilityName'] }}</td>
                    <td>{{ item['dateAdded'] }}</td>
                    <td>{{ item['shortDescription'] }}</td>
                    <td>{{ item['requiredAction'] }}</td>
                    <td>{{ item['dueDate'] }}</td>
                    <td>{{ item['knownRansomwareCampaignUse'] }}</td>
                    <td>{{ item['notes'] }}</td>
                </tr>
                {% endfor %}
            </table>
        </div>

        <div id="drawer-ip" class="drawer" onclick="toggleVisibility('content-ip', 'drawer-ip')">Blocklist.de IP Blocklist</div>
        <div id="content-ip" class="content">
            <input type="text" onkeyup="filterTable(event)" placeholder="Search for Blocked IPs..." data-table="ipTable">
            <table id="ipTable">
                <tr>
                    <th>IP</th>
                </tr>
                {% for ip in ip_blocklist %}
                <tr>
                    <td>{{ ip }}</td>
                </tr>
                {% endfor %}
            </table>
        </div>
    </body>
    </html>
    """

    template = Template(html_template)
    html_content = template.render(ssl_blacklist=ssl_blacklist, cve_data=cve_data, recent_malware=recent_malware, known_c2=known_c2, cisa_known_exploits=cisa_known_exploits, ip_blocklist=ip_blocklist, current_date=current_date)

    with open(report_name, "w") as file:
        file.write(html_content)

    print(f"Threat Intelligence Report has been generated!: {report_name}")


def main():
    generate_html(fetch_ssl_blacklist(), fetch_recent_cves_with_nvdlib(), fetch_recent_malware_urls(), fetch_known_c2(), fetch_cisa_known_exploits(), fetch_ip_blocklist())

if __name__ == "__main__":
    main()
