
# ThreatScope

ThreatScope is a threat intelligence tool that generates a static HTML file for security analysts to use to gather information from the past week (24 hours for some sources). As of now, it pulls data from:

    abuse.ch SSLBL Botnet C2 IP Blacklist
    abuse.ch URLHaus Recent Malware URLs
    Blocklist.de IP Blacklist
    Threatmon Known C2 Servers
    NIST NVD
    CISA Known Exploits Database

Each drawer contains the respective data and can be sorted using the search bar within. 



## Run Locally

Clone the project

```bash
  git clone https://github.com/khronos2/ThreatScope
```

Go to the project directory

```bash
  cd ThreatScope
```

Install dependencies

```bash
  # If not installed, install pip3 for your OS according to these instructions: https://pip.pypa.io/en/stable/installation/

  pip3 install -r requirements.txt
```

Run the script

```bash
  python3 ThreatScope.py
```

After the script finishes, open the `threat_intelligence_report_current-date.html`