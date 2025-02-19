# AstraRecon

AstraRecon is an Automated Pentesting Tool designed to scan and enumerate subdomains, perform reconnaissance on hostnames and FQDNs (Fully Qualified Domain Names), and more. It's developed as a comprehensive solution for security testing and analysis.

## Version History

### Beta Version 1.2 (Current)
- Improved application structure and reliability
- Enhanced error handling and logging system
- Fixed API authentication headers
- Optimized subdomain discovery process
- Added comprehensive results analysis
- Improved database storage and management

### Beta Version 1.1
- Enhanced HTML interface for better user experience
- Initial implementation of API integrations
- Basic logging system implementation
- Preliminary subdomain discovery features

## Features

- Subdomain Enumeration using multiple sources:
  - Passive Recon: AlienVault, Anubis, Censys, CertSpotter, crt.sh, HackerTarget, RapidDNS, SecurityTrails, Shodan, URLScan, VirusTotal
  - Active Recon: ASNmap, Assetfinder, GoSpider, httpx, Katana, Naabu, Subfinder, TLSx, Wapiti, WhatWeb, Wafw00f, Waybackurls, Hakrawler, CMSeek
- Hostname and FQDN Reconnaissance
- Automated Installation of Essential Tools
- Web Interface for Easy Management
- Comprehensive Results Analysis
- Database Storage for Historical Data
- Rate Limiting Protection
- Detailed Logging System

## Requirements

- Python 3.8+
- Required API Keys (configure in `.env`):
  - CertSpotter
  - SecurityTrails
  - Shodan
  - VirusTotal
  - URLScan (optional)

## Installation

1. **Clone the repository:**

   ```bash
   git clone https://github.com/yourusername/AstraRecon.git
   cd AstraRecon
   ```

2. **Install required Python packages:**

   ```bash
   pip install -r requirements.txt
   ```

3. **Configure your API keys:**
   Create a `.env` file in the root directory with your API keys:
   ```
   CERTSPOTTER_API_KEY=your_key_here
   SECURITY_TRAILS_API_KEY=your_key_here
   SHODAN_API_KEY=your_key_here
   VIRUSTOTAL_API_KEY=your_key_here
   URLSCAN_API_KEY=your_key_here  # Optional
   ```

## Usage

### Web Interface
Run the application in web mode:
```bash
python3 app.py
```
Then access the web interface at `http://localhost:5000`

### Command Line
For command-line usage:
```bash
python3 app.py <domain>  # For reconnaissance on a specific domain
python3 analyze_results.py --help  # For analyzing results
```

### Analysis Options
```bash
python3 analyze_results.py [OPTIONS]
Options:
  -d, --domain DOMAIN    Target domain to analyze
  -l, --list-domains    List all domains in the database
  -H, --history         Show execution history
  -e, --export FILE     Export results to JSON file
  -a, --all            Analyze all domains in the database
  -D, --details        Include detailed tool results
  --debug              Enable debug logging
```

## Contributing

Contributions to AstraRecon are welcome! Please read our contributing guidelines for more information.

## MIT License

Copyright (c) [2025] [AstraRecon]

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

## Acknowledgements

- This tool is intended for educational and ethical testing purposes only
- We are not responsible for any misuse or damage
- Thanks to all contributors and the security community

## Support

If you encounter any issues or have suggestions, please open an issue on GitHub.
