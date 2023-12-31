# AstraRecon

AstraRecon is an Automated Pentesting Tool designed to scan and enumerate subdomains, perform reconnaissance on hostnames and FQDNs (Fully Qualified Domain Names), and more. It's developed as a comprehensive solution for security testing and analysis.

## Features

- Subdomain Enumeration
- Hostname and FQDN Reconnaissance
- Automated Installation of Essential Tools
- Easy-to-use Command-Line Interface

## Installation

1. **Clone the repository:**

   ```bash
   git clone [your-repository-url]
   cd AstraPentest
   ```
2. **Install required Python packages:**

   ```bash
   pip install -r requirements.txt
   ```
3. **Install the necessary tools:**
   Run the script in install mode to automatically install the necessary tools.

   ```bash
   python3 subdomain.py -mode install
   ```
4. **Set up your environment (if necessary):**
   You might need to set up your environment depending on your system configuration.

## Usage

To use AstraPentest, run the script with the desired mode and target. For example:

```bash
python3 subdomain.py [target-domain] -mode [mode]
```

Available modes are:

- `subdomain`: for subdomain enumeration.
- `recon`: for reconnaissance on hostnames and FQDNs.
- `all`: for running all the features.

## Contributing

Contributions to AstraPentest are welcome! Please read our contributing guidelines for more information.

## MIT License

Copyright (c) [2023] [AtraRecon]

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

We are not responsible for misuse. AstraPentest is intended for educational and ethical testing purposes only.

Thanks to all the contributors and supporters of AstraPentest.
