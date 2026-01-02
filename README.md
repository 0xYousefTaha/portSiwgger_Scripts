# PortSwigger Scripts

Scripts that automate solutions for PortSwigger Web Security Academy labs.

## Info Scanner

A Python-based information disclosure vulnerability scanner designed for Solving PortSwigger labs.

### Features

- **Error Message Disclosure Check**: Tests for error Based Vulns.
- **Exposed phpinfo.php Detection**: Scans for exposed PHP debug pages and extracts potential secrets.
- **Hidden Pages Discovery**: Checks for common hidden administrative and backup pages.
- **Authentication Bypass**: Attempts to bypass authentication using custom headers to access admin panels and perform actions like user deletion.

### Requirements

- Python 3.x
- `requests` library
- `urllib3` library

### Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/yourusername/portSiwgger_Scripts.git
   cd portSiwgger_Scripts
   ```

2. Install dependencies:
   ```bash
   pip install requests urllib3
   ```

### Usage

Run the scanner with a target URL:

```bash
python3 Info_scanner.py -u <target_url> 
```

#### Arguments

- `-u, --url`: The target URL to test (required). Example: `https://example.com`
- `-p, --proxies`: Use a proxy. Format: `IP:PORT`. Default: `127.0.0.1:8080` if `-p` is used without value.

#### Examples

- Basic scan:
  ```bash
  python3 Info_scanner.py -u https://vulnerable-site.com
  ```

- Scan with proxy:
  ```bash
  python3 Info_scanner.py -u https://vulnerable-site.com -p 127.0.0.1:8080
  ```


### References 
- Rana Khalil
- https://docs.python.org/3/library/argparse.html

