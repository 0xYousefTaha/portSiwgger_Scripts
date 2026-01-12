# PortSwigger Scripts

Scripts that automate solutions for PortSwigger Web Security Academy labs.

## Requirements

- Python 3.x
- `requests` library
- `urllib3` library

## Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/yourusername/portSiwgger_Scripts.git
   cd portSiwgger_Scripts
   ```

2. Install dependencies:
   ```bash
   pip install requests urllib3
   ```

---

## Info Scanner

A Python-based information disclosure vulnerability scanner designed for solving PortSwigger labs.

### Features

- **Error Message Disclosure Check**: Tests for error-based vulnerabilities.
- **Exposed phpinfo.php Detection**: Scans for exposed PHP debug pages and extracts potential secrets.
- **Hidden Pages Discovery**: Checks for common hidden administrative and backup pages.
- **Authentication Bypass**: Attempts to bypass authentication using custom headers to access admin panels and perform actions like user deletion.

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

#### Video Tutorial

📹 [Video](https://www.youtube.com/watch?v=XxCMx4J-o4k)

---

## Path Traversal Scanner

A Python-based path traversal vulnerability scanner designed for solving PortSwigger labs. Tests multiple payload variations to detect path traversal vulnerabilities.

### Features

- **Comprehensive Payload Testing**: Tests hundreds of path traversal payload variations including:
  - Standard directory traversal (`../`)
  - URL encoding variations (`%2e%2e%2f`)
  - Double encoding (`%252e%252e%252f`)
  - Null byte injection (`%00`)
  - Unicode encoding variations
- **Concurrent Scanning**: Uses multi-threading for faster payload testing.
- **Automatic Detection**: Identifies successful payloads by detecting `/etc/passwd` content in responses.

### Usage

Run the scanner with a target URL:

```bash
python3 PathTraversal.py -u <target_url>
```

#### Arguments

- `-u, --url`: The target URL to test (required). Example: `https://example.com`
- `-p, --proxies`: Use a proxy. Format: `IP:PORT`. Default: `127.0.0.1:8080` if `-p` is used without value.

#### Examples

- Basic scan:
  ```bash
  python3 PathTraversal.py -u https://vulnerable-site.com
  ```

- Scan with proxy:
  ```bash
  python3 PathTraversal.py -u https://vulnerable-site.com -p 
  python3 PathTraversal.py -u https://vulnerable-site.com -p 127.0.0.1:9090
  ```


