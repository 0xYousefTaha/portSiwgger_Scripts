# Info Scanner

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

Scan with proxy:

```bash
python3 Info_scanner.py -u https://vulnerable-site.com -p 127.0.0.1:8080
```

#### Video Tutorial

📹 [Video](https://www.youtube.com/watch?v=XxCMx4J-o4k)

---

# Info Scanner V2

An enhanced version of the information disclosure scanner with automated submission capabilities for PortSwigger Web Security Academy labs.

## Features

- **All Info Scanner features**: Includes all functionality from the original Info_scanner.py
- **Automated Lab Submission**: Uses Selenium WebDriver to automatically submit discovered solutions to PortSwigger labs
- **Chrome Integration**: Launches Chrome browser to interact with lab interfaces and submit answers
- **Real-time Status Monitoring**: Monitors lab status before and after submission
- **Error Handling**: Robust error handling for browser interactions and dialog management

## Usage

Run the enhanced scanner with a target URL:

```bash
python3 Info_scanner_V2.py -u <target_url> 
```

### Arguments

- `-u, --url`: The target URL to test (required). Example: `https://example.com`
- `-p, --proxies`: Use a proxy. Format: `IP:PORT`. Default: `127.0.0.1:8080` if `-p` is used without value.

## Examples

- Basic scan with automated submission:
  ```bash
  python3 Info_scanner_V2.py -u https://vulnerable-site.com 
  ```

- Scan with proxy:
  ```bash
  python3 Info_scanner_V2.py -u https://vulnerable-site.com  -p 
  python3 Info_scanner_V2.py -u https://vulnerable-site.com  -p 127.0.0.1:9000
  ```

## Requirements

- Chrome browser installed on system
- All standard requirements from Info_scanner.py

#### Video Tutorial

📹 [Video](https://www.youtube.com/watch?v=AuaK82x94IA)
