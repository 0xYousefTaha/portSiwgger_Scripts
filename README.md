# PortSwigger Scripts

Scripts that automate solutions for PortSwigger Web Security Academy labs.

## Requirements

- Python 3.x
- `requests` library
- `urllib3` library
- `selenium` library (for Info_scanner_V2.py automated submission)
- Chrome WebDriver (for Info_scanner_V2.py automated submission)

## Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/yourusername/portSiwgger_Scripts.git
   cd portSiwgger_Scripts
   ```

2. Install dependencies:
   ```bash
   python3 -m venv venv
   source venv/bin/activate
   pip install requests urllib3 selenium
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

## Info Scanner V2

An enhanced version of the information disclosure scanner with automated submission capabilities for PortSwigger Web Security Academy labs.

### Features

- **All Info Scanner features**: Includes all functionality from the original Info_scanner.py
- **Automated Lab Submission**: Uses Selenium WebDriver to automatically submit discovered solutions to PortSwigger labs
- **Chrome Integration**: Launches Chrome browser to interact with lab interfaces and submit answers
- **Real-time Status Monitoring**: Monitors lab status before and after submission
- **Error Handling**: Robust error handling for browser interactions and dialog management

### Usage

Run the enhanced scanner with a target URL:

```bash
python3 Info_scanner_V2.py -u <target_url> 
```

#### Arguments

- `-u, --url`: The target URL to test (required). Example: `https://example.com`
- `-p, --proxies`: Use a proxy. Format: `IP:PORT`. Default: `127.0.0.1:8080` if `-p` is used without value.

#### Examples

- Basic scan with automated submission:
  ```bash
  python3 Info_scanner_V2.py -u https://vulnerable-site.com 
  ```

- Scan with proxy:
  ```bash
  python3 Info_scanner_V2.py -u https://vulnerable-site.com  -p 
  python3 Info_scanner_V2.py -u https://vulnerable-site.com  -p 127.0.0.1:9000
  ```

#### Requirements

- Chrome browser installed on system
- Chrome WebDriver matching your Chrome version
- All standard requirements from Info_scanner.py

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

#### Video Tutorial

📹 [Video](https://www.youtube.com/watch?v=reytcvH-buk)

---

## Broken Authentication Fuzzer

A comprehensive broken authentication vulnerability scanner designed for solving PortSwigger Web Security Academy labs. Automates the exploitation of various authentication bypass techniques.

### Features

- **2FA Simple Bypass**: Directly accesses account pages by bypassing 2FA protection
- **Password Reset Broken Logic**: Exploits flawed password reset mechanisms
- **Username Enumeration via Different Responses**: Detects valid usernames based on different error messages
- **Username Enumeration via Subtly Different Responses**: Advanced enumeration with nuanced response analysis
- **Username Enumeration via Response Timing**: Uses timing analysis to detect valid usernames (with rate limiting bypass)
- **Concurrent Processing**: Multi-threaded execution for faster brute-force operations
- **Rate Limiting Bypass**: Dynamic IP rotation to avoid detection during timing-based enumeration

### Supported Labs

- 2FA simple bypass
- Password reset broken logic
- Username enumeration via different responses
- Username enumeration via subtly different responses
- Username enumeration via response timing

### Usage

Run the fuzzer with a target URL:

```bash
python3 Broken_Authentication_Fuzzer -u <target_url> [-p PROXY]
```

#### Arguments

- `-u, --url`: Target URL (required). Example: `https://example.com`
- `-p, --proxies`: Proxy server (optional). Format: `IP:PORT`. Default: `127.0.0.1:8080`

#### Requirements

- `username.txt`: File containing usernames to test (one per line)
- `passwords.txt`: File containing passwords to test (one per line)

#### Examples

- Basic scan:
  ```bash
  python3 Broken_Authentication_Fuzzer -u https://vulnerable-site.com
  ```

- Scan with proxy:
  ```bash
  python3 Broken_Authentication_Fuzzer -u https://vulnerable-site.com -p 127.0.0.1:8080
  ```

---


