# Broken Authentication Fuzzer

A comprehensive broken authentication vulnerability scanner designed for solving PortSwigger Web Security Academy labs. Automates the exploitation of various authentication bypass techniques.

## Features

- **2FA Simple Bypass**: Directly accesses account pages by bypassing 2FA protection
- **Password Reset Broken Logic**: Exploits flawed password reset mechanisms
- **Username Enumeration via Different Responses**: Detects valid usernames based on different error messages
- **Username Enumeration via Subtly Different Responses**: Advanced enumeration with nuanced response analysis
- **Concurrent Processing**: Multi-threaded execution for faster brute-force operations
- **Rate Limiting Bypass**: Dynamic IP rotation to avoid detection during timing-based enumeration


## Usage

Run the fuzzer with a target URL:

```bash
python3 Broken_Authentication.py -u <target_url> 
```

### Arguments

- `-u, --url`: Target URL (required). Example: `https://example.com`
- `-p, --proxies`: Proxy server (optional). Format: `IP:PORT`. Default: `127.0.0.1:8080`

## Examples

- Basic scan:
  ```bash
  python3 Broken_Authentication.py -u https://vulnerable-site.com
  ```

- Scan with proxy:
  ```bash
  python3 Broken_Authentication.py -u https://vulnerable-site.com -p 127.0.0.1:8080
  ```
