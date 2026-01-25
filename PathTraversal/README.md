# Path Traversal Scanner

A Python-based path traversal vulnerability scanner designed for solving PortSwigger labs. Tests multiple payload variations to detect path traversal vulnerabilities.

## Features

- **Comprehensive Payload Testing**: Tests hundreds of path traversal payload variations including:
  - Standard directory traversal (`../`)
  - URL encoding variations (`%2e%2e%2f`)
  - Double encoding (`%252e%252e%252f`)
  - Null byte injection (`%00`)
  - Unicode encoding variations
- **Concurrent Scanning**: Uses multi-threading for faster payload testing.
- **Automatic Detection**: Identifies successful payloads by detecting `/etc/passwd` content in responses.

## Usage

Run the scanner with a target URL:

```bash
python3 PathTraversal.py -u <target_url>
```

### Arguments

- `-u, --url`: The target URL to test (required). Example: `https://example.com`
- `-p, --proxies`: Use a proxy. Format: `IP:PORT`. Default: `127.0.0.1:8080` if `-p` is used without value.

## Examples

- Basic scan:
  ```bash
  python3 PathTraversal.py -u https://vulnerable-site.com
  ```

- Scan with proxy:
  ```bash
  python3 PathTraversal.py -u https://vulnerable-site.com -p 127.0.0.1:8080
  ```

## Video Tutorial

📹 [Video](https://www.youtube.com/watch?v=reytcvH-buk)
