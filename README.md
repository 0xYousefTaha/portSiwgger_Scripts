# PortSwigger Scripts

This repository contains a collection of Python scripts designed to automate the solution of various labs in the PortSwigger Web Security Academy. These scripts cover a range of web vulnerabilities, providing practical examples and automated exploitation techniques.

## Repository Structure

- [`Broken_Authentication/`](./Broken_Authentication/README.md): Scripts for exploiting broken authentication vulnerabilities.
- [`Information_Disclosure/`](./Information_Disclosure/README.md): Scripts for detecting and exploiting information disclosure vulnerabilities.
- [`PathTraversal/`](./PathTraversal/README.md): Scripts for identifying and exploiting path traversal vulnerabilities.

## Requirements

- Python 3.x
- `requests` library
- `urllib3` library
- `selenium` library (specifically for `Info_scanner_V2.py` automated submission)
- Chrome WebDriver (for `Info_scanner_V2.py` automated submission)

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

3. Install Chrome WebDriver (for `Info_scanner_V2.py`):
   - Download from: https://chromedriver.chromium.org/downloads
   - Or install via package manager (Ubuntu/Debian):
     ```bash
     sudo apt-get install chromium-chromedriver
     ```

For detailed usage and specific requirements for each script, please refer to their respective `README.md` files located in their directories.
