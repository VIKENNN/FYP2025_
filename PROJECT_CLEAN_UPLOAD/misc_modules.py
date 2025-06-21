import os
import time
#import reconnaissance
import socket
from urllib.parse import urlparse


def resolve_url_to_ip(url): #Resolves a given URL or hostname to an IP address.
    try:
        # Extract hostname from URL if needed
        parsed_url = urlparse(url)
        hostname = parsed_url.hostname if parsed_url.hostname else url  # Fallback if it's already a hostname

        # Resolve to IP
        ip_address = socket.gethostbyname(hostname)
        return ip_address
    except socket.gaierror as e:
        return f"Error resolving {url}: {e}"



def my_ruler():
    print("===================================================================================================================")
def clear_terminal():
    if os.name == 'nt':
        os.system('cls')
    else:
        os.system('clear')

def clear_pycharm():
    print("\033[H\033[J", end="")


def title():
    start = input('''
        Welcome to my Vulnerability Scanner...






                                                BY MAMAH CHUKWUEBUKA.
        PRESS ANY KEY TO CONTINUE...

    ''')
    clear_pycharm()

def selection():
    my_ruler()
    case = input('''
        What will you like to do?

        [+]1. Reconnasiance 
        [+]2. Check for Vuln
        [+]3. Posible exploit?
        [+]4. Quit
        ''')
    if case == "1":
        pass
#        reconnaissance.ip_finder()

