#!/usr/bin/env python3
from colorama import init, Fore, Style

# Initialize colorama
init(autoreset=True)

# Orange color for colorama (using ANSI escape code since colorama doesn't have orange directly)
ORANGE = '\033[38;5;208m'

# Your exact output with specified colors
print(f"{Style.BRIGHT}{Fore.CYAN}Starting Shiv at Fri May 22 01:08:02 2026{Style.RESET_ALL}")
print(f"{Style.BRIGHT}{Fore.CYAN}Shiv scan report for {Fore.GREEN}ack.nmap.org ({Fore.GREEN}50.116.1.184{Fore.CYAN}){Style.RESET_ALL}")
print()
print(f"{Style.BRIGHT}{Fore.YELLOW}PORT      STATE   SERVICE{Style.RESET_ALL}")
print(f"{ORANGE}22{Style.RESET_ALL}/tcp    {Fore.GREEN}open{Style.RESET_ALL}    ssh 🔐")
print(f"{ORANGE}80{Style.RESET_ALL}/tcp    {Fore.GREEN}open{Style.RESET_ALL}    http 🌐")
print(f"{ORANGE}443{Style.RESET_ALL}/tcp   {Fore.GREEN}open{Style.RESET_ALL}    https 🌐")
print()
print(f"{Fore.WHITE}Packets send : 2989{Style.RESET_ALL}")
print(f"{Fore.WHITE}RTT          : 0.274s{Style.RESET_ALL}")
print(f"{Fore.WHITE}Not shown    : 994 filtered tcp ports ({Fore.YELLOW}no-response{Fore.WHITE}), 4 closed tcp ports ({Fore.RED}reset-conn{Fore.WHITE}){Style.RESET_ALL}")
print(f"{Fore.WHITE}Duration     : 14.69s{Style.RESET_ALL}")
