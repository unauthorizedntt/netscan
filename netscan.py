#!/usr/bin/env python3

"""
> Scirpt for scanning devices in the same network and returning their IP and MAC addresses using ARP scanning.
> Must be run with root privilege.
> Command example: sudo python3 pythontest.py -t 192.168.1.0/24 -c 50
"""

from scapy.all import ARP, Ether, srp
from argparse import ArgumentParser


def get_argument():    # Function for getting arguments from user and parsing them

    # Creating an object "parser" from the class "ArgumentParser()"
    parser = ArgumentParser()

    # Adding argument options
    parser.add_argument("-t", "--target", dest="target", help="Specify a target IP or IP range e.g. 192.168.1.0/24")
    parser.add_argument("-c", "--count", dest="count", type=int, default=50, help="How many times the packet should be sent. Default is 50")

    # Parse the arguments
    arguments_01 = parser.parse_args()

    # Checking if arguments are passed properly in the command
    if not arguments_01.target:
        parser.error("[!] Specify a target IP or IP range e.g. 192.168.1.0/24")

    return arguments_01


def scan(ip, retry_count=50):    # Funtion for scanning devices

    # Creating an ARP request packet (ARP) with the destination IP address (pdst)
    #set to the value passed as the "ip" parameter to the function.
    arp_request = ARP(pdst=ip)

    # Creating an Ethernet frame (Ether) with the destination MAC address (dst) 
    #set to the broadcast address, "ff:ff:ff:ff:ff:ff", indicating that the packet should be sent to all devices on the local network.
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")

    # Encapsulating the ARP request within the Ethernet frame
    broadcast_arp_request = broadcast / arp_request

    # Capturing answered packets and ignoring non-answered packets
    responsed_list, _ = srp(broadcast_arp_request, timeout=0.1, retry=retry_count, verbose=False)

    # responsed_list.show()    # Uncomment to view the answered packets

    client_list = []
    for element in responsed_list:
        # element[1].show()    # Uncomment for showing ARP responses in details

        # Getting IP (psrc) and MAC (hwsrc) addresses from ARP responses
        client_dictionary = {"ip": element[1].psrc, "mac": element[1].hwsrc}
        client_list.append(client_dictionary)

    return client_list


def print_scan_result(client_list):    # Function for showing result in the terminal in a nice format
    print("\n n\t IP\t\t\t MAC\n===================================================")
    count = 0
    for client in client_list:
        count += 1
        print("", count, "\t", client["ip"], "\t\t", client["mac"])
        print("---------------------------------------------------")


def main():
    arguments_1 = get_argument()
    scan_result = scan(ip=arguments_1.target, retry_count=arguments_1.count)
    print_scan_result(scan_result)


if __name__ == "__main__":
    main()
