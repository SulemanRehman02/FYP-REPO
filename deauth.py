#!/usr/bin/env python3
import os
import re
import argparse
from scapy.all import *

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

WIRELESS_FILE = "/proc/net/wireless"
DEV_FILE = "/proc/net/dev"
PACKET_COUNT = 2000
GREEN = '\033[92m'
RED = '\033[91m'
ENDC = '\033[0m'
PATTERN = {"MAC Address": 'Address:(.*)', "ESSID": 'ESSID:(.*)', "ID": '(.*) - Address'}


class WiFiExplorer:
    def __init__(self, iface):
        self.iface = iface
        self.ap_list = {}

    def packet_handler(self, pkt):
        if pkt.haslayer(Dot11) and pkt.type == 0 and pkt.subtype == 8 and pkt.addr2 not in self.ap_list:
            mac_address = pkt.addr2
            ssid = pkt.info.decode('utf-8')
            channel = ord(pkt[Dot11Elt:3].info)
            self.ap_list[mac_address] = {'SSID': ssid, 'Channel': channel}
            print(f"[+] Found WiFi Network: {ssid} ({mac_address}) - Channel: {channel}")

    def explore_networks(self):
        print("[+] Exploring WiFi networks on all channels. Please wait...")
        for channel in range(1, 14):  # Explore channels 1 to 13
            os.system(f"iwconfig {self.iface} channel {channel}")
            sniff(iface=self.iface, prn=self.packet_handler, timeout=2, store=0)

    def get_bssid_input(self):
        while True:
            bssid = input("Enter the BSSID of the network for continuous deauthentication (or 'exit' to quit): ").strip()
            if bssid.lower() == 'exit':
                exit(0)
            elif bssid in self.ap_list:
                return bssid
            else:
                print("Invalid BSSID. Please try again.")


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Explore WiFi networks on all channels and perform continuous deauthentication attack.')
    parser.add_argument('-i', '--iface', action='store', dest='iface', required=True, help='Wireless interface name')
    results = parser.parse_args()

    if not os.geteuid() == 0:
        print(RED + "[-] Script must run with 'sudo'" + ENDC)
        exit(1)

    iface = results.iface

    explorer = WiFiExplorer(iface)
    explorer.explore_networks()

    if not explorer.ap_list:
        print(RED + "[-] No WiFi networks found. Exiting." + ENDC)
        exit(1)

    bssid = explorer.get_bssid_input()

