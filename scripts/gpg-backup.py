#!/usr/bin/env python3

import os
import argparse
import subprocess
import getpass

BLACK = "\033[0;30m"
RED = "\033[0;31m"
GREEN = "\033[0;32m"
BLUE = "\033[0;34m"
YELLOW = "\033[0;93m"
END = "\033[0m"

# Display list of disks
def disk_list():
    try:
        output = subprocess.check_output(["fdisk","-l"]).decode("utf-8")
        lines = output.split('\n')

        print(f"{YELLOW}\nAvailable disks:{END}")

        count = 0
        for line in lines:
            if 'Disk /dev/s' in line:
                print(line)

    except subprocess.CalledProcessError as e:
        print(f"Error: {e}")

def input_password():
    """
    User to provide a password twice, and the must be identical
    """

    password = getpass.getpass(f"{YELLOW}Please provide a password to protect the secret key partition: {END}")
    password2 = getpass.getpass(f"{YELLOW}Please repeat the password: {END}")
    if password == password2:
        if len(password)<9:
            if input(f"{YELLOW}The password provided is very short. Do you wish to continue (y/n)?{END}") != "y":
                return None
        return password
    else:
        return None

def disk_partition_secret(disk, gnupghome, password):
    """
    After selecting an available disk it will be partitions in two parts:
    1. A LUKS partition - where the secret keys will be stored
    2. A standard partition - where the public keys will be stoted
    This function created the Luks partition and copies the secret keys
    """
    luks_mounted = True
    luks_open = True
    luks_folder = True

    try:

        if input(f"{RED}\nAll data on {END}" + disk + f"{RED} will be deleted. Continue (y/n)?{END}") != "y":
            exit()

        print(f"{YELLOW}\nCreating new partiton table ...{END}")
        commands = f"g\nw"
        subprocess.run(["fdisk", str(disk)], input =f"{commands}", stderr = subprocess.PIPE, text=True, check=True)

        print(f"{YELLOW}\nCreating partiton 20Mb for LUKS vault ...{END}")
        commands = f"n\n\n\n+20M\nw"
        luks_folder = subprocess.run(["fdisk", str(disk)], input =f"{commands}", stderr = subprocess.PIPE, text=True, check=True)
        partition_luks = disk + "1"

        print(f"{YELLOW}\nFormatting the LUKS partition ...{END}")
        subprocess.run(["cryptsetup", "-q", "luksFormat", str(partition_luks)], input =f"{password}", stderr = subprocess.PIPE, text=True, check=True)

        print(f"{YELLOW}\nMounting the LUKS partition ...{END}")
        luks_open = subprocess.run(["cryptsetup", "-q", "luksOpen", str(partition_luks), "gnupg-secrets"], input =f"{password}", stderr = subprocess.PIPE, text=True, check=True)

        print(f"{YELLOW}\nCreating ext2 filesystem on LUKS partition ...{END}")
        subprocess.run(["mkfs.ext2", "/dev/mapper/gnupg-secrets", "-L", "GNUPG"], stderr = subprocess.PIPE, text=True, check=True)

        print(f"{YELLOW}\nMount the filesystem on LUKS partition ...{END}")
        if os.path.exists("/mnt/vault") is True:
            subprocess.run(["rm", "-rf", "/mnt/vault"], stderr = subprocess.PIPE, text=True, check=True)
        subprocess.run(["mkdir", "/mnt/vault"], stderr = subprocess.PIPE, text=True, check=True)
        luks_mounted = subprocess.run(["mount", "/dev/mapper/gnupg-secrets", "/mnt/vault"], stderr = subprocess.PIPE, text=True, check=True)

        print(f"{YELLOW}\nCopy GNUPG secret keys and revocation certificate ...{END}")
        subprocess.run(["cp", "-av", str(gnupghome), "/mnt/vault"], stderr = subprocess.PIPE, text=True, check=True)

    except subprocess.CalledProcessError as e:
        print(f"{RED}An error occured copying the GnuPG keychain: {END}\n")
        print(e)

    finally:
            print(f"{YELLOW}\nCleaning up the Secret partition.{END}")
            if luks_mounted is False: subprocess.run(["umount", "/mnt/vault"], stderr = subprocess.PIPE, text=True, check=True)
            if luks_open is False: subprocess.run(["cryptsetup", "luksClose", "gnupg-secrets"], stderr = subprocess.PIPE, text=True, check=True)
            if luks_folder is False: subprocess.run(["rm", "-rf", "mnt/vault/"], stderr = subprocess.PIPE, text=True, check=True)

def disk_partition_public(disk, pubkey):
    """
    After selecting an available disk it will be partitions in two parts:
    1. A LUKS partition - where the secret keys will be stored
    2. A standard partition - where the public keys will be stoted
    This function created the standard partition
    """

    public_mounted = True
    public_folder = True

    try:
        if True:
            print(f"{YELLOW}\nCreating partiton 40Mb for public keys ...{END}")
            commands = f"n\n\n\n+40M\nw"
            subprocess.run(["fdisk", str(disk)], input =f"{commands}", stderr = subprocess.PIPE, text=True, check=True)
            partition_public = disk + "2"

            print(f"{YELLOW}\nCreating ext2 filesystem on public partition ...{END}")
            subprocess.run(["mkfs.ext2", partition_public, "-L", "PUBLIC"], stderr = subprocess.PIPE, text=True, check=True)

            print(f"{YELLOW}\nMount the filesystem on public partition ...{END}")
            if os.path.exists("/mnt/public") is True:
                subprocess.run(["rm", "-rf", "/mnt/public"], stderr = subprocess.PIPE, text=True, check=True)
            public_folder = subprocess.run(["mkdir", "/mnt/public"], stderr = subprocess.PIPE, text=True, check=True)
            public_mounted =  subprocess.run(["mount", partition_public, "/mnt/public"], stderr = subprocess.PIPE, text=True, check=True)

            print(f"{YELLOW}\nCopy GNUPG public keys ...{END}")
            subprocess.run(["cp", pubkey, "/mnt/public"], stderr = subprocess.PIPE, text=True, check=True)

            print(f"{YELLOW}\nChanging public key to read-only.{END}")
            pub_file = os.path.basename(pubkey)
            pub_path = os.path.join("/mnt/public/", pub_file )
            subprocess.run(["chmod", "0444", pub_path], stderr = subprocess.PIPE, text=True, check=True)

    except subprocess.CalledProcessError as e:
        print(f"{RED}An error occured copying the GnuPG public key: {END}\n")
        print(e)

    finally:
            print(f"{YELLOW}\nCleaning up the public partition.{END}")
            if public_mounted is False: subprocess.run(["umount", "/mnt/public"], stderr = subprocess.PIPE, text=True, check=True)
            if public_folder is False:  subprocess.run(["rm", "-rf", "mnt/public/"], stderr = subprocess.PIPE, text=True, check=True)

def main():
    parser = argparse.ArgumentParser(
        description='Backup GnuPG private and public keys to USB backup drive.\n\n'
                    'This script requires three required argumenents.\n'
                    '1. The full path to the GnuPG keychain is stored ($GNUPGHOME).\n'
                    '2. The full path to the public key in armored format ~public-key.asc~.\n'
                    '3. The path to the USB device in ~/dev/sdx~ format.\n'
                    '   Use the ~lsblk~ command to list available USB devices.\n'
                    'This script must be executed as root ~sudo gpg-backup~.\n'
                    'Only run this on a secure and trusted system.',
        epilog='''Backup GnuPG keys to USB device example:
        sudo ./gpgbackup.py $GNUPGHOME public.asc /dev/sbx
        ''',
        formatter_class=argparse.RawDescriptionHelpFormatter)

    parser.add_argument('gnupghome', type=str,
                        help="path to the GnuPG path")
    parser.add_argument('pubkey', type=str,
                        help="Public key exported using ~ gpg -a --export public.asc")
    parser.add_argument('usb', type=str,
                        help="path to the USB device in /dev/sdx format")
    args = parser.parse_args()

    os.system("reset")
    print(f"{YELLOW}====================================================={END}")
    print(f"{YELLOW} GPG Key Backup to USB Drive: {END}" + args.usb)
    print(f"{YELLOW}====================================================={END}")

    # Ensure the sript is executed as root / sudo
    if os.geteuid() != 0:
        print(f"{RED}This script must be executed as root{END}")
        exit()

    # Ensure the GnuPG directory exists and is valid
    if os.path.exists(args.gnupghome) is False:
        print(f"{RED}GnuPG path provided does not exist!{END}")
        exit()

    if os.path.isfile(os.path.join(args.gnupghome, "trustdb.gpg")) is False:
        print(f"{RED}GnuPG path provided is not a valid GnuPG folder!{END}")
        exit()

    pass_luks = input_password()
    if pass_luks is None:
        print(f"{RED}Password for secret key partition is not identical!{END}")
        exit()

     # Display disks for verification
    disk_list()

    if os.path.exists(args.usb) is False:
        print(f"{RED}USB provided is not connected or does not exist!{END}")
        exit()

    disk_partition_secret(args.usb, args.gnupghome, pass_luks)
    disk_partition_public(args.usb, args.pubkey)

    print(f"{GREEN}\nAll Done. Remove the USB device, and store it in a save location.{END}")
    print(f"{GREEN}The USB has now two partitions:{END}")
    print(f"{GREEN}a. An encrypted partition created with LUKS that contains the complete GNUPGHOME content and exporte key files.{END}")
    print(f"{GREEN}b. An standard partition that contains the exported public key file for distribution and publication.{END}")
    print(f"{GREEN}   This partition also contains the scripts in case a reverse engineering is required!{END}")

if __name__ == "__main__":
    main()
