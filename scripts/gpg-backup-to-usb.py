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

def message_start():
    os.system("reset")
    print(f"{GREEN}====================================================={END}")
    print(f"{GREEN} Backup GnuPG Key-chain to USB Drive: {END}")
    print(f"{GREEN}====================================================={END}")

def message_complete():
    print(f"{GREEN}\n====================================================={END}")
    print(f"{GREEN} GPG Key Backup to USB Drive completed successfully. {END}")
    print(f"{GREEN}====================================================={END}")
    print(f"{YELLOW}Remove the USB device, and store it in a save location.{END}")
    print(f"{YELLOW}The USB has now two partitions:{END}")
    print(f"{YELLOW}a. An encrypted partition created with LUKS that contains the complete GNUPGHOME content and exporte key files.{END}")
    print(f"{YELLOW}b. An standard partition that contains the exported public key file for distribution and publication.{END}")
    print(f"{YELLOW}   This partition also contains the scripts in case a reverse engineering is required!{END}")

def is_usb_drive(usb):
    """
    Validate if ~usb~ is in xxx format without the backslash and dev.
    Returns a fully qualified path to a disk ~/dev/disk/~
    Returns None if the disk does not exist.
    """

    # Ensure drives are provided plain
    if "/" in usb:
        print(f"{RED}Provide a drive as ~sdx~")
        return None

    path = os.path.join("/", "dev", usb)
    if  os.path.exists(path) is True:
        return path
    else:
        print(f"{RED}Drive " + usb + f" does not exist or is not connected{END}")
        return None

def is_gpg_path(gnupghome):
    """
    Validate if ~gnupghome~ is a valid GnuPG folder
    Return True if it is
    Return False if it is not
    """
    if os.path.exists(gnupghome) is False:
        print(f"{RED}GnuPG path provided does mot exist!{END}")
        return False
    if os.path.isfile(os.path.join(gnupghome, "trustdb.gpg")) is False:
        print(f"{RED}GnuPG path provided is not a valid GnuPG folder!{END}")
        return False
    return True

def is_public_key(pubkey):
    """
    Validate is ~pubkey~ is a valid GnuPG public key
    Return True if it is
    Return False if it is not
    """
    if os.path.isfile(pubkey) is False:
        print(f"{RED}Public key provided is not a file!{END}")
        return False
    return True

def input_password(length):
    """
    User to provide a password twice, and both must be identical
    Password must have ~length~ size
    Return password if valid
    Return None is not valid
    """

    password = getpass.getpass(f"{YELLOW}Please provide a password to protect the secret key partition: {END}")
    password2 = getpass.getpass(f"{YELLOW}Please repeat the password: {END}")
    if password == password2:
        if len(password) < length:
            if input(f"{YELLOW}The password provided is very short. Do you wish to continue (y/n)?{END}") != "y":
                return None
        return password
    else:
        print(f"{RED}Passwords entered are not identical!{END}")
        return None

def partition_create(device, partition_no):
    """
    Create a new partition on devices
    Return partition path if successfull
    Return None not successfull
    """

    partiton = None

    if input(f"{RED}\nAll data on {END}" + device + f"{RED} will be deleted. Continue (y/n)?{END}") != "y":
        return None

    if partition_no == 1:
        print(f"{GREEN}\nCreating new partiton table ...{END}")
        commands = f"g\nw"
        subprocess.run(["fdisk", str(device)], input =f"{commands}", stderr = subprocess.PIPE, text=True, check=True)

    try:
        print(f"{GREEN}\nCreating partiton 20Mb for LUKS secret ...{END}")
        commands = f"n\n\n\n+20M\nw"
        subprocess.run(["fdisk", str(device)], input =f"{commands}", stderr = subprocess.PIPE, text=True, check=True)
        partition = device + partition_no
    except:
        print(f"{RED}Could not create partition: {END}" + str(partiton_no))
    finally:
        return partition

def partition_mount_luks(partiton, vaultname, password):
    """
    Format and mount a partition in LUKS
    Return LUKS path if successfull
    Return None if not successfull
    LUKS"""

    luks = None

    try:
        print(f"{GREEM}\nFormatting LUKS partiton ...{END}")
        subprocess.run(["cryptsetup", "-q", "luksFormat", str(partition)], input =f"{password}", stderr = subprocess.PIPE, text=True, check=True)

        print(f"{GREEM}\nMounting LUKS partition ...{END}")
        subprocess.run(["cryptsetup", "-q", "luksOpen", str(partition), vaultname], input =f"{password}", stderr = subprocess.PIPE, text=True, check=True)
        luks = "/dev/mapper/" + vaultname
    except:
        print(f"{RED}Could not mount LUKS partition: {END}" + partition)
    finally:
        return luks

def partiton_format(format, partition, name):
    """
    Format partition
    Return True if successfull
    Return False if not successfull
    """

    format = False

    try:
        print(f"{GREEN}\nFormatting partition ...{END}")
        subprocess.run([format, partition, "-L", name], stderr = subprocess.PIPE, text=True, check=True)
        format = True
    except:
        print(f"{RED}Could not format partition: {END}" + partition)
    finally:
        return format

def old_stuff(device, partition_no, password):
    """
    Create a LUKS partiton on ~device~
    Return full path if successfull
    Return None is not succesfull
    """

    luks_is_mounted = False
    luks_is_open = False
    luks_has_folder = False

    try:
        # if input(f"{RED}\nAll data on {END}" + device + f"{RED} will be deleted. Continue (y/n)?{END}") != "y":
        #     return None:

        # print(f"{GREEN}\nCreating new partiton table ...{END}")
        # commands = f"g\nw"
        # subprocess.run(["fdisk", str(device)], input =f"{commands}", stderr = subprocess.PIPE, text=True, check=True)

        # print(f"{GREEN}\nCreating partiton 20Mb for LUKS secret ...{END}")
        # commands = f"n\n\n\n+20M\nw"
        # if subprocess.run(["fdisk", str(device)], input =f"{commands}", stderr = subprocess.PIPE, text=True, check=True)
        # partition_luks = device + partition_no

        # print(f"{GREEM}\nFormatting the LUKS partition ...{END}")
        # subprocess.run(["cryptsetup", "-q", "luksFormat", str(partition_luks)], input =f"{password}", stderr = subprocess.PIPE, text=True, check=True)

        # print(f"{GREEM}\nMounting the LUKS partition ...{END}")
        # luks_open = subprocess.run(["cryptsetup", "-q", "luksOpen", str(partition_luks), "gnupg-secret"], input =f"{password}", stderr = subprocess.PIPE, text=True, check=True)

        print(f"{GREEN}\nCreating ext2 filesystem on LUKS partition ...{END}")
        subprocess.run(["mkfs.ext2", "/dev/mapper/gnupg-secret", "-L", "GNUPG"], stderr = subprocess.PIPE, text=True, check=True)

        print(f"{GREEM}\nMount the filesystem on LUKS partition ...{END}")
        if os.path.exists("/mnt/secret") is True:
            subprocess.run(["rm", "-rf", "/mnt/secret"], stderr = subprocess.PIPE, text=True, check=True)
        subprocess.run(["mkdir", "/mnt/secret"], stderr = subprocess.PIPE, text=True, check=True)
        luks_mounted = subprocess.run(["mount", "/dev/mapper/gnupg-secret", "/mnt/secret"], stderr = subprocess.PIPE, text=True, check=True)

        print(f"{YELLOW}\nCopy GNUPG secret keys and revocation certificate ...{END}")
        subprocess.run(["cp", "-av", str(gnupghome), "/mnt/secret/"], stderr = subprocess.PIPE, text=True, check=True)

    except subprocess.CalledProcessError as error:
        print(f"{RED}An error occured creating the secret partiton: {END}\n")
        print(error)

    finally:
            print(f"{YELLOW}\nCleaning up the Secret partition.{END}")
            if luks_mounted is False: subprocess.run(["umount", "/mnt/secret"], stderr = subprocess.PIPE, text=True, check=True)
            if luks_open is False: subprocess.run(["cryptsetup", "luksClose", "gnupg-secret"], stderr = subprocess.PIPE, text=True, check=True)
            if luks_folder is False: subprocess.run(["rm", "-rf", "/mnt/secret/"], stderr = subprocess.PIPE, text=True, check=True)

    return drive_path


def main():

    parser = argparse.ArgumentParser(
        description='Backup GnuPG private and public keys to USB backup drive.\n\n'
                    'This script requires three required argumenents.\n'
                    '1. The connected USB device in ~sdx~ format.\n'
                    '   Use the ~lsblk~ command to list available USB devices.\n'
                    '2. The full path to the GnuPG keychain is stored ($GNUPGHOME).\n'
                    '3. The full path to the public key in armored format ~public-key.asc~.\n'
                    'This script must be executed as root ~sudo gpg-backup~.\n'
                    'Only run this on a secure and trusted system.',
        epilog='''Backup GnuPG keys to USB device example:
        sudo ./gpgbackup.py sda $GNUPGHOME public.asc
        ''',
        formatter_class=argparse.RawDescriptionHelpFormatter)

    parser.add_argument('usb', type=str,
                        help="path to the USB device in sdx format")
    parser.add_argument('gnupghome', type=str,
                        help="path to the GnuPG path")
    parser.add_argument('pubkey', type=str,
                        help="Public key exported using ~ gpg -a --export public.asc")
    args = parser.parse_args()

    USB_DRIVE = None
    LUKS_PASSWORD = None
    LUKS_PARTITION = None
    PUBLIC_PARTITON = None

    message_start()

    # Validate correct inputs
    USB_DRIVE = is_usb_drive(args.usb)
    if  USB_DRIVE is None: exit()
    if is_gpg_path(args.gnupghome) is False: exit()
    if is_public_key(args.pubkey) is False: exit()


    # Password for secret LUKS partition
    LUKS_PASSWORD = input_password(8)
    if LUKS_PASSWORD is None: exit()

    # Create partitions
    LUKS_PARTITION = partition_create(USB_DRIVE, 1)
    if LUKS_PARTITION is None: exit()
    PUBLIC_PARTITON = create_partiton(USB_DRIVE, 2)
    if PUBLIC_PARTITON is None: exit()

    # Mount LUKS partition
    LUKS_VAULT = partition_mount_luks(LUKS_PARTITION, "VAULT", LUKS_PASSWORD)
    if LUKS_VAULT is None: exit()

    # Formatting partitions
    if partiton_format("mkfs.ext2", LUKS_VAULT, "SECRET") is False: exit()

    message_complete()

if __name__ == "__main__":
    main()
