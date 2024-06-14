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
    print(f"{YELLOW}The USB contains two partitions:{END}")
    print(f"{YELLOW}a. An encrypted partition - created with LUKS - that contains the complete GNUPGHOME content and exported key files.{END}")
    print(f"{YELLOW}b. A standard partition that contains the exported public key file for distribution and publication.{END}")
    print(f"{YELLOW}   This partition also contains the scripts in case a reverse engineering is required!{END}")

def is_sudo():
    """
    Check if executed with root priviledges
    Return True if root priviledges
    Return False if no root priviledges
    """
    if os.getuid() != 0:
        print(f"{RED} This script must be executed with root priviledges (sudo){END}")
        return False

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
    Validate is ~pubkey~ is a valid GnuPG public key (rudimentary)
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

def folder_create(folder):
    """
    Create a folder.
    Return folder path if successful
    Return None of not successful
    """

    folder_create = None

    try:
        print(f"{GREEN}[ * ] Creating folder {END}" + folder)
        subprocess.run(["mkdir", folder], stderr = subprocess.PIPE, stdout = subprocess.DEVNULL, text=True, check=True)
        folder_create = folder
    except subprocess.CalledProcessError as err:
        print(f"{RED}Could not create folder: {END}" + folder)
        print(err)
    finally:
        return folder_create

def folder_remove(folder):
    """
    Remove a folder.
    If the folder exists, get confirmation on removal prior.
    Return True if successful
    Return False of not successful
    """

    folder_remove = False

    try:
        # Remove before creation
        if os.path.exists(folder) is True:
            print(f"{GREEN}[ * ] Removing folder: {END}" + folder)
            subprocess.run(["rm", "-rf", folder], stderr = subprocess.PIPE, stdout = subprocess.DEVNULL, text=True, check=True)
            folder_remove = True
        else:
            folder_remove = True

    except subprocess.CalledProcessError as err:
        print(f"{RED}Could not remove folder: {END}" + folder)
        print(err)
    finally:
        return folder_remove

def copy_folder(source, destination):
    """
    Copy folder from ~source~ to ~destination~
    Return True if successful
    Return False if not successful
    """

    copy_folder = False

    try:
        print(f"{GREEN}[ * ] Copying folder from: {END}" + source + f"{GREEN} to {END}" + destination)
        subprocess.run(["cp", "-av", source, destination], stderr = subprocess.PIPE, stdout = subprocess.DEVNULL, text=True, check=True)
        copy_folder = True
    except subprocess.CalledProcessError as err:
        print(f"{RED}Could not copy folder from: {END}" + source + f"{RED} to {END}" + destination)
        print(err)
    finally:
        return copy_folder

def copy_file(source, destination):
    """
    Copy file from ~source~ to ~destination~
    Return True if successful
    Return False if not successful
    """

    copy_file = False

    pubkey_file = os.path.basename(source)
    pubkey_path = os.path.join(destination, pubkey_file )
    try:
        print(f"{GREEN}[ * ] Copying file from: {END}" + source + f"{GREEN} to {END}" + destination)
        subprocess.run(["cp", source, destination], stderr = subprocess.PIPE, stdout = subprocess.DEVNULL, text=True, check=True)
        subprocess.run(["chmod", "0444", pubkey_path], stderr = subprocess.PIPE, stdout = subprocess.DEVNULL, text=True, check=True)
        copy_file = True
    except subprocess.CalledProcessError as err:
        print(f"{RED}Could not copy file from: {END}" + source + f"{RED} to {END}" + destination)
        print(err)
    finally:
        return copy_file

def partition_create(device, partition_no, size):
    """
    Create a new partition on devices
    Return partition path if successful
    Return None not successful
    """

    partition = None

    if partition_no == 1:
        print(f"{GREEN}[ * ] Creating new partition table for: {END}" + device)
        commands = f"g\nw"
        subprocess.run(["fdisk", str(device)], input =f"{commands}", stderr = subprocess.PIPE, stdout = subprocess.DEVNULL, text=True, check=True)

    try:
        print(f"{GREEN}[ * ] Creating partition: {END}" + device + str(partition_no))
        #commands = f"n\n\n\n+20M\nw"
        commands = f"n\n\n\n+" + size + "\nw"
        subprocess.run(["fdisk", str(device)], input =f"{commands}", stderr = subprocess.PIPE, stdout = subprocess.DEVNULL, text=True, check=True)
        partition = device + str(partition_no)
    except subprocess.CalledProcessError as err:
        print(f"{RED}Could not create partition: {END}" + str(partition_no))
        print(err)
    finally:
        return partition

def luks_create(partition, password):
    """
    Create a LUKS partition
    Return True if successful
    Return False if not successful
    """

    luks_create = False

    try:
        print(f"{GREEN}[ * ] Creating LUKS partition: {END}" + partition)
        subprocess.run(["cryptsetup", "-q", "luksFormat", str(partition)], input =f"{password}", stderr = subprocess.PIPE, stdout = subprocess.DEVNULL, text=True, check=True)
        luks_create = True
    except subprocess.CalledProcessError as err:
        print(f"{RED}Could not create LUKS partition: {END}" + partition)
        print(err)
    finally:
        return luks_create

def luks_open(partition, lukslabel, password):
    """
    Open a LUKS partition
    Return LUKS partition if successful
    Return None if not successful
    """

    luks_open = None

    try:
        print(f"{GREEN}[ * ] Opening LUKS partition: {END}" + lukslabel)
        subprocess.run(["cryptsetup", "-q", "luksOpen", str(partition), lukslabel], input =f"{password}", stderr = subprocess.PIPE, stdout = subprocess.DEVNULL, text=True, check=True)
        luks_open = "/dev/mapper/" + lukslabel
    except subprocess.CalledProcessError as err:
        print(f"{RED}Could not open LUKS partition: {END}" + partition)
        print(err)
    finally:
        return luks_open

def luks_close(partition):
    """
    Close a LUKS partition
    Return True if successful
    Return False if not successful
    """

    luks_close = False

    try:
        print(f"{GREEN}[ * ] Closing LUKS partition: {END}" + partition)
        subprocess.run(["cryptsetup", "luksClose", str(partition)], stderr = subprocess.PIPE, stdout = subprocess.DEVNULL, text=True, check=True)
        luks_close = True
    except:
        print(f"{RED}Could not close LUKS partition: {END}" + partition)
    finally:
        return luks_close

def partition_mount(partition, mountfolder):
    """
    Mount ~partition~ to ~mountfolder~
    Return True if successful
    Return False if not successful
    """

    mounted = False

    try:
        print(f"{GREEN}[ * ] Mounting partition: {END}" + partition + f"{GREEN} to {END}" + mountfolder)
        subprocess.run(["mount", partition, mountfolder], stderr = subprocess.PIPE, stdout = subprocess.DEVNULL, text=True, check=True)
        mounted = True
    except subprocess.CalledProcessError as err:
        print(f"{RED}Could not mount partition: {END}" + partition + f"{RED} to {END}" + mountfolder)
        print(err)
    finally:
        return mounted

def partition_umount(mountfolder):
    """
    Un-mount ~partition~
    Return True if successful
    Return False if not successful
    """

    partition_umount = False
    try:
        print(f"{GREEN}[ * ] Unmounting partition: {END}" + mountfolder)
        subprocess.run(["umount", mountfolder], stderr = subprocess.PIPE, stdout = subprocess.DEVNULL, text=True, check=True)
        partition_umount = True
    except subprocess.CalledProcessError as err:
        print(f"{RED}Could not un-mount folder: {END}" + mountfolder)
        print(err)
    finally:
        return partition_umount

def partition_format(format, partition, label):
    """
    Format partition
    Return True if successful
    Return False if not successful
    """

    partition_format = False

    try:
        print(f"{GREEN}[ * ] Formatting partition: {END}" + partition)
        subprocess.run([format, partition, "-L", label], stderr = subprocess.PIPE, stdout = subprocess.DEVNULL, text=True, check=True)
        partition_format = True
    except subprocess.CalledProcessError as err:
        print(f"{RED}Could not format partition: {END}" + partition)
        print(err)
    finally:
        return partition_format

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

    GNUPG_COPIED = False
    PUBLIC_COPIED = False
    LUKS_PASSWORD = None
    LUKS_CREATED = False
    LUKS_PARTITION = None
    LUKS_FORMATTED = False
    LUKS_MOUNTED = False
    LUKS_FOLDER = None
    PARTITION_SECRET = None
    PARTITION_PUBLIC = None
    USB_DRIVE = None

    message_start()

    # Validate if executed as sudo
    if is_sudo() == False: exit()

    # Validate correct inputs
    USB_DRIVE = is_usb_drive(args.usb)
    if USB_DRIVE is None: exit()
    if is_gpg_path(args.gnupghome) is False: exit()
    if is_public_key(args.pubkey) is False: exit()

    if input(f"{RED}\nAll data on {END}" + USB_DRIVE + f"{RED} will be deleted. Continue (y/n)?{END}") != "y":
        exit()

    # Create Secret partition and copy gnupghome content
    LUKS_PASSWORD = input_password(8)
    if LUKS_PASSWORD is None: exit()

    print(f"\n{GREEN}Archiving GNUPGHOME in LUKS partition on USB.{END}")
    print(f"{GREEN}============================================={END}")

    PARTITION_SECRET = partition_create(USB_DRIVE, 1, "50M")
    if PARTITION_SECRET is None: exit()

    LUKS_CREATED = luks_create(PARTITION_SECRET, LUKS_PASSWORD)
    if LUKS_CREATED is False: exit()

    LUKS_PARTITION = luks_open(PARTITION_SECRET, "SECRET", LUKS_PASSWORD)
    if LUKS_PARTITION is None: exit()

    LUKS_FORMATTED =  partition_format("mkfs.ext2", LUKS_PARTITION, "SECRET")
    if LUKS_FORMATTED is False: exit()

    if folder_remove("/mnt/secret") is False: exit()

    LUKS_FOLDER = folder_create("/mnt/secret")
    if LUKS_FOLDER is None: exit()

    LUKS_MOUNTED = partition_mount(LUKS_PARTITION, LUKS_FOLDER)
    if LUKS_MOUNTED is False: exit()

    GNUPG_COPIED = copy_folder(args.gnupghome, LUKS_FOLDER)
    if GNUPG_COPIED is False: exit()

    # Cleanup Secret partiton
    if LUKS_MOUNTED is True: partition_umount(LUKS_FOLDER)
    if LUKS_MOUNTED is True: folder_remove(LUKS_FOLDER)
    if LUKS_PARTITION is not None: luks_close(LUKS_PARTITION)

    print(f"\n{GREEN}Copying GNUPG public key to partition on USB.{END}")
    print(f"{GREEN}============================================={END}")

    PARTITION_PUBLIC = partition_create(USB_DRIVE, 2, "50M")
    if PARTITION_PUBLIC is None: exit()

    PUBLIC_FORMATTED =  partition_format("mkfs.ext2", PARTITION_PUBLIC, "PUBLIC")
    if PUBLIC_FORMATTED is False: exit()

    if folder_remove("/mnt/public") is False: exit()

    PUBLIC_FOLDER = folder_create("/mnt/public")
    if PUBLIC_FOLDER is None: exit()

    PUBLIC_MOUNTED = partition_mount(PARTITION_PUBLIC, PUBLIC_FOLDER)
    if PUBLIC_MOUNTED is False: exit()

    # Do something
    PUBLIC_COPIED = copy_file(args.pubkey, PUBLIC_FOLDER)
    if PUBLIC_COPIED is False: exit()

    # Cleanup Secret partiton
    if PUBLIC_MOUNTED is True: partition_umount(PUBLIC_FOLDER)
    if PUBLIC_MOUNTED is True: folder_remove(PUBLIC_FOLDER)

    message_complete()

if __name__ == "__main__":
    main()
