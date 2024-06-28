#!/usr/bin/env python3

import os
import argparse
import subprocess
import tempfile
import getpass

BLACK = "\033[0;30m"
RED = "\033[0;31m"
GREEN = "\033[0;32m"
BLUE = "\033[0;34m"
YELLOW = "\033[0;93m"
END = "\033[0m"

def message_start():
    os.system("reset")
    print(f"{GREEN}================================================================{END}")
    print(f"{GREEN} Restore GnuPG Key-chain from USB Drive: {END}")
    print(f"{GREEN}================================================================{END}")
    print(f"{YELLOW}Note: you likely want to execute this script on a Live Arch ISO!{END}")

def message_complete(path_private):
    print(f"{GREEN}\n====================================================={END}")
    print(f"{GREEN} Restore of GPG Key Backup from  USB completed. {END}")
    print(f"{GREEN}====================================================={END}")
    print(f"{YELLOW}Remove the USB device, and store it in a save location.{END}")
    print(f"{YELLOW}a. The GnuPG key has been restored to: {END}" + path_private)
    print(f"{YELLOW}b. It might be required to take ownership if the secret partition with: sudo chown -R user:user ~/tmp/gpx_xxxxx~{END}")
    print(f"{YELLOW}\nYou have now several options of using the restored gpg data:{END}")
    print(f"{YELLOW}1. Import the secret keys on the harddrive (not recommended) with: ~gpg --import /tmp/gpg_xxx/xxx.private.subkeys.asc~{END}")
    print(f"{YELLOW}2. Move the imported secret keys to a YubiKey, or{END}")
    print(f"{YELLOW}3. Move the imported secret keys to an OnlyKey{END}")
    print(f"{YELLOW}4. Reboot the machine to remove all data.{END}")

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

def input_password():
    """
    User to provide a password
    Return password if valid
    """
    return getpass.getpass(f"{YELLOW}Please provide the password to unlock the secret partition: {END}")

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

def create_gnupghome():
    """
    Create a temporary directory which will be cleared on reboot,
    and configure it as the hardened GnuPG directory.
    """
    with tempfile.TemporaryDirectory(prefix="gpg_", delete=False) as GNUPGHOME:
        return GNUPGHOME

def copy_folder(source, destination):
    """
    Copy folder from ~source~ to ~destination~
    Return True if successful
    Return False if not successful
    """

    copy_folder = False

    try:
        print(f"{GREEN}[ * ] Copying folder from: {END}" + source + f"{GREEN} to {END}" + destination)
        subprocess.run(["cp", "-a", os.path.join(source, "."), destination], stderr = subprocess.PIPE, stdout = subprocess.DEVNULL, text=True, check=True)
        copy_folder = True
    except subprocess.CalledProcessError as err:
        print(f"{RED}Could not copy folder from: {END}" + source + f"{RED} to {END}" + destination)
        print(err)
    finally:
        return copy_folder

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

def main():

    parser = argparse.ArgumentParser(
        description='Restore the GnuPG private and/or public keys from USB backup drive.\n\n'
                    'The following arguments are available:\n'
                    '1. The connected USB device in ~sdx~ format.\n'
                    '   Use the ~lsblk~ command to list available USB devices.\n'
                    '2. Optionally include the private private key data.\n\n'
                    'This script must be executed as root ~sudo ./gpg-restore-from-usb.py~.\n'
                    'Only run this on a secure and trusted system, like a live Arch Linux ISO.',
        epilog='''Restore GnuPG keys from backup USB device example:
        sudo ./gpg-restore-from-usb.py --private sda
        ''',
        formatter_class=argparse.RawDescriptionHelpFormatter)

    parser.add_argument('usb', type=str,
                        help="Path to the USB device in sdx format")
    parser.add_argument('--private', action='store_true',
                        help="Mount the private key partition")
    args = parser.parse_args()

    USB_DRIVE = None
    LUKS_PARTITION = None
    LUKS_FOLDER = None

    message_start()

    # Validate if executed as sudo
    if is_sudo() == False: exit()

    # Validate correct inputs
    USB_DRIVE = is_usb_drive(args.usb)
    if USB_DRIVE is None: exit()

    # Restore the private partition (public keys and private keys)
    if args.private:
        LUKS_PASSWORD = input_password()
        PARTITION_SECRET = USB_DRIVE + str(1)

        LUKS_PARTITION = luks_open(PARTITION_SECRET, "SECRET", LUKS_PASSWORD)
        if LUKS_PARTITION is None: exit()

        if folder_remove("/mnt/private") is False: exit()

        LUKS_FOLDER = folder_create("/mnt/private")
        if LUKS_FOLDER is None: exit()

        LUKS_MOUNTED = partition_mount(LUKS_PARTITION, LUKS_FOLDER)
        if LUKS_MOUNTED is False: exit()

        PATH_GPG = create_gnupghome()
        if PATH_GPG is None: exit()

        COPY_PRIVATE = copy_folder("/mnt/private", PATH_GPG)
        if COPY_PRIVATE is False: ext()

        # Cleanup Secret partiton
        if LUKS_MOUNTED is True: partition_umount(LUKS_FOLDER)
        if LUKS_MOUNTED is True: folder_remove(LUKS_FOLDER)
        if LUKS_PARTITION is not None: luks_close(LUKS_PARTITION)

    # restore the public partition (public keys)
    else:
        # Mount Public partition only
        PARTITION_PUBLIC = USB_DRIVE + str(2)

        if folder_remove("/mnt/public") is False: exit()

        PUBLIC_FOLDER = folder_create("/mnt/public")
        if PUBLIC_FOLDER is None: exit()

        PUBLIC_MOUNTED = partition_mount(PARTITION_PUBLIC, PUBLIC_FOLDER)
        if PUBLIC_MOUNTED is False: exit()

        PATH_GPG = create_gnupghome()
        if PATH_GPG is None: exit()

        COPY_PUBLIC = copy_folder("/mnt/public", PATH_GPG)
        if COPY_PUBLIC is False: ext()

        # Cleanup Public partiton
        if PUBLIC_MOUNTED is True: partition_umount(PUBLIC_FOLDER)
        if PUBLIC_MOUNTED is True: folder_remove(PUBLIC_FOLDER)

    message_complete(PATH_GPG)

if __name__ == "__main__":
    main()
