#!/usr/bin/env python3

import subprocess
import getpass

BLACK = "\033[0;30m"
RED = "\033[0;31m"
GREEN = "\033[0;32m"
BLUE = "\033[0;34m"
YELLOW = "\033[0;93m"
END = "\033[0m"

#sudo = getpass.getpass("please enter your root pass: ")

def disk_list():
    try:
        output = subprocess.check_output(["sudo", "fdisk","-l"]).decode("utf-8")
        lines = output.split('\n')

        print(f"{YELLOW}\nAvailable disks:{END}")

        count = 0
        for line in lines:
            if 'Disk /dev/s' in line:
                print(line)

    except subprocess.CalledProcessError as e:
        print(f"Error: {e}")

def disk_partition():
    """
    After selecting an available disk it will be partitions in two parts:
    1. A LUKS partition - where the secret keys will be stored
    2. A standard partition - where the public keys will be stoted
    """
    disk = input(f"{YELLOW}\nPlease type the drive name to use for PGP Key Backup (/dev/sdb): {END}")
    if input(f"{RED}All data on the disk {END}" + str(disk) + f"{RED} will be deleted. Continue (y/n)?{END}") == "y":
        print(f"{YELLOW}Partitioning ..{END}")

        print(f"{YELLOW}\nCreating new partiton table ...{END}")
        sudo = "123"
        commands = f"g\nw"
        subprocess.run(["sudo", "fdisk", str(disk)], input =f"{sudo}\n{commands}", stderr = subprocess.PIPE, text=True, check=True)

        print(f"{YELLOW}\nCreating new partiton table for LUKS vault ...{END}")
        commands = f"n\n\n\n+20M\nw"
        subprocess.run(["sudo", "fdisk", str(disk)], input =f"{sudo}\n{commands}", stderr = subprocess.PIPE, text=True, check=True)
        partition_luks = disk + "1"

        print(f"{YELLOW}\nFormatting the LUKS partition ...{END}")
        pass_luks = "123"
        subprocess.run(["sudo", "cryptsetup", "-q", "luksFormat", str(partition_luks)], input =f"{sudo}\n{pass_luks}", stderr = subprocess.PIPE, text=True, check=True)

        print(f"{YELLOW}\nMounting the LUKS partition ...{END}")
        subprocess.run(["sudo", "cryptsetup", "-q", "luksOpen", str(partition_luks), "gnupg-secrets"], input =f"{sudo}\n{pass_luks}", stderr = subprocess.PIPE, text=True, check=True)

        print(f"{YELLOW}\nCreating ext2 filesystem on LUKS partition ...{END}")
        subprocess.run(["sudo", "mkfs.ext2", "/dev/mapper/gnupg-secrets", "-L", "GNUPG"], input =f"{sudo}", stderr = subprocess.PIPE, text=True, check=True)

        print(f"{YELLOW}\nMount the filesystem on LUKS partition ...{END}")
        subprocess.run(["sudo", "mkdir", "/mnt/vault"], input =f"{sudo}", stderr = subprocess.PIPE, text=True, check=True)
        subprocess.run(["sudo", "mount", "/dev/mapper/gnupg-secrets", "/mnt/vault"], input =f"{sudo}", stderr = subprocess.PIPE, text=True, check=True)

        print(f"{YELLOW}\nCopy GNUPG secret keys and revocation certificate ...{END}")
        ## subprocess.run(["sudo", "cp", "-av", "$GNUPGHOME", "/mnt/vault"], input =f"{sudo}", stderr = subprocess.PIPE, text=True, check=True)
        subprocess.run(["sudo", "cp", "-av", "/home/ejansen/.gnupg/", "/mnt/vault/"], input =f"{sudo}", stderr = subprocess.PIPE, text=True, check=True)

        print(f"{YELLOW}\nUnmount and close the encrypted secret volume ...{END}")
        subprocess.run(["sudo", "umount", "/mnt/vault"], input =f"{sudo}", stderr = subprocess.PIPE, text=True, check=True)
        subprocess.run(["sudo", "cryptsetup", "luksClose", "gnupg-secrets"], input =f"{sudo}", stderr = subprocess.PIPE, text=True, check=True)

        print(f"{GREEN}\nAll Done. Remove the USB device, and store it in a save location.{END}")
        print(f"{GREEN}\nRepeat the process for addional copies.{END}")

def main():
    disk_list()
    disk_partition()

if __name__ == "__main__":
    main()
