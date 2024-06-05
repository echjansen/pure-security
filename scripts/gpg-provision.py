#!/usr/bin/env python3

"""
This scripts provisions a new GPG according to the method described in 'drduh' guide.
The script does not created a GPG configuration on this computer, instead it creates
a configuration to be:
1. Taken offline (full set of armoured files)
2. Transfered to a smartcard such as OnlyKey or YubiKey
"""

import os
import subprocess
import tempfile
import getpass

GPG_DEBUG = False

def gpg_create_gnupghome():
    """
    Create a temporary directory which will be cleared on reboot,
    and configure it as the hardened GnuPG directory.
    """
    with tempfile.TemporaryDirectory(prefix="gpg_", delete=False) as GNUPGHOME:
        os.system("cp ../config/gpg.conf " + GNUPGHOME + "/gpg.conf")
        os.environ['GNUPGHOME']=GNUPGHOME
        return GNUPGHOME

def gpg_create_certify_key(identity, keytype, password):
    """
    The primary key is the [C] Certify Key.
    It is responsible for issuing Subkeys for [E] Encryption, [S] Signing and [A] Authentication.
    The Certify key should be kept offline at all times and only access to issue or revoke subkeys.
    No expiration date is set for the Certify key (as it can change it itself).
    """
    if keytype == "25519": keytype = "ed25519"
    cmd = "gpg --batch --passphrase " + password + \
             " --quick-generate-key " + identity + " " + keytype + " cert never"
    if GPG_DEBUG: print("\n" + cmd)
    os.system(cmd)

def gpg_create_sign_subkey(identity, keytype, password, expiration):
    if keytype == "25519": keytype = "ed25519"
    cmd = "gpg --batch --pinentry-mode=loopback --passphrase " + password + \
             " --quick-add-key " + identity + " " + keytype + " sign " + expiration
    if GPG_DEBUG: print("\n" + cmd)
    os.system(cmd)

def gpg_create_encrypt_subkey(identity, keytype, password, expiration):
    if keytype == "25519": keytype = "cv25519"
    cmd = "gpg --batch --pinentry-mode=loopback --passphrase " + password + \
             " --quick-add-key " + identity + " " + keytype + " encrypt " + expiration
    if GPG_DEBUG: print("\n" + cmd)
    os.system(cmd)

def gpg_create_auth_subkey(identity, keytype, password, expiration):
    if keytype == "25519": keytype = "ed25519"
    cmd = "gpg --batch --pinentry-mode=loopback --passphrase " + password + \
             " --quick-add-key " + identity + " " + keytype + " auth " + expiration
    if GPG_DEBUG: print("\n" + cmd)
    os.system(cmd)

def gpg_export_secret_key(keyid, gnupghome, password):
    cmd = "gpg --output " + gnupghome + "/" + keyid + ".private.master.asc " + \
             " --batch --pinentry-mode=loopback --passphrase " + password + \
             " --armor --export-secret-keys " + keyid
    if GPG_DEBUG: print("\n" + cmd)
    os.system(cmd)

def gpg_export_secret_subkey(keyid, gnupghome, password):
    cmd = "gpg --output " + gnupghome + "/" + keyid + ".private.subkeys.asc " + \
             " --batch --pinentry-mode=loopback --passphrase " + password + \
             " --armor --export-secret-subkeys " + keyid
    if GPG_DEBUG: print("\n" + cmd)
    os.system(cmd)

def gpg_export_public_key(keyid, gnupghome, password):
    cmd = "gpg --output " + gnupghome + "/" + keyid + ".public.key.asc " + \
             " --batch --pinentry-mode=loopback --passphrase " + password + \
             " --armor --export " + keyid
    if GPG_DEBUG: print("\n" + cmd)
    os.system(cmd)

def gpg_get_fingerprint(identity):
    cmd = "gpg -k --with-colons " + identity + " | awk -F: '/^fpr:/ {print $10; exit}'"
    if GPG_DEBUG: print("\n" + cmd)
    p = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE)
    return p.communicate()[0].decode().strip()

def gpg_get_keyid(identity):
    cmd = "gpg -k --with-colons " + identity + " | awk -F: '/^pub:/ {print $5; exit}'"
    if GPG_DEBUG: print("\n" + cmd)
    p = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE)
    return p.communicate()[0].decode().strip()

def gpg_print_keys_list():
    cmd = "gpg -K"
    if GPG_DEBUG: print("\n" + cmd)
    p = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE)
    print(p.communicate()[0].decode())


if __name__ == '__main__':
    os.system("reset")

    # Setup user information
    GPG_GNUPGHOME = gpg_create_gnupghome()
    GPG_USER =  input("Real Name: ")
    GPG_EMAIL = input("Email: ")
    GPG_IDENTITY = '"' + GPG_USER + ' <' + GPG_EMAIL + '>"'
    GPG_PASSWORD = getpass.getpass("Password: ")
    GPG_KEYTYPE = input('Curve 25519 (1 = default), RSA (2): ')
    if GPG_KEYTYPE  == '1':
        GPG_KEYTYPE = "25519"
    elif GPG_KEYTYPE == '2':
        GPG_KEYTYPE = "rsa4096"
    else:
        GPG_KEYTYPE = "25519"
    GPG_EXPIRATION = input("Expiration in years (2y): ")
    if GPG_EXPIRATION == "":
        GPG_EXPIRATION = "2y"

    print("\n")
    print("============================================================")
    print("* Selected values for GPG Key creation.                    *")
    print("============================================================")
    print("GNUPGHOME:  " + GPG_GNUPGHOME)
    print("IDENTITY:   " + GPG_IDENTITY)
    print("KEY TYPE:   " + GPG_KEYTYPE)
    print("EXPIRATION: " + GPG_EXPIRATION)
    if input("Continue (y/n)?") != "y": exit()

    # Create GPG keys
    gpg_create_certify_key(GPG_IDENTITY, GPG_KEYTYPE, GPG_PASSWORD)
    GPG_FINGERPRINT = gpg_get_fingerprint(GPG_IDENTITY)
    GPG_KEYID = gpg_get_keyid(GPG_IDENTITY)
    gpg_create_sign_subkey(GPG_FINGERPRINT, GPG_KEYTYPE, GPG_PASSWORD, GPG_EXPIRATION)
    gpg_create_encrypt_subkey(GPG_FINGERPRINT, GPG_KEYTYPE, GPG_PASSWORD, GPG_EXPIRATION)
    gpg_create_auth_subkey(GPG_FINGERPRINT, GPG_KEYTYPE, GPG_PASSWORD, GPG_EXPIRATION)

    # Create backup files and certificate
    gpg_export_secret_key(GPG_KEYID, GPG_GNUPGHOME, GPG_PASSWORD)
    gpg_export_secret_subkey(GPG_KEYID, GPG_GNUPGHOME, GPG_PASSWORD)
    gpg_export_public_key(GPG_KEYID, GPG_GNUPGHOME, GPG_PASSWORD)

    print("\n")
    print("============================================================")
    print("* Keys created and backup files created.                   *")
    print("* Check " + GPG_GNUPGHOME + " for backup files.            *")
    print("============================================================")
    gpg_print_keys_list()
