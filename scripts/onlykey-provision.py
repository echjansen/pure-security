#!/usr/bin/env python
"""
OnlyKey provision Script.

Description:
- This script reads secret keys from to provided keyfile. Keyfile is encouraged
  to contains subkeys for [S] Signing and [E] Encryption. If the keyfile contains
  an [A] Authorization key, it will be igniored, as it is not supported.
- With the -d options displays the contect of the keyfile, and what is loaded
  on the OnlyKey.
- If the password is not provided the script will ask for entry, without displaying.
- After transfer the script shows wher the keys are written on the onlykey
  - slot 101 .. 116 for ECC keys
  - slot 1 .....4   for RSA keys

- After successull trasnfer of the keys to Onlykey execute the following
  commands to complete the OnlyKey 'activations'
  > onlykey-gpg init -sk 101 -dk 102 -i publickeyfile "name <email>"
  > export GNUPGHOME=$HOME/.gnupg/onlykey

Usage:

onlykey-provision [-h] [-d] [--no-expired] [--no-colors] [-p PASSPHRASE] keyfile

positional arguments:
  keyfile               path to the secret PEM-encoded key file, or '-' for stdin.

options:
  -h, --help            show this help message and exit
  -d, --display         display only, extracted keys shown for loading in the OnlyKey Desktop App
  --no-expired          do not show expired subkeys
  --no-colors           do not output with colors. Usefull for piping output and use in scripts.
  -p PASSPHRASE,        the passphrase of the key. Don't forget bash's history keeps everything !
"""

import sys
import argparse
import fileinput
import getpass
import pgpy
import subprocess
import atexit
import time
import os

from warnings import filterwarnings
from onlykey.client import OnlyKey, MessageField
from Crypto.Util.number import long_to_bytes

# Suppress traceback information (when OnlyKey is locked, etc)
sys.tracebacklimit = 0

# ignore any depreciation warnings
filterwarnings("ignore")

algorithmnames = {0x0: "RSA", 0x01: "RSA", 0x02: "RSA", 0x03: "RSA", 0x10: "ElGamal",
                  0x11: "DSA", 0x12: "ECDH", 0x13: "ECDSA", 0x14: "ElGammal",
                  0x15: "DiffieHellman", 0x16: "EdDSA"}

# Try to detect the OnlyKey
try:
    only_key = OnlyKey()
except:
    raise SystemExit

BLACK = "\033[0;30m"
RED = "\033[0;31m"
BLUE = "\033[0;34m"
YELLOW = "\033[0;93m"
END = "\033[0m"

class KeyDetails:
    def __init__(self):
        self.type = ""
        self.keygrip = ""
        self.keyid = ""
        self.curvetype = ""
        self.keylength = ""
        self.algorithm = ""
        self.trust = ""
        self.keyvalue = None

    def __repr__(self):
        return f"keyid: {self.keyid}, type: {self.type}, algorithm: {self.algorithm}, keylength {self.keylength}"


def get_keygrips_by_keyid_from_blob(keyblob):
    retval = subprocess.run(['gpg', '--keyid', 'long', '--with-keygrip',
                            '--with-colons', '--import-options', 'show-only',
                             '--import', '-'], stdout=subprocess.PIPE,
                             input=keyblob.encode("ascii"))
    lines = retval.stdout.split(b'\n')
    keys = {}
    currentKey = None
    disabled = True
    for line in lines:
        values = line.split(b':')
        if len(values) < 2:
            continue
        if len(values) >= 12 and values[11] == b'D':
            disabled = True
            continue
        if values[0] in [b'pub', b'sub', b'sec', b'ssb'] and values[1] in [b'f', b'u', b'-']:
            disabled = False
        if disabled is True:
            continue


        if values[0] in [b'pub', b'sub', b'sec', b'ssb']:
            currentKey = KeyDetails()
            keys[values[4]] = currentKey
            if values[0] in(b'pub', 'sec'):
                currentKey.type = b's'
            else:
                currentKey.type = values[11]
            currentKey.trust = values[1]
            currentKey.curvetype = values[16]
            currentKey.keyid = values[4]
            currentKey.keylength = values[2]
            currentKey.algorithm = int(values[3])
            if currentKey.algorithm in algorithmnames:
                currentKey.algorithmname = algorithmnames[currentKey.algorithm]
            else:
                currentKey.algorithmname = "Unknown"
        elif values[0] == b'grp':
            currentKey.keygrip = values[9]
            currentKey.okkeygrip = values[9][:16]
        elif values[0] == b'fpr':
            currentKey.fingerprint = values[9]
    return keys


def set_key_only_key(keyslots, key):
    print(key.type)
    if key.type == b'e':
        # Encrypt / Decrypt key
        key_features = 'd'
    elif key.type in (b's', b'scESC'):
        # Sign key
        key_features = 's'
    elif key.type in (b'cESCA'):
        # Primary key (echjansen)
        key_features = 's'
    else:
        key_features = key["type"]

    for i in keyslots:
        if i.label != b'':
            continue
        if key.algorithmname == "RSA":
            if i.targetslot > 100:
                continue
            print(f"targetslot - {i.targetslot}, label - {i.label}")
            if key.keylength == b'4096':
                key_type = '4'
            elif key.keylength == b'2048':
                key_type = '2'
            print(f"only_key.setkey({i.targetslot}, {key_type}, {key_features}, {key.keyvalue})")
            print(f"only_key.setslot({i.number}, {MessageField.LABEL}, {key.okkeygrip.decode('utf-8')})")
            only_key.setkey(i.targetslot, key_type, key_features, key.keyvalue)
            # Unfortunately the onlykey_cli does not return and error when Onlykey not in config mode
            # Thus, the label will be set regardless, as it does not require config mode
            only_key.setslot(i.number, MessageField.LABEL, key.okkeygrip.decode('utf-8'))
            return
        elif key.algorithmname in ("ECDH", "EdDSA", "ECDSA"):
            if i.targetslot <= 100:
                continue
            if key.curvetype in [b'ed25519', b'cv25519']:
                print(f"only_key.setkey({i.targetslot}, 'x', '{key_features}', '{key.keyvalue}')")
                only_key.setkey(i.targetslot, 'x', key_features, key.keyvalue)
            elif key.curvetype in [b'nistp256']:
                print(f"only_key.setkey({i.targetslot}, 'n', '{key_features}', '{key.keyvalue}')")
                only_key.setkey(i.targetslot, 'n', key_features, key.keyvalue)
            elif key.curvetype in [b'secp256k1']:
                print(f"only_key.setkey({i.targetslot}, 's', '{key_features}', '{key.keyvalue}')")
                only_key.setkey(i.targetslot, 's', key_features, key.keyvalue)
            else:
                raise "Error unsupported curve"
            print(f"only_key.setslot({i.number}, {MessageField.LABEL}, {key.okkeygrip.decode('utf-8')})")
            # Unfortunately the onlykey_cli does not return and error when Onlykey not in config mode
            # Thus, the label will be set regardless, as it does not require config mode
            only_key.setslot(i.number, MessageField.LABEL, key.okkeygrip.decode('utf-8'))
            return
        else:
            print("algorithm - %s is unsupported" % (key.algorithmname))


def get_key_type(key:pgpy.PGPKey):
    """
    Get the key's type.

    Parameters
    ----------
    key : pgpy.PGPKey
        The key from which to get the type.

    Returns
    -------
    str
        The type of the key. One of RSA, DSA, ElGamal, ECDSA, EdDSA or ECDH.

    """
    if isinstance(key._key.keymaterial, pgpy.packet.fields.RSAPriv):
        return 'RSA'
    elif isinstance(key._key.keymaterial, pgpy.packet.fields.DSAPriv):
        return 'DSA'
    elif isinstance(key._key.keymaterial, pgpy.packet.fields.ElGPriv):
        return 'ElGamal'
    elif isinstance(key._key.keymaterial, pgpy.packet.fields.ECDSAPriv):
        return 'ECDSA'
    elif isinstance(key._key.keymaterial, pgpy.packet.fields.EdDSAPriv):
        return 'EdDSA'
    elif isinstance(key._key.keymaterial, pgpy.packet.fields.ECDHPriv):
        return 'ECDH'
    return ''


def get_key_value(key:pgpy.PGPKey):
    """
    Get the private key's value and size.

    Parameters
    ----------
    key : pgpy.PGPKey
        The private key.

    Raises
    ------
    NotImplementedError
        Key type not supported for DSA and ElGamal.

    Returns
    -------
    value : str
        hex string representing the raw private key.
    size : int
        The size of the raw private key in bits.

    """
    key_type = get_key_type(key)
    if key_type == 'RSA':
        p = long_to_bytes(key._key.keymaterial.p)
        q = long_to_bytes(key._key.keymaterial.q)
        value = "".join([f"{c:02x}" for c in p]) + "".join([f"{c:02x}" for c in q])
        size = (len(p) + len(q)) * 8
    elif key_type in ('ECDSA', 'EdDSA', 'ECDH'):
        s = long_to_bytes(key._key.keymaterial.s)
        value = "".join([f"{c:02x}" for c in s])
        size = len(s)*8
    else:
        raise NotImplementedError(f"Get value from {key_type} key is not "
                                  f"supported")
    return (value, size)


def get_key_flags(key:pgpy.PGPKey):
    """
    Get the key's usage flags.

    Parameters
    ----------
    key : pgpy.PGPKey
        The key.

    Returns
    -------
    str
        Usage flags of the key.
        Flags:
            C : Certification

            S : Signature

            E : Encryption

            A : Authentication

    """
    flags = []
    strs = {pgpy.constants.KeyFlags.Certify : 'C',
            pgpy.constants.KeyFlags.Sign : 'S',
            pgpy.constants.KeyFlags.EncryptCommunications : 'E',
            pgpy.constants.KeyFlags.Authentication : 'A'}
    for sig in key.self_signatures:
        if not sig.is_expired:
            flags += sig.key_flags
    return "".join(strs.get(flag, '') for flag in flags)

def get_key_slots():
    keylabels = only_key.getkeylabels()
    for i in keylabels:
        if i.label == "ÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿ":
            i.label = ""
        if i.number + 72 > 100:
            i.targetslot = i.number + 72
        else:
            i.targetslot = i.number - 24
        i.label = i.label.encode('ascii')
    return keylabels


def Run():
    GREEN = "\033[0;32m"

    parser = argparse.ArgumentParser(
        description='Extract secret subkeys from a OpenPGP key.\n\n'
                    'This script will display and set the raw private keys and subkeys on your OnlyKey.\n'
                    'Only run this on a secure trusted system.',
        epilog='''Extract and load keys onto OnlyKey example:
        gpg --export-secret-keys -a keyid | ./onlykey-cli-gpg-add-keys -
        ./onlykey-cli-gpg-add-keys ~/mykey.asc --no-expired
        Extract and display for loading in the OnlyKey Desktop App example:
        ./onlykey-cli-gpg-add-keys ~/mykey.asc -d
        ''',
        formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('keyfile', type=str,
                        help="path to the secret PEM-encoded key file, or "
                        "'-' for stdin.'")
    parser.add_argument('-d', '--display', action='store_true',
                        help='display only, extracted keys shown for loading in the OnlyKey Desktop App')
    parser.add_argument('--no-expired', action='store_true',
                        help='do not show expired subkeys')
    parser.add_argument('--no-colors', action='store_true',
                        help='do not output with colors. Usefull for piping '
                        'output and use in scripts.')
    parser.add_argument('-p', '--passphrase', type=str,
                        help="the passphrase of the key. Don't forget bash's "
                        "history keeps everything !")

    args = parser.parse_args()

    # Ensure the GNUPGHOME variable is not set
    if os.environ['GNUPGHOME'] != "":
        print(f'{RED}The GNUPGHOME environemnt variable is set: {END}' + os.environ['GNUPGHOME'])
        print("Clear the variable with export GNUPGHOME=  and try again.")
        print("Exiting ....")
        exit()

    if args.no_colors:
        GREEN = ""

    # Parse input - either a file or stdin - for private key block
    armored_key = None
    with fileinput.input(files=args.keyfile) as keyfile:
        for line in keyfile:
            if line == "-----BEGIN PGP PRIVATE KEY BLOCK-----\n":
                armored_key = line
            elif line == "-----END PGP PRIVATE KEY BLOCK-----\n":
                armored_key += line
                break
            elif armored_key is not None:
                armored_key += line
    primary_key, _ = pgpy.PGPKey.from_blob(armored_key)
    keygrip_by_id = get_keygrips_by_keyid_from_blob(armored_key)

    try:
        os.system("reset")
        print(f"{YELLOW}====================================================={END}")
        print(f"{YELLOW}| OnlyKey Provisioning script                       |{END}")
        print(f"{YELLOW}====================================================={END}")
        password = args.passphrase if args.passphrase else getpass.getpass(
            f"{YELLOW}Enter GPG key password to open key: {END}")
        if primary_key.is_protected is True and primary_key._key.keymaterial.encbytes == b'':
            print("No secret primary key")
        elif primary_key.is_protected is True:
            with primary_key.unlock(password):
                # primary_key is now unlocked
                assert primary_key.is_unlocked
                print(f'{YELLOW}\nPrimary key is now unlocked{END}')
                key_value, key_size = get_key_value(primary_key)
                print(f'primary key id: {primary_key.fingerprint.keyid}')
                print(f'primary key type: {get_key_type(primary_key)}')
                print(f'primary key usage: {get_key_flags(primary_key)}')
                if args.display:
                    print(f'{GREEN}primary key value:{END} {key_value}')
                print(f'primary key size: {key_size} bits')
                keygrip_by_id[primary_key.fingerprint.keyid.encode('ascii')].keyvalue = key_value
        elif primary_key.is_primary is True:
            # primary_key is not password protected
            print('Load these raw key values to OnlyKey by using the '
                'OnlyKey App --> Advanced -> Add Private Key')
            key_value, key_size = get_key_value(primary_key)
            print(f'primary key id: {primary_key.fingerprint.keyid}')
            print(f'primary key type: {get_key_type(primary_key)}')
            print(f'primary key usage: {get_key_flags(primary_key)}')
            if args.display:
                print(f'{GREEN}primary key value:{END} {key_value}')
            print(f'primary key size: {key_size} bits')
            keygrip_by_id[primary_key.fingerprint.keyid.encode('ascii')].keyvalue = key_value

        print(f"{YELLOW}\nExtracting subkeys...{END}")

        for key_id, subkey in primary_key.subkeys.items():
            with subkey.unlock(password):
                assert subkey.is_unlocked
                if args.no_expired and subkey.is_expired:
                    continue
                print(f'subkey id: {key_id}')
                print(f'subkey type: {get_key_type(subkey)}')
                print(f'subkey usage: {get_key_flags(subkey)}')
                if subkey.is_expired:
                    print(f'{RED}subkey has expired !{END}')
                key_value, key_size = get_key_value(subkey)
                if args.display:
                    print(f'{GREEN}subkey value:{END} {key_value}')
                print(f'subkey size: {key_size} bits')
                print()
                keygrip_by_id[key_id.encode('ascii')].keyvalue = key_value

        keyslots = get_key_slots()
        keys_to_transfer = []
        keys_on_onlykey = []
        keys_no_private_key = []
        keys_not_supported = []

        for k, v in keygrip_by_id.items():
            keyexists = False
            keysupported = True
            keygrip = keygrip_by_id[k].okkeygrip

            # Authorise keys are not supported on OnlyKey (yet)
            if keygrip_by_id[k].type.decode() == "a":
                keysupported = False

            # Check if key is already loaded on OnlyKey
            for slot in keyslots:
                if slot.label == keygrip:
                    keyexists = True

            # Sort the presented key in appropriate list
            if keyexists is False and v.keyvalue is not None:
                if keysupported is True:
                    keys_to_transfer.append(v)
                else:
                    keys_not_supported.append(v)
            elif keyexists is False:
                keys_no_private_key.append(v)
            else:
                keys_on_onlykey.append(v)

        if len(keys_no_private_key)>0:
            print(f"{YELLOW}\nKeys without a private key:{END}")
            for key in keys_no_private_key: print(key)

        if len(keys_not_supported)>0:
            print(f"{YELLOW}\nKeys not supported:{END}")
            for key in keys_not_supported: print(key)

        if len(keys_on_onlykey)>0:
            print(f"{YELLOW}\nKeys already transfered to OnlyKey:{END}")
            for key in keys_on_onlykey: print(key)

        if len(keys_to_transfer)>0:
            if args.display is False:
                # There are new keys to transfer, action:
                print(f"{YELLOW}\nKeys to create:{END}")
                if len(keys_to_transfer) > 1:
                    print(f"{YELLOW}\nTransfering keys ...{END}")
                for i in keys_to_transfer:
                    set_key_only_key(keyslots, i)
                    time.sleep(2.0)
                    keyslots = get_key_slots()
                print(f"{YELLOW}\nKeyslots:{END}")
                for key in keyslots: print(key)
            else:
                # There are new keys to transfer, show manual instruction
                print(f"{YELLOW}\nLoad the raw GPG key values (Green -subkey values-) to OnlyKey by using the{END}")
                print(f"{YELLOW}OnlyKey App --> Advanced -> Add Private Key{END}")
                for key in keys_to_transfer: print(key)

        else:
            print(f"{RED}\nNo new GPG keys to transfer{END}")

    except pgpy.errors.PGPDecryptionError:
        print("Wrong password")
        sys.exit(1)

    # Primary_key is no longer unlocked
    if primary_key.is_protected is True:
        assert primary_key.is_unlocked is False

def exit_handler():
    only_key._hid.close()

if __name__ == '__main__':
    try:
        atexit.register(exit_handler)
        Run()
    except EOFError:
        only_key._hid.close()
        print()
        print('Bye!')
