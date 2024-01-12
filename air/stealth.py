from cryptography.hazmat.backends import default_backend
import cryptography
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
import secrets
import getpass
import base64
import getpass
import sys
import os
from pycardano import *


def load_salt(dir):
    # load salt from salt.salt file
    return open(dir, "rb").read()
def encrypt(filename, key):
    f = Fernet(key)
    with open(filename, "rb") as file:
        # read all file data
        file_data = file.read()
    # encrypt data
    encrypted_data = f.encrypt(file_data)
    # write the encrypted file
    with open(filename + '.aes' , "wb") as file:
        file.write(encrypted_data)
def decrypt(filename, key):
    f = Fernet(key)
    with open(filename, "rb") as file:
        # read the encrypted data
        encrypted_data = file.read()
    # decrypt data
    try:
        decrypted_data = f.decrypt(encrypted_data)
    except cryptography.fernet.InvalidToken:
        print("Invalid token, most likely the password is incorrect")
        return
    return decrypted_data
    
# ddata = decrypt(cwd + '/keys/payment.skey.aes',b64key)
# payment_signing_key = PaymentSigningKey.from_json(ddata.decode())
cwd = os.getcwd()

print('Welcome to Stealth Wallet!')
print()
print('Please enter an option ->')
print()
print('1 - Generate a key and address')
print('2 - Print your address')
print('3 - Sign a transaction')
print('4 - Sign stake registration')
print()

menu = input()
print()

if menu == '1':
### Generate a key if one doesnt exit ###

    if not os.path.exists(cwd + '/keys'):
        print('Creating Folder..')
        os.makedirs(cwd + '/keys')

    if not os.path.exists(cwd + '/keys'):

        print('Do you wish to password protect the key file - Y/N ?')
        x = input()
        if x == 'Y':
            salt = secrets.token_bytes(16)
            kdf = Scrypt(salt=salt, length=32, n=2**14, r=8, p=1,backend=default_backend())
            with open("salt.salt", "wb") as salt_file:
                    salt_file.write(salt)
            
            print('Enter Password: ')
            password = input()
            key = kdf.derive(password.encode())
            b64key = base64.urlsafe_b64encode(key)
            payment_signing_key = PaymentSigningKey.generate()
            payment_verification_key = PaymentVerificationKey.from_signing_key(payment_signing_key)
            payment_signing_key.save(cwd + '/keys/' + "payment.skey")
            payment_verification_key.save(cwd + '/keys/' + "payment.vkey")
            stake_signing_key = StakeSigningKey.generate()
            stake_verification_key = StakeVerificationKey.from_signing_key(stake_signing_key)
            stake_signing_key.save(cwd + '/keys/' + "stake.skey")
            stake_verification_key.save(cwd + '/keys/' + "stake.vkey")
            base_address_t = Address(payment_part=payment_verification_key.hash(),staking_part=stake_verification_key.hash(),network=Network.TESTNET)
            base_address_m = Address(payment_part=payment_verification_key.hash(),staking_part=stake_verification_key.hash(),network=Network.MAINNET)
            
            print(f'Your testnet address is: \n{base_address_t}')
            print(f'Your mainnet address is: \n{base_address_m}')
            
            encrypt(cwd + '/keys/payment.skey',b64key)
            path = cwd + '/keys/payment.skey.aes'
            if os.path.isfile(path):
                os.remove(cwd + '/keys/payment.skey')
            sys.exit()

        elif x == 'N':
            payment_signing_key = PaymentSigningKey.generate()
            payment_verification_key = PaymentVerificationKey.from_signing_key(payment_signing_key)
            payment_signing_key.save("payment.skey")
            payment_verification_key.save("payment.vkey")
            base_address_t = Address(payment_part=payment_verification_key.hash(),staking_part=stake_verification_key.hash(),network=Network.TESTNET)
            base_address_m = Address(payment_part=payment_verification_key.hash(),staking_part=stake_verification_key.hash(),network=Network.MAINNET)
            print('Keys Generated')
            print(f'Your testnet address is: \n{base_address_t}')
            print(f'Your mainnet address is: \n{base_address_m}')
            sys.exit()
    else:
        print('Key Already Exists...')
        sys.exit()
        
elif menu == '2':
    #path = cwd + '/keys/payment.skey.aes'
    #if os.path.isfile(path):
    if os.path.exists(cwd + '/keys'):
        #payment_skey = PaymentSigningKey.load("/home/map/eopsin/nft-test/keys/payment.skey")
        payment_vkey = PaymentVerificationKey.load(cwd + '/keys/payment.vkey')
        stake_vkey = StakeVerificationKey.load(cwd + '/keys/stake.vkey')
        base_address_t = Address(payment_part=payment_vkey.hash(),staking_part=stake_vkey.hash(),network=Network.TESTNET)
        base_address_m = Address(payment_part=payment_vkey.hash(),staking_part=stake_vkey.hash(),network=Network.MAINNET)
        ent_address_t = Address(payment_part=payment_vkey.hash(),network=Network.TESTNET)
        ent_address_m = Address(payment_part=payment_vkey.hash(),network=Network.MAINNET)
        print(f'Your testnet address is: \n{base_address_t}\n')
        print(f'Your mainnet address is: \n{base_address_m}\n')
        print(f'Your testnet enterprise address is: \n{ent_address_t}')
        print(f'Your mainnet enterprise address is: \n{ent_address_m}')
    else:
        print('No Keys or addresses found..')

elif menu == '3':
    
    path = cwd + '/keys/payment.skey.aes'
    
    if os.path.isfile(path):
        print('Enter Password')
        password = getpass.getpass()
        salt = load_salt(cwd + '/keys/salt.salt')
        kdf = Scrypt(salt=salt, length=32, n=2**14, r=8, p=1,backend=default_backend())
        key = kdf.derive(password.encode())
        b64key = base64.urlsafe_b64encode(key)
        try:
            ddata = decrypt(cwd + '/keys/payment.skey.aes',b64key)
            payment_skey = PaymentSigningKey.from_json(ddata.decode())
            payment_vkey = PaymentVerificationKey.load(cwd + '/keys/payment.vkey')
            print('Key Decrypted successfully')
            print()
            print('Paste Unsigned Transaction here: ')
            unsignedCbor = input()
            tb = TransactionBody.from_cbor(unsignedCbor)
            #print(unsignedCbor)
            signature = payment_skey.sign(tb.hash())
            vk_witnesses = [VerificationKeyWitness(payment_vkey, signature)]
            signed_tx = Transaction(tb, TransactionWitnessSet(vkey_witnesses=vk_witnesses))
            print('Signed Transaction CBOR: ')
            print(signed_tx.to_cbor_hex())
        except Exception as e:
            print(e)
        sys.exit()
    else:
    # Not Encrypted
        path = cwd + '/keys/payment.skey'
        if os.path.isfile(path):   
            try:
                payment_skey = PaymentSigningKey.load(cwd + '/keys/payment.skey')
                payment_vkey = PaymentVerificationKey.from_signing_key(payment_skey)
                print('Paste Unsigned Transaction here: ')
                unsignedCbor = input()
                tb = TransactionBody.from_cbor(unsignedCbor)
                #print(unsignedCbor)
                signature = payment_skey.sign(tb.hash())
                vk_witnesses = [VerificationKeyWitness(payment_vkey, signature)]
                signed_tx = Transaction(tb, TransactionWitnessSet(vkey_witnesses=vk_witnesses))
                print('Signed Transaction CBOR: ')
                print(signed_tx.to_cbor_hex())
            except Exception as e:
                print(e)
elif menu == '4':
    #stakeRegTxSign
    path = cwd + '/keys/payment.skey.aes'
    if os.path.isfile(path):
        print('Enter Password')
        password = getpass.getpass()
        salt = load_salt(cwd + '/keys/salt.salt')
        kdf = Scrypt(salt=salt, length=32, n=2**14, r=8, p=1,backend=default_backend())
        key = kdf.derive(password.encode())
        b64key = base64.urlsafe_b64encode(key)
        try:
            ddata = decrypt(cwd + '/keys/payment.skey.aes',b64key)
            payment_skey = PaymentSigningKey.from_json(ddata.decode())
            payment_vkey = PaymentVerificationKey.load(cwd + '/keys/payment.vkey')
            stake_skey = StakeSigningKey.load(cwd + '/keys/stake.skey')
            stake_vkey = StakeVerificationKey.load(cwd + '/keys/stake.vkey')
            print('Key Decrypted successfully')
            print()
            print('Paste Unsigned Transaction here: ')
            unsignedCbor = input()
            tb = TransactionBody.from_cbor(unsignedCbor)
            #print(unsignedCbor)
            stake_credential = StakeCredential(stake_vkey.hash())
            stake_registration = StakeRegistration(stake_credential)
            print('Enter hash of your nominated stake pool:')
            poolhash = input()
            pool_hash = PoolKeyHash(bytes.fromhex(poolhash))
            stake_delegation = StakeDelegation(stake_credential, pool_keyhash=pool_hash)
            tb.certificates = [stake_registration, stake_delegation]
            tb.fee = tb.fee + 25000
            signature = payment_skey.sign(tb.hash())
            stake_sign = stake_skey.sign(tb.hash())
            vk_witnesses = [VerificationKeyWitness(payment_vkey, signature),VerificationKeyWitness(stake_vkey, stake_sign)]
            signed_tx = Transaction(tb, TransactionWitnessSet(vkey_witnesses=vk_witnesses))
            print('Signed Transaction CBOR: ')
            print(signed_tx.to_cbor())
        except Exception as e:
            print(e)
        sys.exit()
    else:
    # Not Encrypted
        try:
            payment_skey = PaymentSigningKey.load(cwd + '/keys/payment.skey')
            payment_vkey = PaymentVerificationKey.load(cwd + '/keys/payment.vkey')
            stake_skey = StakeSigningKey.load(cwd + '/keys/stake.skey')
            stake_vkey = StakeVerificationKey.load(cwd + '/keys/stake.skey')
            print('Paste Unsigned Transaction here: ')
            unsignedCbor = input()
            tb = TransactionBody.from_cbor(unsignedCbor)
            #print(unsignedCbor)
            signature = payment_skey.sign(tb.hash())
            stake_sign = stake_skey.sign(tb.hash())
            vk_witnesses = [VerificationKeyWitness(payment_vkey, signature),VerificationKeyWitness(stake_vkey, stake_sign)]
            signed_tx = Transaction(tb, TransactionWitnessSet(vkey_witnesses=vk_witnesses))
            print('Signed Transaction CBOR: ')
            print(signed_tx.to_cbor())
        except Exception as e:
            print(e)
    