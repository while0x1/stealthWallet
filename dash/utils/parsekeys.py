from pycardano import PaymentSigningKey, PaymentExtendedSigningKey, PaymentVerificationKey, StakeSigningKey, StakeVerificationKey
import base64
from utils.crypto import *
from cryptography.hazmat.backends import default_backend
import cryptography
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
import secrets
import base64
import os


def getKeys(list_of_names,list_of_contents,password=None):
    cwd = os.getcwd()
    if list_of_contents is not None:
        payment_skey = ''
        payment_vkey = ''
        stake_skey = ''
        stake_vkey = ''
        address = ''
        salt = ''
        path = (cwd + '/keys/salt.salt')
        if os.path.isfile(path):
            salt = load_salt(cwd + '/keys/salt.salt')
                
        for n in range(0,len(list_of_names)):
            if list_of_names[n] != 'salt.salt':
                print(list_of_names[n])
                b64_raw = list_of_contents[n][list_of_contents[n].find('base64')+7:]
                b64_bytes = b64_raw.encode('utf-8')
                utf_bytes = base64.b64decode(b64_bytes)
                utf_str = utf_bytes.decode('utf-8')
            if list_of_names[n] == 'payment.skey':
                #print(utf_str)
                if utf_str.find('PaymentExtendedSigningKeyShelley') < 0:
                    payment_skey = PaymentSigningKey.from_json(utf_str)
                else:
                    payment_skey = PaymentExtendedSigningKey.from_json(utf_str)
                    print('ExtendedSigningKeyGenerated!')
                    #print(payment_skey)
            elif list_of_names[n] == 'stake.skey':
                stake_skey = StakeSigningKey.from_json(utf_str)
            elif list_of_names[n] == 'payment.vkey':
                payment_vkey = PaymentVerificationKey.from_json(utf_str)
            elif list_of_names[n] == 'stake.vkey':
                stake_vkey = StakeVerificationKey.from_json(utf_str)
            elif list_of_names[n] == 'payment.skey.aes':
                kdf = Scrypt(salt=salt, length=32, n=2**14, r=8, p=1,backend=default_backend())
                key = kdf.derive(password.encode())
                b64key = base64.urlsafe_b64encode(key)
                print('HEREiam;')
                print(password)
                try: 
                    ddata = decrypt_64(utf_bytes,b64key)
                    print('here')
                    payment_skey = PaymentSigningKey.from_json(ddata.decode())
                except Exception as e:
                    print(e)
        print(payment_skey,payment_vkey,stake_skey,stake_vkey)
        return [payment_skey,payment_vkey,stake_skey,stake_vkey]
    
            

            