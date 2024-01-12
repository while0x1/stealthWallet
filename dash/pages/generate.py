import os
from dash import html,  Input, Output, callback, State
import dash
import dash_bootstrap_components as dbc
from cryptography.hazmat.backends import default_backend
import cryptography
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
import secrets
import base64
import sys
import os
from pycardano import *

dash.register_page(__name__, path="/generate")

cwd = os.getcwd()

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


form = dbc.Form(
    dbc.Row(
        [
            dbc.Col(
                dbc.Input(type="password", placeholder="Enter password", id='password', value=""),
                className="me-3",
            ),
            dbc.Col(dbc.Button("Generate",id="gen-wallet", color="primary", n_clicks=0), width="auto"),

        ],
        className="g-2",
    )
)

layout = html.Div([
    dbc.Container([
        html.H1("Create Hot Wallet",style = {'textAlign':'center','marginTop':40,'marginBottom':40}),
        html.H4('Recommended: Backup your keys to a secure USB and then remove them from your PC',style = {'textAlign':'center'}),
        dbc.Row([
            dbc.Col(
                form,
                width={"size": 6, "offset": 3},
            ),
            html.Div(dbc.Col(id='example-output',
                             width={"size": 6, "offset": 4}),
                     ),
            html.Div(dbc.Col(id='hot-address',width={"size": 6, "offset": 2})),
        ],className="row-gap-1"
        ),
        
        
    ])
],id="homediv",style={"min-height":"100vh","display":"block"})




@callback(
    Output("example-output", "children"),
    Output("hot-address", "children"),
    [Input("gen-wallet", "n_clicks")],
    [State('password', 'value')],
)
def on_button_click(n,password):
    if n>0 and len(password) > 7:
        #print(password)
        if not os.path.exists(cwd + '/keys'):
            print('Creating hot keys Folder..')
            os.makedirs(cwd + '/keys')
            
        path_aes = cwd + '/keys/payment.skey.aes'
        path_clear = cwd + '/keys/payment.skey'
        if not os.path.isfile(path_aes) and not os.path.isfile(path_clear) :
            salt = secrets.token_bytes(16)
            kdf = Scrypt(salt=salt, length=32, n=2**14, r=8, p=1,backend=default_backend())
            with open(cwd + "/keys/salt.salt", "wb") as salt_file:
                salt_file.write(salt)
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
            return "Keys Generated", base_address_m.encode()
        else:
            return 'Keys Exist already',''
            print('Keys Already Exist')
    else:
        if len(password) < 8:
            print('Password insufficient')
            return "Password must be 8 or more characters",''
            
        else:
            print('EmptyHere')
            return "",''

