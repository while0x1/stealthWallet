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
from blockfrost import ApiUrls
from dotenv import dotenv_values

env_dict = dotenv_values()


BF_MAINNET_KEY = env_dict.get('BF_MAINNET')
BF_PREPROD_KEY = env_dict.get('BF_PREPROD')

net = env_dict.get('NETWORK')
if net == 'MAINNET':
    pyNet = Network.MAINNET
else:
    pyNet = Network.TESTNET


if pyNet == Network.MAINNET:
    BF_PROJ_ID  = BF_MAINNET_KEY
    chain_context = BlockFrostChainContext(project_id=BF_PROJ_ID,base_url=ApiUrls.mainnet.value,)
else:
    BF_PROJ_ID = BF_PREPROD_KEY
    chain_context = BlockFrostChainContext(project_id=BF_PROJ_ID,base_url=ApiUrls.preprod.value,)   



dash.register_page(__name__, path="/delegate")

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
            dbc.Label('Keys must be present in the keys directory to use for Delegation Transaction'),
            dbc.Input(type="text", placeholder="Enter pool hash", id='poolid', value="033c7a00ae33e9a0fa6802b388ccfa5ca9633d712231c41c468c2d39"),

            dbc.Input(type="password", placeholder="Enter decryption password if necessary", id='password', value=""),

            dbc.Button("Submit",id="pool-submit", color="primary", n_clicks=0)
        ],
        className="g-2",
    )
)

layout = html.Div([
    dbc.Container([
        html.H1("Delegate",style = {'textAlign':'center','marginTop':40,'marginBottom':40}),
        dbc.Row([
            dbc.Col(
                form,
                width={"size": 6, "offset": 3},
            ),
            html.Div(dbc.Col(id='staking-output',
                             width={"size": 6, "offset": 5}),
                     ),
        ],className="row-gap-1"
        ),
        
        
    ])
],id="homediv",style={"min-height":"100vh","display":"block"})




@callback(
    Output("staking-output", "children"), [Input("pool-submit", "n_clicks")],
    [State('password', 'value')],
    [State('poolid', 'value')],
)
def on_button_click(n,password,poolid):
    #033c7a00ae33e9a0fa6802b388ccfa5ca9633d712231c41c468c2d39
    if n>0 and len(password) > 7:
        #print(password)
        path = cwd + '/keys/payment.skey.aes'
        if os.path.isfile(path):
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
                from_address = Address(payment_part=payment_vkey.hash(),staking_part=stake_vkey.hash(),network=Network.MAINNET)
                print(from_address)
                #print(unsignedCbor)
                stake_credential = StakeCredential(stake_vkey.hash())
                stake_registration = StakeRegistration(stake_credential)
                poolhash = poolid
                pool_hash = PoolKeyHash(bytes.fromhex(poolhash))
                stake_delegation = StakeDelegation(stake_credential, pool_keyhash=pool_hash)
                builder = TransactionBuilder(chain_context) 
                builder.add_input_address(from_address)
                #builder.add_output(TransactionOutput(from_address, 3500000))      
                #print(from_address)
                print(poolhash)
                #builder._estimate_fee = lambda : 220000
                est_fee = builder._estimate_fee()
                print(f'Transaction fee {est_fee}')
                builder.certificates = [stake_registration, stake_delegation]
                signed_tx = builder.build_and_sign(
                [stake_skey, payment_skey],
                from_address,
                )
                print('Signed Transaction')
                print("############### Transaction created ###############")
                print(signed_tx.id)
                print("############### Submitting transaction ###############")
                #chain_context.submit_tx(signed_tx)
            except Exception as e:
                print(e)
    path = cwd + '/keys/payment.skey'
    if os.path.isfile(path):
        try:
            payment_skey = PaymentSigningKey.load(cwd + '/keys/payment.vkey')
            payment_vkey = PaymentVerificationKey.load(cwd + '/keys/payment.vkey')
            stake_skey = StakeSigningKey.load(cwd + '/keys/stake.skey')
            stake_vkey = StakeVerificationKey.load(cwd + '/keys/stake.vkey')
            from_address = Address(payment_part=payment_vkey.hash(),staking_part=stake_vkey.hash(),network=Network.MAINNET)
            print(from_address)
            #print(unsignedCbor)
            stake_credential = StakeCredential(stake_vkey.hash())
            stake_registration = StakeRegistration(stake_credential)
            poolhash = poolid
            pool_hash = PoolKeyHash(bytes.fromhex(poolhash))
            stake_delegation = StakeDelegation(stake_credential, pool_keyhash=pool_hash)
            builder = TransactionBuilder(chain_context) 
            builder.add_input_address(from_address)
            #builder.add_output(TransactionOutput(from_address, 3500000))      
            #print(from_address)
            print(poolhash)
            #builder._estimate_fee = lambda : 220000
            est_fee = builder._estimate_fee()
            print(f'Transaction fee {est_fee}')
            builder.certificates = [stake_registration, stake_delegation]
            signed_tx = builder.build_and_sign(
            [stake_skey, payment_skey],
            from_address,
            )
            print('Signed Transaction')
            print("############### Transaction created ###############")
            print(signed_tx.id)
            print("############### Submitting transaction ###############")
            chain_context.submit_tx(signed_tx)
        except Exception as e:
            print(e)   
    return f''
        

