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

dash.register_page(__name__, path="/mnemonic")

cwd = os.getcwd()



form = dbc.Form(
    dbc.Row(
        [
            dbc.Col(
                dbc.Input(type="password", placeholder="Past mnemonic", id='m-password', value=""),
                className="me-3",
            ),
            dbc.Col(dbc.Button("Import seed",id="m-wallet", color="primary", n_clicks=0), width="auto"),
        ],
        className="g-2",
    )
)

layout = html.Div([
    dbc.Container([
        html.H1("Import mnemonic wallet",style = {'textAlign':'center','marginTop':40,'marginBottom':40}),
        dbc.Row([
            dbc.Col(
                form,
                width={"size": 6, "offset": 3},
            ),
            html.Div(dbc.Col(id='m-output',
                             width={"size": 6, "offset": 5}),
                     ),
        ],className="row-gap-1"
        ),
        
        
    ])
],id="m-div",style={"min-height":"100vh","display":"block"})


@callback(
    Output("m-output", "children"), [Input("m-wallet", "n_clicks")],
    [State('m-password', 'value')],
)
def on_button_click(n,password):
    if n > 0:
        key_exists = False
        path = cwd + '/keys/payment.skey.aes'
        if os.path.isfile(path):
            key_exists = True
        path = cwd + '/keys/payment.skey'
        if os.path.isfile(path):
            key_exists = True
        path = cwd + '/keys/payment.vkey'
        if os.path.isfile(path):
            key_exists = True
        path = cwd + '/keys/stake.skey'
        if os.path.isfile(path):
            key_exists = True
        
        if not key_exists:
            try:
                #print(password)
                hdwallet = HDWallet.from_mnemonic(password)
                hdwallet_stake = hdwallet.derive_from_path("m/1852'/1815'/0'/2/0")
                stake_public_key = hdwallet_stake.public_key
                stake_vk = PaymentVerificationKey.from_primitive(stake_public_key)
                hdwallet_spend = hdwallet.derive_from_path("m/1852'/1815'/0'/0/0")
                spend_public_key = hdwallet_spend.public_key
                spend_vk = PaymentVerificationKey.from_primitive(spend_public_key)
                stake_skey = StakeExtendedSigningKey.from_hdwallet(hdwallet_stake)
                stake_skey.save(cwd + '/keys/stake.skey')
                #ExtendedSigningKey
                esk = ExtendedSigningKey.from_hdwallet(hdwallet_spend)
                esk.save(cwd + '/keys/payment.skey')
                #ExtendedVKey
                evk = ExtendedVerificationKey.from_signing_key(esk)
                #StakeKey
                stk_skey = StakeExtendedSigningKey.from_hdwallet(hdwallet_stake)

                stake_vk.save(cwd + '/keys/stake.vkey')
                spend_vk.save(cwd + '/keys/payment.vkey')

                ad = Address(evk.hash(), stake_vk.hash(), network=Network.MAINNET)
                address = Address(spend_vk.hash(), stake_vk.hash(), network=Network.MAINNET).encode()

                #with open(cwd + "payment.addr", "w") as f:
                #    f.write(address)
                return 'Keys Generated for address: ' + address[0:9] + '...' + address[100:]
            except Exception as e:
                print(e)
        else:
            return 'Key file(s) already exist!'
    else:
        return ''
