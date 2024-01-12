import os
from dash import html,  Input, Output, callback, State
import dash
import dash_bootstrap_components as dbc
import secrets
import sys
import os
from pycardano import *
from blockfrost import ApiUrls
from dotenv import dotenv_values
from utils.crypto import *
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
import base64

env_dict = dotenv_values()



dash.register_page(__name__, path="/decrypt")

cwd = os.getcwd()


form = dbc.Form(
    dbc.Row(
        [

            dbc.Label('Decrypts an AES key present @  ~/StealthWallet/dash/keys/payment.skey.aes'),
            dbc.Label('Requires your AES key and the original salt.salt file in they keys directory'),
            dbc.Label('Saves unencrypted key to disk and removes salt.salt and AES key files'),
            dbc.Input(type="password", placeholder="Enter decryption password", id='decrypt-password', value=""),

            dbc.Button("Decrypt",id="decrypt-submit", color="primary", n_clicks=0)
        ],
        className="g-2",
    )
)

layout = html.Div([
    dbc.Container([
        html.H1("Decrypt",style = {'textAlign':'center','marginTop':40,'marginBottom':40}),
        dbc.Row([
            dbc.Col(
                form,
                width={"size": 6, "offset": 3},
            ),
            html.Div(dbc.Col(id='decrypt-output',
                             width={"size": 6, "offset": 5}),
                     ),
        ],className="row-gap-1"
        ),
        
        
    ])
],id="decrypt-div",style={"min-height":"100vh","display":"block"})




@callback(
    Output("decrypt-output", "children"), [Input("decrypt-submit", "n_clicks")],
    [State('decrypt-password', 'value')],
)
def on_button_click(n,password):
    #033c7a00ae33e9a0fa6802b388ccfa5ca9633d712231c41c468c2d39
    if n>0 and len(password) > 7:
        #print(password)
        path = cwd + '/keys/payment.skey.aes'
        if os.path.isfile(path):

            try:
                salt = load_salt(cwd + '/keys/salt.salt')
                kdf = Scrypt(salt=salt, length=32, n=2**14, r=8, p=1,backend=default_backend())
                key = kdf.derive(password.encode())
                b64key = base64.urlsafe_b64encode(key)
                ddata = decrypt(cwd + '/keys/payment.skey.aes',b64key)
                payment_skey = PaymentSigningKey.from_json(ddata.decode())
                payment_skey.save(cwd+ '/keys/payment.skey')
                #if unencrypted key generated delete aes version
                path = cwd + '/keys/payment.skey'
                if os.path.isfile(path):
                    os.remove(cwd + '/keys/payment.skey.aes')
                path = cwd + '/keys/salt.salt'
                if os.path.isfile(path):
                    os.remove(cwd + '/keys/salt.salt')
                return('Key Decrypted successfully - unencrypted key saved to keys directory')
            except Exception as e:
                print(e)
                return str(e)
        else:
            return 'No Key File Present in Keys Directory'
    elif n > 0  and len(password) < 8:
            return 'Password must be 8 or more characters'
    else:
        return f''
        

