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



dash.register_page(__name__, path="/encrypt")

cwd = os.getcwd()


form = dbc.Form(
    dbc.Row(
        [

            dbc.Label('Encrypts a key present @  ~/StealthWallet/dash/keys/payment.skey'),
            dbc.Label('Saves encrypted key and salt security file to disk'),
            dbc.Label('Removes unencrypted key from disk'),
            dbc.Input(type="password", placeholder="Enter encryption password", id='enc-password', value=""),

            dbc.Button("Encrypt",id="enc-submit", color="primary", n_clicks=0)
        ],
        className="g-2",
    )
)

layout = html.Div([
    dbc.Container([
        html.H1("Encrypt",style = {'textAlign':'center','marginTop':40,'marginBottom':40}),
        dbc.Row([
            dbc.Col(
                form,
                width={"size": 6, "offset": 3},
            ),
            html.Div(dbc.Col(id='enc-output',
                             width={"size": 6, "offset": 5}),
                     ),
        ],className="row-gap-1"
        ),
        
        
    ])
],id="enc-div",style={"min-height":"100vh","display":"block"})


@callback(
    Output("enc-output", "children"), [Input("enc-submit", "n_clicks")],
    [State('enc-password', 'value')],
)
def on_button_click(n,password):
    #033c7a00ae33e9a0fa6802b388ccfa5ca9633d712231c41c468c2d39
    if n>0 and len(password) > 7:
        #print(password)
        path = cwd + '/keys/payment.skey'
        if os.path.isfile(path):

            try:
                salt = secrets.token_bytes(16)
                kdf = Scrypt(salt=salt, length=32, n=2**14, r=8, p=1,backend=default_backend())
                with open(cwd + "/keys/salt.salt", "wb") as salt_file:
                    salt_file.write(salt)
                key = kdf.derive(password.encode())
                b64key = base64.urlsafe_b64encode(key)
                encrypt(cwd + '/keys/payment.skey',b64key)
                #if key generated delete unencrypted version
                path = cwd + '/keys/payment.skey.aes'
                if os.path.isfile(path):
                    os.remove(cwd + '/keys/payment.skey')
                return('Key Encrypted successfully - key saved to keys directory')
            except Exception as e:
                print(e)
                return str(e)
        else:
            return 'No Key File Present'
    elif n>0 and len(password) < 8:
        return 'Password must be a minimum of 8 characters'
        
    else:
        return f''
        

