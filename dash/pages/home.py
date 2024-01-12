from dash import html,  Input, Output, callback, State, dcc
import dash
import dash_bootstrap_components as dbc
from dotenv import dotenv_values
import datetime
import os
import io
import base64
import json
from pycardano import *
from utils.crypto import *
dash.register_page(__name__, path="/")


app = dash.Dash()
tprint()
cwd = os.getcwd()
env_dict = dotenv_values()

BF_MAINNET = env_dict.get('BF_MAINNET')
#print(BF_MAINNET)

    

layout = html.Div([
    dbc.Container([
        html.H1("Stealth Wallet",style = {'textAlign':'center','marginTop':40,'marginBottom':40}),
        html.H3('A python-based and air-gapped Cardano Wallet Solution',style = {'textAlign':'center','marginTop':40,'marginBottom':40}),
        dbc.Row([
            dbc.Col(
                html.Div('Stealth Wallet uses pycardano to create and manage Cardano keys ' \
                         'ideally on an air-gapped device. ' \
                         'The wallet GUI should be deployed onto an internet-facing device. ' \
                        'By copying transaction CBOR from the GUI to the secure-offline device for ' \
                        'signing you can safely store your crypto keys. ' \
                        'Created by While0x1'),
                width={"size": 6, "offset": 3},
            ),
            html.Div(dbc.Col(html.Img(src=app.get_asset_url('ovaling_scaled.svg')),
                             width={"size": 6, "offset": 5}),
                     ),
        ],className="row-gap-1"
        ),
        
        
    ])
],id="homediv",style={"min-height":"100vh","display":"block"})


