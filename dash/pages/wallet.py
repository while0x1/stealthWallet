
from dash import html,  Input, Output, callback, State
import dash
import dash_bootstrap_components as dbc
from dotenv import dotenv_values
from dash import Dash, dcc, html, Input, Output, callback, State, ctx, dash_table
from pycardano import *
import datetime
import os
from blockfrost import ApiUrls
import requests
import json
import base64
from utils.crypto import *
from utils.getutxos import *
from utils.parsekeys import *


cwd = os.getcwd()
env_dict = dotenv_values()

BF_MAINNET = env_dict.get('BF_MAINNET')
COLD_ADDRESS = env_dict.get('COLD_ADDRESS')
BF_PREPROD = env_dict.get('BF_PREPROD')
EXCLUDE_UTXOS_S = env_dict.get('EXCLUDE_UTXOS')
EXCLUDE_UTXOS = json.loads(EXCLUDE_UTXOS_S)
print(EXCLUDE_UTXOS)

net = env_dict.get('NETWORK')
if net == 'MAINNET':
    pyNet = Network.MAINNET
else:
    pyNet = Network.TESTNET
#min_lovelace_post_alonzo

if pyNet == Network.MAINNET:
    BF_PROJ_ID  = BF_MAINNET
    chain_context = BlockFrostChainContext(project_id=BF_PROJ_ID,base_url=ApiUrls.mainnet.value,)
                    #from_address = Address(payment_vkey.hash(),network=Network.MAINNET)
else:
    BF_PROJ_ID = BF_PREPROD
    chain_context = BlockFrostChainContext(project_id=BF_PROJ_ID,base_url=ApiUrls.preprod.value,)          

dash.register_page(__name__, path="/wallet")

token_selector = dcc.Dropdown(
        id = 'token_selector',
        style={'color':'black'},
        #options = [{'label':v, 'value':k } for k,v in ddict.items()],
        value = None,
        placeholder = 'Select a Token',
        multi=False
        )

tx_form = dbc.Form(
    dbc.Row(
        [
            
            dbc.Col(dbc.Input(type='text',id='output_address',placeholder="Output Address addr1...")),
            dbc.Label('Ada Amount:'),
            dbc.Col(dbc.Input(type='number',id='ADA'),width='auto'),
            dbc.Label('Asset Amount:'),
            dbc.Col(dbc.Input(type='number',id='asset_amount'),width='auto'),
            dbc.Col(token_selector),
            dbc.Input(type='text',id='assetid',placeholder="policy.hexname",disabled=True),
            dbc.Label('Exclude Utxos:'),
            dbc.Col(dbc.Input(type='text',id='exclude',placeholder='txHash#txId'),width='50%'),
            dbc.Col(dbc.Input(type="password", placeholder="Enter decryption key if necessary", id='tx_password', value="")),
            #'https://cexplorer.io/tx/txhash'
            #html.Div(id="tx_message"),
            html.Div(html.A(href=None, target="_blank", id='tx_message'),id='tx_link', style={'display':'none'}),

            dbc.Row([
                dbc.Col(dbc.Button("Submit",id="tx_submit", color="primary", n_clicks=0),width='auto'),
                dbc.Col(dbc.Button("CBOR",id="aircbor", color="primary", n_clicks=0),width='auto'),
            ],className="g-2")
        ],
        className="g-2",)
)

upload = dcc.Upload(
        id='upload-keys',
        children=html.Div([
            'Drag or Select stake and payment keys',
        ]),style={
            'width': 'auto',
            'height': '60px',
            'lineHeight': '60px',
            'borderWidth': '1px',
            'borderStyle': 'dashed',
            'borderRadius': '5px',
            'textAlign': 'center',
            'margin': '10px',
        },
        multiple=True,
    )

keys_modal = html.Div(
    [
        dbc.Button("Keys", id="keysopen", n_clicks=0),
        dbc.Modal(
            [
                dbc.ModalHeader(dbc.ModalTitle("Upload keys")),
                dbc.ModalBody(html.Div([
                                        #dbc.Input(type="password", placeholder="Enter decryption password if required", id='wpassword', value=""),
                                        upload,
                                        html.Div(id='output-image-upload')
                                        ])
                ),
                dbc.ModalFooter(
                    dbc.Button(
                        "Close", id="keysclose", className="ms-auto", n_clicks=0
                    )
                ),
            ],
            id="keysmodal",
            is_open=False,
        ),
    ]
)

send_modal = html.Div(
    [
        dbc.Button("Send", id="sendopen", n_clicks=0),
        dbc.Modal(
            [
                dbc.ModalHeader(dbc.ModalTitle("Transaction")),
                dbc.ModalBody(html.Div([tx_form
                                        #dbc.Input(type="password", placeholder="Enter decryption password if required", id='wpassword', value=""),
                                        ])
                ),
                dbc.ModalFooter(
                    dbc.Button(
                        "Close", id="sendclose", className="ms-auto", n_clicks=0
                    )
                ),
            ],
            id="sendmodal",
            is_open=False,
            size="xl",
        ),
    ]
)

recv_modal = html.Div(
    [
        dbc.Button("Receive", id="recvopen", n_clicks=0),
        dbc.Modal(
            [
                dbc.ModalHeader(dbc.ModalTitle("Receive Address")),
                dbc.ModalBody(html.Div(id='recv_address'
                                        #dbc.Input(type="password", placeholder="Enter decryption password if required", id='wpassword', value=""),
                                        )
                ),
                dbc.ModalFooter(
                    dbc.Button(
                        "Close", id="recvclose", className="ms-auto", n_clicks=0
                    )
                ),
            ],
            id="recvmodal",
            is_open=False,
            size="xl",
        ),
    ]
)

air_modal = html.Div(
    [
        dbc.Button("Air", id="airopen", n_clicks=0),
        dbc.Modal(
            [
                dbc.ModalHeader(dbc.ModalTitle("Air Gap Transaction")),
                dbc.ModalBody([html.Div(id='air_address'),
                              dbc.Label('UnsignedCBOR'),
                              dbc.Textarea(size="lg",id="unsigned_cbor",rows=5,disabled=True),
                              dbc.Label('SignedCBOR'),
                              dbc.Textarea(size="lg",id="signed_cbor",rows=5,disabled=False),
                              html.Br(),
                              dbc.Button("Submit", id="airsubmit", className="ms-auto", n_clicks=0),
                              #dbc.Input(id="unsigned_cbor", type="text", disabled=True),
                              html.Div(id="air_message"),]
                ),
                dbc.ModalFooter(
                    dbc.Button(
                        "Close", id="airclose", className="ms-auto", n_clicks=0
                    )
                ),
            ],
            id="airmodal",
            is_open=False,
            size="xl",
        ),
    ]
)



@callback(
    Output("tx_message", "children"),
    Output("tx_message", "href"),
    Output("tx_link", "style"),  
    Input("tx_submit", "n_clicks"),
    State('tx_password', 'value'),
    State('wallet_info','data'),
    State('output_address','value'),
    State('ADA','value'),
    State('upload-keys', 'contents'),
    State('upload-keys', 'filename'),
    State('address_store', 'data'),
    State('exclude', 'value'),
    State('assetid', 'value'),
    State('asset_amount', 'value'),
)
def tx_submit_click(n,password,wallet_info,output_address,ADA,keycontents,keynames,address_store,exclude,assetid,asset_amount):
    exclude_utxo = ''
    if n > 0:
        
        try:
            if ADA is None:
                raise Exception
            print(output_address)
            print(ADA)

            keyDict = getKeys(keynames,keycontents,password)
            #print(keyDict)
            #print(wallet_info)
            print(address_store)
            lovelaces = int(ADA) * 1000000
            change_address = Address.from_primitive(address_store)
            builder = TransactionBuilder(chain_context)
            builder.add_input_address(change_address)
            for n in wallet_info:
                if exclude in n:
                    print(n[exclude])
                    exclude_utxo = UTxO.from_cbor(n[exclude])
            if exclude_utxo != '':
                builder.excluded_inputs.append(exclude_utxo)
            #pyoutputaddress = Address.from_primitive(output_address)
            if len(EXCLUDE_UTXOS) > 0:
                for n in EXCLUDE_UTXOS:
                    if address_store == n:
                        for q in wallet_info:
                            if EXCLUDE_UTXOS[n] in q:
                                exclude_utxo = UTxO.from_cbor(q[EXCLUDE_UTXOS[n]])
                                #print(exclude_utxo)
                                builder.excluded_inputs.append(exclude_utxo)    
            if ADA is not None:
                builder.add_output(TransactionOutput.from_primitive([output_address, lovelaces]))
            if assetid is not None and asset_amount is not None:

                policy = assetid[0:assetid.find('.')]
                hexname = assetid[assetid.find('.')+1:]

                swap_asset = MultiAsset.from_primitive({bytes.fromhex(policy): {bytes.fromhex(hexname): asset_amount}})
                print(swap_asset)

                pyaddress = Address.from_primitive(output_address)
                min_val = min_lovelace(chain_context, output=TransactionOutput(pyaddress, Value(0, swap_asset)))
                print(min_val)
                builder.add_output(TransactionOutput(output_address, Value(min_val, swap_asset)))
            #print(keyDict[0])
            #builder.required_signers = [ExtendedVerificationKey.from_signing_key(keyDict[0]).hash()]
            signed_tx = builder.build_and_sign([keyDict[0]], change_address=change_address)
            chain_context.submit_tx(signed_tx)
            'https://cexplorer.io/tx/txhash'
            return 'Success! ' + str(signed_tx.id), 'https://cexplorer.io/tx/' + str(signed_tx.id),{'display':'block'}
            #print(wallet_info)
        except Exception as e:
            print(e)
            return 'BuildErrror: ' + str(e),'',{'display':'none'}
    else:
        return '','',{'display':'none'}
    

@callback(
    Output('unsigned_cbor', 'value'),
    Input("aircbor", "n_clicks"),
    State('wallet_info','data'),
    State('output_address','value'),
    State('ADA','value'),
    State('upload-keys', 'contents'),
    State('upload-keys', 'filename'),
    State('address_store', 'data'),
    State('exclude', 'value'),
    State('assetid', 'value'),
    State('asset_amount', 'value'),
    #State('unsigned_cbor', 'value'),
    
)
def cbor_click(n,wallet_info,output_address,ADA,keycontents,keynames,address_store,exclude,assetid,asset_amount):

    exclude_utxo = ''
    if n > 0:
        
        try:
            if ADA is None:
                raise Exception
            print(output_address)
            print(ADA)
            keyDict = getKeys(keynames,keycontents)
            print(address_store)
            lovelaces = int(ADA) * 1000000
            change_address = Address.from_primitive(address_store)
            builder = TransactionBuilder(chain_context)
            builder.add_input_address(change_address)
            for n in wallet_info:
                if exclude in n:
                    print(n[exclude])
                    exclude_utxo = UTxO.from_cbor(n[exclude])
            if exclude_utxo != '':
                builder.excluded_inputs.append(exclude_utxo)
            #pyoutputaddress = Address.from_primitive(output_address)
            if len(EXCLUDE_UTXOS) > 0:
                for n in EXCLUDE_UTXOS:
                    if address_store == n:
                        for q in wallet_info:
                            if EXCLUDE_UTXOS[n] in q:
                                exclude_utxo = UTxO.from_cbor(q[EXCLUDE_UTXOS[n]])
                                #print(exclude_utxo)
                                builder.excluded_inputs.append(exclude_utxo)    
            if ADA is not None:
                builder.add_output(TransactionOutput.from_primitive([output_address, lovelaces]))
            if assetid is not None and asset_amount is not None:

                policy = assetid[0:assetid.find('.')]
                hexname = assetid[assetid.find('.')+1:]

                swap_asset = MultiAsset.from_primitive({bytes.fromhex(policy): {bytes.fromhex(hexname): asset_amount}})
                print(swap_asset)

                pyaddress = Address.from_primitive(output_address)
                min_val = min_lovelace(chain_context, output=TransactionOutput(pyaddress, Value(0, swap_asset)))
                print(min_val)
                builder.add_output(TransactionOutput(output_address, Value(min_val, swap_asset)))
            
                #print(builder)
            raw = builder.build(change_address=change_address)
            tb = builder._build_tx_body()
            unsignedTx = tb.to_cbor_hex()
            print('ALIVE')
            print(unsignedTx)
            return unsignedTx
        except Exception as e:
            print(e)
            return 'BuildErrror: ' + str(e)
    else:
        return ''

@callback(
    Output("recvmodal", "is_open"),Output("recv_address", "children"),
    [Input("recvopen", "n_clicks"), Input("recvclose", "n_clicks")],
    [State("recvmodal", "is_open")],State('address_store', 'data')
)
def toggle_modal(n1, n2, is_open,address):
    print(address)
    #if keynames:
    #    for n in range(0,len(keynames)):
    #        print(keynames[n])
    if n1 or n2:
        return not is_open,address
    return is_open,address

@callback(
    Output("air_message", "children"),
    Output("signed_cbor", "value"),
    [Input("airsubmit", "n_clicks")],
    State('signed_cbor', 'value'),
    
)
def submit_air(n1,cbor):

    if n1 > 0:
        tx_id = ''
        if cbor is not None:
            print(cbor)
            try:  
                tx_id = chain_context.submit_tx(Transaction.from_cbor(cbor))
                return 'Success - Tx Hash: ' + tx_id,''
            except Exception as e:
                return str(e),''
                print(e)
    else:
        return '',''

@callback(
    Output("airmodal", "is_open"),
    [
     Input("airopen", "n_clicks"), 
     Input("airclose", "n_clicks"),
     Input("aircbor", "n_clicks")
     ],
    [State("airmodal", "is_open")]
)
def toggle_modal(n1, n2,n3, is_open):
    if n1 or n2 or n3:
        return not is_open
    return is_open

@callback(
    Output("keysmodal", "is_open"),
    [Input("keysopen", "n_clicks"), Input("keysclose", "n_clicks")],
    [State("keysmodal", "is_open")],
)
def toggle_modal(n1, n2, is_open):
    if n1 or n2:
        return not is_open
    return is_open

@callback(
    Output("sendmodal", "is_open"),
    Output("ADA", "value"),
    Output("asset_amount", "value"),
    Output("assetid", "value",allow_duplicate=True),
    Output("exclude", "value"),
    #allow_duplicate=True
    Output("tx_message", "children",allow_duplicate=True),
    Output("output_address", "value"),
    #
    Output("token_selector", "value"),
    Output("tx_password", "value"),
    Output("tx_link", "style",allow_duplicate=True),
    [   Input("sendopen", "n_clicks"), 
        Input("sendclose", "n_clicks"),
        Input("aircbor", "n_clicks"),
        ],
    [State("sendmodal", "is_open")],
    prevent_initial_call=True
)
def toggle_modal(n1, n2,n3, is_open):
    if n1 or n2 or n3:
        return not is_open,None,None,None,None,None,None,None,'',{'display':'none'}
    return is_open,None,None,None,None,None,None,None,'',{'display':'none'}

divs = []

def make_card(asset):
    return dbc.Col( 
    dbc.Card(
    [dbc.CardBody(
        [
            html.H4(asset['amount'], className="card-title"),
            html.B(asset['assetname'], className='card-subtitle',),
            html.P([dbc.Badge('policy', className="ms-1", id=asset['policy']),dbc.Badge('name', className="ms-1", id=asset['assethex'])],className="card-text"),
            dbc.Popover(asset['policy'],target=asset['policy'], body=True,trigger="hover",placement='bottom'),
            dbc.Popover(asset['assethex'],target=asset['assethex'], body=True,trigger="hover",placement='bottom'),
        ]
        ),
    ],
    style={"width": "14rem"}, id=asset['policy'] + asset['assetname']),className="p3"
   
    )


layout = html.Div([
    dbc.Container([
        html.Div(id='utxo_store',style={'display':'none'}),
        dcc.Store(id='address_store', data=''),
        dcc.Store(id='wallet_info',data=[]),
        html.H1("Wallet",style = {'textAlign':'center','marginTop':40,'marginBottom':40}),
        dbc.Row([
            dbc.Row([
              dbc.Col(keys_modal,width={"size": 1}),
              dbc.Col(send_modal,width={"size": 1}),
              dbc.Col(recv_modal,width={"size": 1},),
              dbc.Col(dbc.Button("Refresh", id="refresh", className="ms-auto", n_clicks=0),width={"size": 1}),
              dbc.Col(air_modal,width={"size": 1},),          
            ],justify="center",style={"padding-left":'2rem'}),
            html.H2(id='balance'),
            html.H3(id='ticker'),
            dbc.Row(divs, className='row-cols-2 row-cols-lg-4 g-2 g-lg-3', id='card-loop'),
            html.Div(dbc.Col(id='example-output',
                             width={"size": 6, "offset": 5}),
                     ),
        ]
        ),
        
        
    ])
],id="walletsDiv",style={"min-height":"100vh","display":"block"})


def parse_contents(contents, filename, date):
    return html.Div([
        html.H5(filename),
        html.H6(datetime.datetime.fromtimestamp(date)),

    ])

@callback(
    Output('assetid', 'value'),
    Input('token_selector', 'value')
)
def update_assetid(value):
    print(value)
    return value

@callback(
          Output("token_selector", "options"),
          Output('output-image-upload', 'children'),
          Output('balance', 'children'),
          Output('ticker', 'children'),
          Output('address_store', 'data'),
          Output('card-loop', 'children'),
          #Output('utxo_store', 'children'),
          Output('wallet_info', 'data'),
          Input('refresh', 'n_clicks'),
          Input('upload-keys', 'contents'),
          State('upload-keys', 'filename'),
          State('upload-keys', 'last_modified'),
              #State('wpassword', 'value'),
          )
def update_output(n_clicks,list_of_contents, list_of_names, list_of_dates):
    if list_of_contents is not None:
        walletinfo = ''
        payment_skey = ''
        payment_vkey = ''
        stake_skey = ''
        stake_vkey = ''
        address = ''
        for n in range(0,len(list_of_names)):
            if list_of_names[n] != 'salt.salt':
                b64_raw = list_of_contents[n][list_of_contents[n].find('base64')+7:]
                b64_bytes = b64_raw.encode('utf-8')
                utf_bytes = base64.b64decode(b64_bytes)
                utf_str = utf_bytes.decode('utf-8')
            if list_of_names[n] == 'payment.vkey':
                payment_vkey = PaymentVerificationKey.from_json(utf_str)
            if list_of_names[n] == 'stake.vkey':
                stake_vkey = StakeVerificationKey.from_json(utf_str)

        if isinstance(payment_vkey,key.PaymentVerificationKey) and isinstance(stake_vkey,key.StakeVerificationKey) :
            address = Address(payment_part=payment_vkey.hash(),staking_part=stake_vkey.hash(),network=pyNet)
        elif isinstance(payment_vkey,key.PaymentVerificationKey) and not isinstance(stake_vkey,key.StakeVerificationKey):
            address = Address(payment_part=payment_vkey.hash(),network=pyNet)
        ##TODO ADD aeskey support

        if len(address.encode()) > 63:
            stake_address = Address(staking_part=address.staking_part,network=pyNet)
        else:
            stake_address = ''
        #stake_address = ''
        print(address.encode())
        if len(address.encode()) > 0:
            #address=Address.from_primitive('addr1qy5r83hgd9jlhpmffz3teztzfh0dgly7kf87wvutcg8p2scq9ua4qhc9mlrel2q3gayl34r8wl2pyenuh6rt4vs7s8uql22vuk')
            try:
                walletinfo = getUtxos(chain_context,address,stake_address)
            except Exception as e:
                print('getUtxos failed')
                print(e)
        divs=[]
        token_options=[]
        for asset in walletinfo['assets']:
            print(asset)
            #options = [{'label':v, 'value':k } for k,v in ddict.items()],
            token_options.append({'label':asset['assetname'], 'value':asset['policy'] + '.'+ asset['assethex']})
            divs.append(make_card(asset))
        children = [
            parse_contents(c, n, d) for c, n, d in
            zip(list_of_contents, list_of_names, list_of_dates)]
        return token_options,children, str(walletinfo['balance']) + '₳','Pool: ' + walletinfo['ticker'], address.encode(),divs,walletinfo['utxos']

    else:
        return [],['','',''],'','','',[],[]


