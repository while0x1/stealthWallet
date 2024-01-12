import json
import requests

def getUtxos(chain_context,address, stake_address):
    utxos = chain_context.utxos(str(address))
    utxosCBOR = []
    balance = 0
    #print(utxos[0].to_cbor_hex())
    for n in utxos:
        balance += n.output.amount.coin
        utxosCBOR.append({n.input.transaction_id.payload.hex()+'#'+str(n.input.index):n.to_cbor_hex()})
    balance = round((balance/1000000),2)  
    assetlist = []
    nlist = []

    for u in utxos:                    
        if u.output.amount.multi_asset:
            for a in u.output.amount.multi_asset:
                policy = a.payload.hex()
                asset = u.output.amount.multi_asset[a]
                for n in asset:
                    try:
                        assetName = n.payload.decode()
                    except:
                        assetName = n.payload.decode('ascii','replace')
                    assetAmount = asset[n]
                    assetNameHex = str(n)

                    address = str(u.output.address)
                    assetlist.append({'policy':policy,'assethex':assetNameHex,'amount':str(assetAmount),'assetname':assetName})
        
    for l in assetlist:
        exclude = False
        for c in nlist:
            if l['policy'] == c['policy'] and l['assethex'] == c['assethex']:
                exclude = True
        if not exclude:
            nlist.append(l)
            
    queryarray = []
    for i in nlist:
        
        count = 0
        for a in assetlist:
            #asset_name
            if  i['policy'] == a['policy'] and i['assethex'] == a['assethex'] :
                count += int(a['amount'])
        print(i['assetname'],count)
        i['amount'] = str(count)
        queryarray.append([i['policy'],i['assethex']])

    dob = {'_asset_list': queryarray} 

    stake_info = ''
    if stake_address != '':
        for i in range(1,4):
            r = requests.post("https://api.koios.rest/api/v0/account_info",json={'_stake_addresses': [[str(stake_address)]]})
            if r.status_code == 200:
                stake_info = json.loads(r.content)
                print(stake_info)
                break

    if len(stake_info) == 0 or stake_address == '' or stake_info[0]['delegated_pool'] == None:
        ticker = 'Unstaked'
    else:
        print('You are Here!')
        pool_id = stake_info[0]['delegated_pool']
        ticker = ''
        for i in range(1,4):
            r = requests.post("https://api.koios.rest/api/v0/pool_info",json={'_pool_bech32_ids': [[pool_id]]})
            if r.status_code == 200:
                pool_info = json.loads(r.content)
                break
        ticker = pool_info[0]['meta_json']['ticker']
    walletinfo = {'balance':balance,'address':address.encode(),'ticker':ticker, 'stake_address': str(stake_address), 'assets': nlist,'utxos':utxosCBOR}
    print(walletinfo)
    return(walletinfo)