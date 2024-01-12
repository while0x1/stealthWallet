#A Cardano wallet interface written predominantly with Dash and Pycardano.

#You will need a cardano-node with ogmios or a blockfrost key to use this tool.

##IMPORTANT NOTE!!
# StealthWallet does not support native token Decimals currently - you need to use the correct scaling derived
# from the cardano token registry for sending native assets!!

git clone https://github.com/while0x1/stealthWallet.git

cd stealthWallet

#generate mainnet and preprod keys @ https://blockfrost.io/

pip install pycardano dash python-dotenv cryptography dash-bootstrap-components flask

Create a .env File in the root directory to insert blockfrost keys and to specify UTXOS to exclude from transactions (collateral UTXOs)

BF_MAINNET=<mainnet...>

BF_PREPROD=<preprod...>

NETWORK=MAINNET

COLD_ADDRESS=

EXCLUDE_UTXOS='{"addr1...":"txHash#txId"}'

cd dash

python3 app.py

