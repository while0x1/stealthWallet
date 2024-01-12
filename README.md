#A Cardano wallet interface written predominantly with Dash and Pycardano.

#You will need a cardano-node with ogmios or a blockfrost key to use this tool.

git clone https://github.com/while0x1/stealthWallet.git

cd stealthWallet

#generate a key @ https://blockfrost.io/

pip install pycardano dash python-dotenv cryptography dash-bootstrap-components flask

Create a .env File in the root directory to insert blockfrost keys and to specify UTXOS to exclude from transactions (collateral UTXOs)

BF_MAINNET=<mainnet...>

BF_PREPROD=<preprod...>

NETWORK=MAINNET

COLD_ADDRESS=

EXCLUDE_UTXOS='{"addr1...":"txHash#txId"}'

cd dash

python3 app.py

