A Cardano wallet interface written predominantly with Dash and Pycardano.

You will need a cardano-node with ogmios or a blockfrost key to use this tool.

You can generate a key @ https://blockfrost.io/

pip install pycardano
pip install dash
pip install python-dotenv
pip install cryptography
pip install base64
pip install dash-bootstrap-components
pip install flask

Create a .env File in the root directory to insert blockfrost keys and to specify UTXOS to exclude from transactions (collateral UTXOs)

BF_MAINNET=<mainnet...>
BF_PREPROD=<preprod...>
NETWORK=MAINNET
COLD_ADDRESS=
EXCLUDE_UTXOS='{"addr1...":"txHash#txId"}'




