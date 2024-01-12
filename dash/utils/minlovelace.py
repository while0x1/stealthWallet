from pycardano import ChainContext, TransactionOutput
def min_lovelace_post_alonzo(output: TransactionOutput, context: ChainContext) -> int:

    constant_overhead = 160
    amt = output.amount
    if amt.coin == 0:
        amt.coin = 1000000
    # Make sure we are using post-alonzo output
    tmp_out = TransactionOutput(output.address,output.amount,output.datum_hash,output.datum,output.script,True,)
    return (constant_overhead + len(tmp_out.to_cbor("bytes"))) * context.protocol_param.coins_per_utxo_byte