#! /usr/bin/env python
from __future__ import absolute_import
'''comments here'''

import sys
import time
import random
from commontest import make_wallets
import pytest

import bitcoin as btc
from joinmarket import load_program_config, jm_single, get_p2pk_vbyte
from joinmarket import P2PProtocol, P2PBroadcastTx

def test_p2p_broadcast(setup_tx_notify):
    #listen up kids, dont do this to generate private
    #keys that hold real money, or else you'll be robbed
    src_privkey = random.getrandbits(256)
    src_privkey = btc.encode(src_privkey, 16, 64) + '01'
    src_addr = btc.privtoaddr(src_privkey, magicbyte=get_p2pk_vbyte())
    dst_addr = btc.pubtoaddr('03' + btc.encode(random.getrandbits(256), 16),
        get_p2pk_vbyte())

    jm_single().bc_interface.rpc('importaddress', [src_addr, "", False])
    jm_single().bc_interface.rpc('importaddress', [dst_addr, "", False])
    jm_single().bc_interface.rpc('generatetoaddress', [1, src_addr])
    jm_single().bc_interface.rpc('generate', [101])
    src_utxos = jm_single().bc_interface.rpc('listunspent', [0, 500,
        [src_addr]])

    inputs = [{'output': src_utxos[0]['txid'] + ':' + str(src_utxos[0]['vout']
        )}]
    outs = [{'address': dst_addr, 'value': int(src_utxos[0]['amount']*1e8)}]
    tx = btc.mktx(inputs, outs)
    tx = btc.sign(tx, 0, src_privkey)

    utxo_b = jm_single().bc_interface.rpc('listunspent', [0, 500, [dst_addr]])

    #jm_single().bc_interface.rpc('sendrawtransaction', [tx])
    p2p_msg_handler = P2PBroadcastTx(tx)
    p2p = P2PProtocol(p2p_msg_handler, testnet='regtest',
        remote_hostport=('localhost', 18444))
    p2p.run()

    jm_single().bc_interface.rpc('generate', [1])
    utxo_a  = jm_single().bc_interface.rpc('listunspent', [0, 500, [dst_addr]])

    return len(utxo_a) - 1 == len(utxo_b)

@pytest.fixture(scope="module")
def setup_tx_notify():
    load_program_config()
