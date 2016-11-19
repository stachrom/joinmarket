#! /usr/bin/env python
from __future__ import absolute_import, print_function

import socket, time, random, sys, datetime
from struct import pack, unpack

from joinmarket.configure import load_program_config, get_network
from joinmarket.socks import socksocket, setdefaultproxy, PROXY_TYPE_SOCKS5
from joinmarket.support import get_log

import bitcoin as btc
import socks
log = get_log()

PROTOCOL_VERSION = 70012
DEFAULT_USER_AGENT = '/JoinMarket:0.2.3/'
RELAY_TX_VERSION = 70001


TESTNET_DNS_SEEDS = [
    "testnet-seed.breadwallet.com.", "testnet-seed.bitcoin.petertodd.org.",
    "testnet-seed.bluematt.me.", "testnet-seed.bitcoin.schildbach.de."]

MAINNET_DNS_SEEDS = [
    "seed.breadwallet.com.", "seed.bitcoin.sipa.be.", "dnsseed.bluematt.me.",
    "dnsseed.bitcoin.dashjr.org.", "seed.bitcoinstats.com.",
    "bitseed.xf2.org.", "seed.bitcoin.jonasschnelli.ch."]

def ip_to_hex(ip_str):
    #ipv4 only for now
    return socket.inet_pton(socket.AF_INET, ip_str)

def create_net_addr(hexip, port): #doesnt contain time as in bitcoin wiki
    services = 0
    return pack("<Q16s", services, '\x00'*10 +
        '\xFF\xFF' + hexip) + pack(">H", port)

def create_var_str(s):
    return btc.num_to_var_int(len(s)) + s

def read_int(ptr, payload, n, littleendian=True):
    data = payload[ptr[0] : ptr[0]+n]
    if littleendian:
        data = data[::-1]
    ret =  btc.decode(data, 256)
    ptr[0] += n
    return ret

def read_var_int(ptr, payload):
    val = ord(payload[ptr[0]])
    ptr[0] += 1
    if val < 253:
        return val
    return read_int(ptr, payload, 2**(val - 252))

def read_var_str(ptr, payload):
    l = read_var_int(ptr, payload)
    ret = payload[ptr[0] : ptr[0] + l]
    ptr[0] += l
    return ret

def read_net_addr(ptr, payload):
    timestamp = read_int(ptr, payload, 4)
    services = read_int(ptr, payload, 8)
    ip_hex = payload[ptr[0] : ptr[0] + 16]
    ptr[0] += 16
    port = read_int(ptr, payload, 2, False)
    return timestamp, services, ip_hex, port

def ip_hex_to_str(ip_hex):
    #https://en.wikipedia.org/wiki/IPv6#IPv4-mapped_IPv6_addresses
    #https://www.cypherpunk.at/onioncat_trac/wiki/OnionCat
    if ip_hex[:14] == '\x00'*10 + '\xff'*2:
        #ipv4 mapped ipv6 addr
        return socket.inet_ntoa(ip_hex[12:])
    elif ip_hex[:6] == '\xfd\x87\xd8\x7e\xeb\x43':
        return base64.b32encode(ip_hex[6:]).lower() + '.onion'
    else:
        return socket.inet_ntop(socket.AF_INET6, ip_hex)

class P2PMessageHandler(object):
    def __init__(self):
        pass

    def handle_message(self, p2p, command, length, payload):
        ptr = [0]
        if command == 'version':
            version = read_int(ptr, payload, 4)
            services = read_int(ptr, payload, 8)
            timestamp = read_int(ptr, payload, 8)
            addr_recv_services = read_int(ptr, payload, 8)
            addr_recv_ip = payload[ptr[0] : ptr[0]+16]
            ptr[0] += 16
            addr_recv_port = read_int(ptr, payload, 2, False)
            addr_trans_services = read_int(ptr, payload, 8)
            addr_trans_ip = payload[ptr[0] : ptr[0]+16]
            ptr[0] += 16
            addr_trans_port = read_int(ptr, payload, 2, False)
            ptr[0] += 8 #skip over nonce
            user_agent = read_var_str(ptr, payload)
            start_height = read_int(ptr, payload, 4)
            if version > RELAY_TX_VERSION:
                relay = read_int(ptr, payload, 1) != 0
            else:
                relay = True
            log.debug(('peer version message: version=%d services=0x%x'
                + ' timestamp=%s user_agent=%s start_height=%d') % (version,
                services, str(datetime.datetime.fromtimestamp(timestamp)),
                user_agent, start_height))
            log.debug('their addr = ' + ip_hex_to_str(addr_trans_ip) + ':'
                + str(addr_trans_port) + ' our address according to them = '
                + ip_hex_to_str(addr_recv_ip) + ':' + str(addr_recv_port))
            p2p.sock.sendall(p2p.create_message('verack', ''))
        elif command == 'verack':
            log.debug('connected to peer')
            self.on_connected(p2p)
        elif command == 'ping':
            p2p.sock.sendall(p2p.create_message('pong', payload))

    def on_connected(self, p2p):
        pass

class P2PProtocol(object):
    def __init__(self, p2p_message_handler, remote_hostport=None,
            testnet=False, user_agent=DEFAULT_USER_AGENT, relay_txes=False,
            socks5_hostport=None):
        '''
        if remote_hostport = None, use dns_seeds for auto finding peers
        if socks5_hostport != None, use that proxy 
        relax_txes controls whether the peer will send you unconfirmed txes
        '''
        self.p2p_message_handler = p2p_message_handler
        self.testnet = testnet
        self.user_agent = user_agent
        self.relay_txes = relay_txes
        self.socks5_hostport = socks5_hostport
        if not self.testnet:
            self.magic = 0xd9b4bef9 #mainnet
        else:
            if testnet == True:
                self.magic = 0x0709110b #testnet
            else:
                self.magic = 0xdab5bffa #regtest
        self.closed = False
        self.connection_attempts = 4

        if remote_hostport != None:
            self.remote_hostport = remote_hostport
            self.dns_seeds = []
        else:
            if self.testnet:
                self.dns_seeds = TESTNET_DNS_SEEDS
                port = 18333
            else:
                self.dns_seeds = MAINNET_DNS_SEEDS   
                port = 8333
            self.dns_index = random.randrange(len(self.dns_seeds))
            self.remote_hostport = (self.dns_seeds[self.dns_index], port)

    def run(self):
        services = 0 #headers only
        st = int(time.time())
        nonce = 0
        start_height = 0
        buffer_size = 4096
        sock_fd = None

        localhost_netaddr = create_net_addr(ip_to_hex('127.0.0.1'), 0)
        version_message = (pack('<iQQ', PROTOCOL_VERSION, services, st)
            + localhost_netaddr
            + localhost_netaddr
            + pack('<Q', nonce)
            + create_var_str(self.user_agent)
            + pack('<I', start_height)
            + ('\x01' if self.relay_txes else '\x00'))
        data = self.create_message('version', version_message)
        while sock_fd == None:
            try:
                log.info('connecting to bitcoin peer (magic=' + hex(self.magic)
                    + ' at ' + str(self.remote_hostport) + ' with proxy ' + 
                    str(self.socks5_hostport))
                if self.socks5_hostport == None:
                    self.sock = socket.socket(socket.AF_INET,
                        socket.SOCK_STREAM)
                else:
                    setdefaultproxy(PROXY_TYPE_SOCKS5, self.socks5_hostport[0],
                        self.socks5_hostport[1], True)
                    self.sock = socksocket()
                self.sock.settimeout(20)
                self.sock.connect(self.remote_hostport)
                self.sock.settimeout(None)
                sock_fd = self.sock.makefile('r', buffer_size)
                self.sock.sendall(data)
            except IOError as e:
                if len(self.dns_seeds) == 0:
                    raise e
                else:
                    ##cycle to the next dns seed
                    time.sleep(0.5)
                    self.connection_attempts -= 1
                    if self.connection_attempts == 0:
                        raise e
                    self.dns_index = (self.dns_index + 1) % len(self.dns_seeds)
                    self.remote_hostport = (self.dns_seeds[self.dns_index],
                        self.remote_hostport[1])

        self.closed = False
        try:
            while not self.closed:
                read_4 = sock_fd.read(4)
                if len(read_4) == 0:
                    raise EOFError()
                net_magic = unpack('<I', read_4)[0]
                if net_magic != self.magic:
                    raise IOError('wrong MAGIC: ' + hex(net_magic))
                command = sock_fd.read(12)
                length = unpack('<I', sock_fd.read(4))[0]
                checksum = sock_fd.read(4)
                payload = sock_fd.read(length)

                if btc.bin_dbl_sha256(payload)[:4] != checksum:
                    log.error('wrong checksum, dropping message')
                    continue
                command = command.strip('\0')
                self.p2p_message_handler.handle_message(self, command,
                    length, payload)
        except IOError as e:
            import traceback
            log.error("logging traceback from %s: \n" %
                traceback.format_exc())
            self.closed = True
        finally:
            try:
                sock_fd.close()
                self.sock.close()
            except Exception as e:
                pass

    def close(self):
        self.closed = True

    def create_message(self, command, payload):
        return (pack("<I12sI", self.magic, command, len(payload))
            + btc.bin_dbl_sha256(payload)[:4] + payload)

class P2PBroadcastTx(P2PMessageHandler):
    def __init__(self, txhex):
        self.txhex = txhex
        self.txid = btc.bin_txhash(self.txhex)[::-1]
        log.info('broadcasting txid ' + str(self.txid[::-1].encode('hex')) +
            ' on ' + get_network())

    def on_connected(self, p2p):
        log.debug('sending inv')
        MSG = 1 #msg_tx
        inv_payload = pack('<BI', 1, MSG) + self.txid
        p2p.sock.sendall(p2p.create_message('inv', inv_payload))

    def handle_message(self, p2p, command, length, payload):
        P2PMessageHandler.handle_message(self, p2p, command, length, payload)
        ptr = [0]
        if command == 'getdata':
            count = read_var_int(ptr, payload)
            log.debug('getdata count=' + str(count))
            for i in xrange(count):
                msg_type = read_int(ptr, payload, 4)
                hash_id = payload[ptr[0] : ptr[0] + 32]
                ptr[0] += 32
                log.debug('hashid=' + hash_id[::-1].encode('hex') + ' txid='
                    + self.txid[::-1].encode('hex'))
                if hash_id == self.txid:
                    log.info('uploading tx ' + hash_id[::-1].encode('hex'))
                    p2p.sock.sendall(p2p.create_message('tx',
                        self.txhex.decode('hex')))
                    time.sleep(3)
                    p2p.close()


if __name__ == "__main__":
    load_program_config()

    class P2PGetAddresses(P2PMessageHandler):
        def on_connected(self, p2p):
            log.info('sending getaddr')
            p2p.sock.sendall(p2p.create_message('getaddr', ''))

        def handle_message(self, p2p, command, length, payload):
            P2PMessageHandler.handle_message(self, p2p, command, length,
                payload)
            ptr = [0]
            if command == 'addr':
                addr_count = read_var_int(ptr, payload)
                log.info('got ' + str(addr_count) + ' addresses')
                for i in xrange(addr_count):
                    timestamp, services, ip_hex, port = read_net_addr(ptr,
                        payload)
                    log.info('timestamp=%s services=0x%02x addr=%s:%d' % (
                        str(datetime.datetime.fromtimestamp(timestamp)),
                        services, ip_hex_to_str(ip_hex), port))

    if len(sys.argv) > 1:
        p2p_msg_handler = P2PBroadcastTx(sys.argv[1])
    else:
        p2p_msg_handler = P2PGetAddresses()
    tor = False
    p2p = P2PProtocol(p2p_msg_handler, testnet=(get_network() != 'mainnet'),
        socks5_hostport=(('localhost', 9150) if tor else None))
    p2p.run()
