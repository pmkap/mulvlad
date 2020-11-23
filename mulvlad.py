import importlib.util
import random
import subprocess

import requests
from pyroute2 import IPRoute, WireGuard

# import global config file
spec = importlib.util.spec_from_file_location('config', '/usr/local/etc/mulvlad/config.py')
config = importlib.util.module_from_spec(spec)
spec.loader.exec_module(config)


def pick_relay():
    r = requests.get('https://api.mullvad.net/app/v1/relays')
    relays =  r.json()['wireguard']['relays']

    relays = [r for r in relays if r['active'] and 'de-' in r['location']]

    owned = [r for r in relays if r['owned']]
    rented = [r for r in relays if not r['owned']]
    
    picked = random.choice(owned) if owned else random.choice(rented)
    return picked['ipv4_addr_in'], picked['public_key']


def replace_key(new):
    """Replace public key on the Mullvad servers via the API.
    Whenever a key is pushed to Mullvad.net, remember the key also in /var/local/mulvlad/pubkey so that we know which key to replace on the mullvad servers the next time."""
    try:
        with open('/var/local/mulvlad/pubkey', 'r') as file:
            old = file.read().strip()
    except FileNotFoundError:
        # if there is no remembered key just use anything for the API call. Apparently it doesn't matter.
        old='H9TjgrQ2DIu5JE3KdgEelDBeKf1MBwruJu6Ia86ZHxs='

    r = requests.post(
            'https://api.mullvad.net/app/v1/replace-wireguard-key',
            headers={'Authorization': f'Token {config.ACCOUNT}'},
            json={'old': old, 'new': new})

    if 'error' in r.json():
        raise RuntimeError(str(r.json()))

    else:
        with open('/var/local/mulvlad/pubkey', 'w') as file:
            file.write(new)
        return r.json()['ipv4_address']


def create_interface():
    ip = IPRoute()
    interfaces = [i[0].dump()['attrs'][0][1] for i in ip.get_links()]
    if config.IFNAME not in interfaces:
        ip.link('add', ifname=config.IFNAME, kind='wireguard')
        idx = ip.link_lookup(ifname=config.IFNAME)[0]
        ip.link('set', index=idx, state='up')
    else:
        # interface already exists, delete and recreate
        idx = ip.link_lookup(ifname=config.IFNAME)[0]
        ip.link('del', index=idx)
        ip.link('add', ifname=config.IFNAME, kind='wireguard')
        idx = ip.link_lookup(ifname=config.IFNAME)[0]
        ip.link('set', index=idx, state='up')


def add_addr(client_ip):
    ip = IPRoute()
    idx = ip.link_lookup(ifname=config.IFNAME)[0]

    address, prefixlen = client_ip.split('/')
    prefixlen = int(prefixlen)

    ip.flush_addr(index=idx)
    ip.addr('add', index=idx, address=address, prefixlen=prefixlen)


def wg_set(**kwargs):
    wg = WireGuard()
    
    interface_kwargs = ['private_key', 'fwmark', 'listen_port']
    peer_kwargs = ['public_key', 'remove', 'preshared_key', 'endpoint_addr', 'endpoint_port', 'persistent_keepalive', 'allowed_ips']
    interface = {}
    peer = {}
    for arg, value in kwargs.items():
        if arg in interface_kwargs:
            interface[arg] = value
        elif arg in peer_kwargs:
            peer[arg] = value

    if 'endpoint_addr' in peer and 'endpoint_port' not in peer:
        peer['endpoint_port'] = 51820
    
    print(f'interface: {interface}\npeer: {peer}')
    if peer:
        wg.set(config.IFNAME, **interface, peer=peer)
    else:
        wg.set(config.IFNAME, **interface)


def add_routes():
    ip = IPRoute()
    idx = ip.link_lookup(ifname=config.IFNAME)[0]
    for i in config.ALLOWED_IPS:
        ip.route('add', dst=i, oif=idx)


def genkeypair():
    p = subprocess.run("wg genkey".split(), stdout=subprocess.PIPE)
    privkey = p.stdout.strip()
    p = subprocess.run("wg pubkey".split(), input=privkey, stdout=subprocess.PIPE)
    pubkey = p.stdout.strip()
    
    return privkey.decode(), pubkey.decode()


def start():
    privkey, pubkey = genkeypair()
    server_ip, server_pubkey = pick_relay()
    client_ip = replace_key(pubkey)
    create_interface()
    add_addr(client_ip)
    wg_set(private_key=privkey, public_key=server_pubkey, endpoint_addr=server_ip, allowed_ips=config.ALLOWED_IPS)
    add_routes()


def rotate():
    privkey, pubkey = genkeypair()
    address = replace_key(pubkey)
    add_addr(address)
    wg_set(private_key=privkey)
    add_routes()


def switch_relay():
    wg = WireGuard()
    old_server_pubkey = wg.info(config.IFNAME)[0].WGDEVICE_A_PEERS['value'][0].WGPEER_A_PUBLIC_KEY['value'].decode()
    wg_set(remove=True, public_key=old_server_pubkey)

    server_ip, server_pubkey = pick_relay()
    wg_set(endpoint_addr=server_ip, public_key=server_pubkey, allowed_ips=config.ALLOWED_IPS)
