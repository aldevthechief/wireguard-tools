import argparse
import json
import requests
from datetime import datetime
from generate_packet import DEFAULT_SNI, I1_GENERATORS
from wireguard_tools import WireguardKey

parser = argparse.ArgumentParser(description='Generate an AmneziaWG WARP config.')
parser.add_argument(
    '--i1',
    choices=I1_GENERATORS,
    default='stun',
    help='packet style (stun by default)',
)
parser.add_argument(
    '-p',
    '--port',
    type=int,
    choices=(2408, 4500),
    default=2408,
    help='endpoint port (2408 by default)',
)
parser.add_argument(
    '-d',
    '--dns',
    default='cloudflare',
    help=(
        'DNS provider or custom comma-separated addresses; '
        'examples: cloudflare, google, "9.9.9.9, 149.112.112.112"'
    ),
)
parser.add_argument(
    '-k',
    '--keepalive',
    type=int,
    default=5,
    help='PersistentKeepalive value (default: 5)',
)
parser.add_argument(
    '-do',
    '--domain',
    metavar='DOMAIN',
    default=DEFAULT_SNI,
    help=f'domain used to generate QUIC packets ({DEFAULT_SNI} by default)',
)
args = parser.parse_args()

dns_servers = {
    'cloudflare': '1.1.1.1, 2606:4700:4700::1111, 1.0.0.1, 2606:4700:4700::1001',
    'google': '8.8.8.8, 2001:4860:4860::8888, 8.8.4.4, 2001:4860:4860::8844',
}
dns = dns_servers.get(args.dns.lower(), args.dns)
i1_generator = I1_GENERATORS[args.i1]
i1 = i1_generator() if args.i1 == 'stun' else i1_generator(sni=args.domain)

private_key = WireguardKey.generate()
public_key = private_key.public_key()

curr_time = datetime.now().strftime('%y%m%d%H%M')
api_link = f'https://api.cloudflareclient.com/v0i{curr_time}/reg'

headers = {
    'user-agent' : '',
    'content-type' : 'application/json'
}

d = {
    'install_id' : '',
    'tos' : datetime.now().isoformat()[:-7] + '.000Z',
    'key': str(public_key),
    'fcm_token' : '',
    'type' : 'android',
    'locale' : 'en_US'
}

response = requests.post(url=api_link, data=json.dumps(d).replace(' ', ''), headers=headers).json()

user_id = response['result']['id']
token = response['result']['token']

headers = {
    'user-agent': '',
    'content-type': 'application/json',
    'authorization': f'Bearer {token}'
}

api_link += f'/{user_id}'
response = requests.patch(url=api_link, data='{"warp_enabled":true}', headers=headers).json()

config = response['result']['config']

peer_key = config['peers'][0]['public_key']
endpoint = config['peers'][0]['endpoint']['host']
address_ipv4 = config['interface']['addresses']['v4']
address_ipv6 = config['interface']['addresses']['v6']
ports = config['peers'][0]['endpoint']['ports']

s = f'''[Interface]
PrivateKey = {private_key}
Jc = 4
Jmin = 40
Jmax = 70
H1 = 1
H2 = 2
H3 = 3
H4 = 4
MTU = 1280
Address = {address_ipv4}, {address_ipv6}
DNS = {dns}
{i1}

[Peer]
PublicKey = {peer_key}
AllowedIPs = 0.0.0.0/0, ::/0
Endpoint = engage.cloudflareclient.com:{args.port}
PersistentKeepalive = {args.keepalive}'''

with open('WARP.conf', 'w') as f:
    print(s, file=f)
