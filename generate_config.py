import json
import random
import requests
from datetime import datetime
from wireguard_tools import WireguardKey

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
S1 = 0
S2 = 0
Jc = 120
Jmin = 23
Jmax = 911
H1 = 1
H2 = 2
H3 = 3
H4 = 4
MTU = 1280
Address = {address_ipv4}, {address_ipv6}
DNS = 1.1.1.1, 2606:4700:4700::1111, 1.0.0.1, 2606:4700:4700::1001

[Peer]
PublicKey = {peer_key}
AllowedIPs = 0.0.0.0/0, ::/0
Endpoint = 188.114.99.224:{random.choice(ports)}'''

with open('WARP.conf', 'w') as f:
    print(s, file=f)
    