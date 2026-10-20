# -*- coding: utf-8 -*-
"""许可签发工具（在激活服务器/供应商侧离线使用）。

用法：
  python license_tool.py genkey                          # 生成 Ed25519 密钥对
  python license_tool.py issue -c "XX公司" -e enterprise \
         [--machine-id 指纹] [--days 365 | --permanent] -o license.lic
  python license_tool.py verify license.lic              # 用公钥验签

签发后的许可文件（.lic）交给客户在系统「授权」页导入。
私钥必须离线保管，公钥 base64 配置到客户端（环境变量 ADM_LICENSE_PUBKEY 或内置）。
"""
import argparse
import base64
import json
import sys
import uuid
from datetime import datetime, timedelta

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

KEY_DIR_DEFAULT = 'license_keys'


def canonical_bytes(payload: dict) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode('utf-8')


def genkey(key_dir=KEY_DIR_DEFAULT):
    import os
    os.makedirs(key_dir, exist_ok=True)
    priv = Ed25519PrivateKey.generate()
    pub = priv.public_key()
    priv_bytes = priv.private_bytes(serialization.Encoding.Raw,
                                    serialization.PrivateFormat.Raw,
                                    serialization.NoEncryption())
    pub_bytes = pub.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    with open(os.path.join(key_dir, 'private.key'), 'wb') as f:
        f.write(priv_bytes)
    with open(os.path.join(key_dir, 'public.key'), 'wb') as f:
        f.write(pub_bytes)
    pub_b64 = base64.b64encode(pub_bytes).decode()
    print(f'密钥已生成到 {key_dir}/')
    print(f'公钥(base64，配置到客户端 ADM_LICENSE_PUBKEY)：')
    print(pub_b64)
    print('⚠ 私钥请离线妥善保管，泄露即意味着任何人都能签发许可')


def _load_private(key_dir):
    import os
    with open(os.path.join(key_dir, 'private.key'), 'rb') as f:
        return Ed25519PrivateKey.from_private_bytes(f.read())


def issue(args):
    import os
    payload = {
        'license_id': uuid.uuid4().hex,
        'customer': args.customer,
        'edition': args.edition,
        'issued_at': datetime.now().strftime('%Y-%m-%dT%H:%M:%S'),
        'expires_at': 'permanent' if args.permanent else
                      (datetime.now() + timedelta(days=args.days)).strftime('%Y-%m-%dT%H:%M:%S'),
    }
    if args.machine_id:
        payload['machine_id'] = args.machine_id
    priv = _load_private(args.key_dir)
    sig = priv.sign(canonical_bytes(payload))
    lic = {'payload': payload, 'signature': base64.b64encode(sig).decode()}
    out = args.out or f'license_{payload["license_id"][:8]}.lic'
    with open(out, 'w', encoding='utf-8') as f:
        json.dump(lic, f, ensure_ascii=False, indent=2)
    print(f'许可已签发：{out}')
    print(json.dumps(payload, ensure_ascii=False, indent=2))


def verify(args):
    import os
    with open(args.file, encoding='utf-8') as f:
        data = json.load(f)
    pub_b64 = args.pubkey or os.environ.get('ADM_LICENSE_PUBKEY', '')
    if not pub_b64:
        print('请用 --pubkey 提供公钥 base64')
        sys.exit(1)
    pub = Ed25519PublicKey.from_public_bytes(base64.b64decode(pub_b64))
    try:
        pub.verify(base64.b64decode(data['signature']), canonical_bytes(data['payload']))
        print('✓ 验签通过')
        print(json.dumps(data['payload'], ensure_ascii=False, indent=2))
    except Exception as e:
        print('✗ 验签失败：', e)
        sys.exit(1)


if __name__ == '__main__':
    p = argparse.ArgumentParser(description='许可签发工具')
    sub = p.add_subparsers(dest='cmd', required=True)
    sub.add_parser('genkey')
    p1 = sub.add_parser('issue')
    p1.add_argument('-c', '--customer', required=True)
    p1.add_argument('-e', '--edition', default='enterprise')
    p1.add_argument('--machine-id', default='')
    p1.add_argument('--days', type=int, default=365)
    p1.add_argument('--permanent', action='store_true')
    p1.add_argument('-o', '--out', default='')
    p1.add_argument('--key-dir', default=KEY_DIR_DEFAULT)
    p2 = sub.add_parser('verify')
    p2.add_argument('file')
    p2.add_argument('--pubkey', default='')
    a = p.parse_args()
    if a.cmd == 'genkey':
        genkey()
    elif a.cmd == 'issue':
        issue(a)
    elif a.cmd == 'verify':
        verify(a)
