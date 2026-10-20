# -*- coding: utf-8 -*-
"""激活服务器（供应商侧部署）：许可签发、撤销、状态查询、吊销列表。

职责边界：
- 私钥在此离线保管，负责对许可 payload 签名（客户端只有公钥，无法伪造）。
- 记录已签发的许可与撤销列表（CRL），供客户端在线二次校验。

接口：
  POST /v1/license/issue              签发许可
  POST /v1/license/revoke             撤销许可（加入 CRL）
  GET  /v1/license/status?license_id= 查询许可状态（客户端在线校验）
  GET  /v1/crl                        吊销列表

运行：
  pip install flask cryptography
  python license_server.py --key-dir license_keys --port 9000
"""
import argparse
import base64
import json
import os
import sqlite3
import uuid
from datetime import datetime, timedelta

from flask import Flask, request, jsonify
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

app = Flask(__name__)
KEY_DIR = 'license_keys'
DB_PATH = os.path.join(KEY_DIR, 'licenses.db')


def canonical_bytes(payload: dict) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode('utf-8')


def _privkey():
    with open(os.path.join(KEY_DIR, 'private.key'), 'rb') as f:
        return Ed25519PrivateKey.from_private_bytes(f.read())


def _db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("""CREATE TABLE IF NOT EXISTS licenses (
        license_id TEXT PRIMARY KEY, customer TEXT, edition TEXT, machine_id TEXT,
        issued_at TEXT, expires_at TEXT, revoked INTEGER DEFAULT 0)""")
    return conn


def _sign(payload: dict) -> str:
    return base64.b64encode(_privkey().sign(canonical_bytes(payload))).decode()


@app.post('/v1/license/issue')
def issue():
    j = request.get_json(force=True, silent=True) or {}
    customer = j.get('customer', '')
    if not customer:
        return jsonify(ok=False, message='customer 必填'), 400
    payload = {
        'license_id': uuid.uuid4().hex,
        'customer': customer,
        'edition': j.get('edition', 'enterprise'),
        'issued_at': datetime.now().strftime('%Y-%m-%dT%H:%M:%S'),
        'expires_at': 'permanent' if j.get('permanent') else
                      (datetime.now() + timedelta(days=int(j.get('days', 365)))).strftime('%Y-%m-%dT%H:%M:%S'),
    }
    if j.get('machine_id'):
        payload['machine_id'] = j['machine_id']
    lic = {'payload': payload, 'signature': _sign(payload)}
    conn = _db()
    conn.execute("INSERT INTO licenses(license_id, customer, edition, machine_id, issued_at, expires_at) "
                 "VALUES(?,?,?,?,?,?)",
                 (payload['license_id'], customer, payload['edition'], j.get('machine_id', ''),
                  payload['issued_at'], payload['expires_at']))
    conn.commit(); conn.close()
    return jsonify(ok=True, license=lic)


@app.post('/v1/license/revoke')
def revoke():
    j = request.get_json(force=True, silent=True) or {}
    lid = j.get('license_id', '')
    if not lid:
        return jsonify(ok=False, message='license_id 必填'), 400
    conn = _db()
    conn.execute('UPDATE licenses SET revoked=1 WHERE license_id=?', (lid,))
    conn.commit(); conn.close()
    return jsonify(ok=True, message='已撤销')


@app.get('/v1/license/status')
def status():
    lid = request.args.get('license_id', '')
    conn = _db()
    row = conn.execute('SELECT * FROM licenses WHERE license_id=?', (lid,)).fetchone()
    conn.close()
    if not row:
        return jsonify(ok=True, status='not_found')
    if row['revoked']:
        return jsonify(ok=True, status='revoked')
    if row['expires_at'] != 'permanent' and datetime.fromisoformat(row['expires_at']) < datetime.now():
        return jsonify(ok=True, status='expired')
    return jsonify(ok=True, status='active', customer=row['customer'], edition=row['edition'],
                   expires_at=row['expires_at'])


@app.get('/v1/crl')
def crl():
    conn = _db()
    rows = conn.execute('SELECT license_id FROM licenses WHERE revoked=1').fetchall()
    conn.close()
    return jsonify(ok=True, revoked=[r['license_id'] for r in rows])


if __name__ == '__main__':
    p = argparse.ArgumentParser()
    p.add_argument('--key-dir', default=KEY_DIR)
    p.add_argument('--port', type=int, default=9000)
    p.add_argument('--host', default='0.0.0.0')
    a = p.parse_args()
    KEY_DIR = a.key_dir
    DB_PATH = os.path.join(KEY_DIR, 'licenses.db')
    app.run(host=a.host, port=a.port)
