#!/usr/bin/env python3
"""Regtest-only wallet failure experiment against an instrumented daemon."""
import json
import os
import re
import pathlib
import subprocess
import sys
import tempfile
import time

build = pathlib.Path(os.environ.get('EDGE_BUILD', '/build/src'))
daemon, cli = build / 'PEPEPOWd', build / 'PEPEPOW-cli'
env = os.environ.copy()
env.setdefault('ASAN_OPTIONS', 'detect_leaks=0:abort_on_error=1')

class Node:
    def __init__(self, root):
        self.root = pathlib.Path(root)
        self.log = open(self.root / 'process.log', 'ab', buffering=0)
        self.p = None
    def rpc(self, method, *args, check=True):
        r = subprocess.run([str(cli), '-regtest', '-datadir=' + str(self.root), method,
                            *map(str, args)], stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                           text=True, env=env, timeout=60)
        if check and r.returncode:
            raise RuntimeError(f'{method} failed ({r.returncode}): {r.stderr}')
        if r.returncode:
            return {'error': r.stderr.strip(), 'code': r.returncode}
        try:
            return json.loads(r.stdout, parse_float=str)
        except ValueError:
            return r.stdout.strip()
    def start(self):
        self.p = subprocess.Popen([str(daemon), '-regtest', '-datadir=' + str(self.root),
            '-server', '-listen=0', '-dnsseed=0', '-discover=0', '-connect=0',
            '-keypool=20', '-printtoconsole=0'], stdout=self.log, stderr=self.log, env=env)
        for _ in range(120):
            if self.p.poll() is not None:
                raise RuntimeError('daemon exited before RPC: ' + (self.root / 'process.log').read_text(errors='replace')[-5000:])
            try:
                self.rpc('getblockchaininfo')
                return
            except (RuntimeError, subprocess.TimeoutExpired):
                time.sleep(.5)
        raise RuntimeError('RPC startup timeout')
    def stop(self):
        if self.p and self.p.poll() is None:
            self.rpc('stop', check=False)
            self.p.wait(timeout=60)
        if self.p and self.p.returncode:
            raise RuntimeError(f'daemon shutdown {self.p.returncode}: ' + (self.root / 'process.log').read_text(errors='replace')[-5000:])
    def marker(self, name):
        (self.root / 'regtest' / name).touch()
    def snapshot(self):
        info = self.rpc('getwalletinfo')
        return {'balance': self.rpc('getbalance'), 'utxos': self.rpc('listunspent', 1),
                'keypoolsize': info.get('keypoolsize'), 'txcount': info.get('txcount'),
                'mempool': self.rpc('getrawmempool')}


def setup(node):
    node.start()
    node.rpc('generate', 105)
    address = node.rpc('getnewaddress')
    return address

def simplify(snapshot):
    return {'balance': snapshot['balance'], 'utxo_count': len(snapshot['utxos']),
            'utxos': sorted((x['txid'], x['vout']) for x in snapshot['utxos']),
            'keypoolsize': snapshot['keypoolsize'], 'txcount': snapshot['txcount'],
            'mempool': snapshot['mempool']}

results = {}
with tempfile.TemporaryDirectory(prefix='pepe-edge-wallet-') as tmp:
    for case in ('reject', 'persistence', 'normal'):
        path = pathlib.Path(tmp) / case
        path.mkdir()
        node = Node(path)
        try:
            address = setup(node)
            before = node.snapshot()
            marker = ('edge-test-reject-mempool' if case == 'reject' else
                      'edge-test-fail-wallet-write' if case == 'persistence' else None)
            if marker:
                node.marker(marker)
            response = node.rpc('sendtoaddress', address, '1000', check=False)
            marker_path = path / 'regtest' / marker if marker else None
            if case == 'persistence':
                marker_path.unlink()
                injected = True
            elif case == 'reject':
                injected = not marker_path.exists()
            else:
                injected = False
            after = node.snapshot()
            debug = (path / 'regtest' / 'debug.log').read_text(errors='replace')
            event = ('EDGE_TEST invalid transaction for mempool rejection' if case == 'reject'
                     else 'EDGE_TEST injected WriteTx failure txid=')
            if marker:
                assert injected and event in debug, f'{case}: injection did not run'
            txid = response if isinstance(response, str) and len(response) == 64 else None
            if case == 'persistence' and isinstance(response, dict):
                match = re.search(r'txid=([a-fA-F0-9]{64})', response.get('error', ''))
                txid = match.group(1) if match else None
            raw = None
            if case == 'persistence' and txid:
                raw = node.rpc('getrawtransaction', txid)
                results['duplicate_in_mempool'] = node.rpc('sendrawtransaction', raw, check=False)
                results['mempool_after_duplicate'] = node.rpc('getrawmempool')
                assert results['duplicate_in_mempool'] == txid
                assert results['mempool_after_duplicate'] == [txid]
                decoded = node.rpc('decoderawtransaction', raw)
                output_addresses = [addr for output in decoded['vout']
                                    for addr in output['scriptPubKey'].get('addresses', [])]
                change_addresses = [addr for addr in output_addresses if addr != address]
                assert len(change_addresses) == 1, 'expected one change output'
                results['change_address'] = change_addresses[0]
                results['history_before_restart'] = node.rpc('gettransaction', txid, check=False)
            node.stop()
            node.start()
            restarted = node.snapshot()
            history = node.rpc('gettransaction', txid, check=False) if txid else None
            if raw:
                sampled_change = [node.rpc('getrawchangeaddress') for _ in range(25)]
                results['change_address_reused_in_next_25'] = results['change_address'] in sampled_change
                assert not results['change_address_reused_in_next_25'], 'reserved change key reused'
            results[case] = {'rpc_response': response, 'before': simplify(before),
                             'after': simplify(after), 'restart': simplify(restarted),
                             'history_after_restart': history, 'injected': injected,
                             'log_rejected_before_record': 'rejected before recording wallet spend' in debug,
                             'injection_count': debug.count(event) if marker else 0}
            if case == 'reject':
                assert isinstance(response, dict) and response.get('error'), 'expected rejected send RPC'
                assert results[case]['log_rejected_before_record'], 'CommitTransaction rejection branch not reached'
                assert before['balance'] == after['balance'] == restarted['balance']
                assert {(x['txid'], x['vout']) for x in before['utxos']} == {(x['txid'], x['vout']) for x in after['utxos']} == {(x['txid'], x['vout']) for x in restarted['utxos']}
                assert not after['mempool'] and not restarted['mempool']
                assert before['txcount'] == after['txcount'] == restarted['txcount']
                print('PASS rejection: real mempool validation rejection, no phantom wallet spend', flush=True)
            elif case == 'persistence':
                assert isinstance(response, dict) and 'Wallet database write failed' in response.get('error', ''), 'persistence failure was reported as success or wrong error'
                assert 'Do not retry' in response['error'] and txid, 'must report uncertainty and txid'
                assert raw and txid in after['mempool'], 'expected accepted transaction after injected failure'
                assert isinstance(history, dict) and history.get('error'), 'expected missing wallet history after restart when disk write was forcibly disabled'
                assert before['txcount'] == restarted['txcount'], 'wallet tx persisted unexpectedly after injected failure'
                assert before['balance'] == restarted['balance'], 'restart did not restore prior wallet balance'
                assert not restarted['mempool'], 'offline restart should not relay a missing wallet record'
                print('PASS persistence: RPC reports unsafe outcome with txid, no success or automatic retry', flush=True)
            else:
                assert txid and txid in after['mempool'], 'normal transaction not accepted into mempool'
                assert isinstance(history, dict) and history.get('txid') == txid, 'normal transaction not persisted across restart'
                assert after['txcount'] == restarted['txcount'] == before['txcount'] + 1
                print('PASS normal: transaction accepted, persisted and returned success', flush=True)
        finally:
            node.stop()
            node.log.close()
print(json.dumps(results, indent=2, sort_keys=True))
# Check the contract, not just a string returned to RPC: the transaction may
# remain in mempool, but callers must receive the txid with an explicit error.
if not isinstance(results['persistence']['rpc_response'], dict):
    print('FAIL: injected write failure was reported as success', file=sys.stderr)
    sys.exit(1)
