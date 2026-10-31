import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import server
import awg_core

KEY = 'A'*43+'='
OTHER = 'B'*43+'='
PEER = '# Client: phone\n[Peer]\nPublicKey = '+KEY+'\nAllowedIPs = 10.8.1.2/32\n'
CONFIG = '[Interface]\nAddress = 10.8.1.0/24\nPrivateKey = secret\n\n'+PEER+'\n# Client: laptop\n[Peer]\nPublicKey = '+OTHER+'\nAllowedIPs = 10.8.1.3/32\n'

class ManagementTest(unittest.TestCase):
    def test_remove_only_target_and_its_label(self):
        updated = server.remove_peer(CONFIG, KEY)
        self.assertNotIn(KEY, updated)
        self.assertNotIn('phone', updated)
        self.assertIn(OTHER, updated)
        self.assertIn('laptop', updated)
        self.assertIn('PrivateKey = secret', updated)
    def test_block_parser_preserves_configuration(self):
        self.assertEqual(''.join(server.blocks(CONFIG)), CONFIG)
        self.assertEqual([server.peer_key(b) for b in server.blocks(CONFIG)], [None, KEY, OTHER])
    def test_allocation_reserves_disabled_address(self):
        sections=awg_core.parse(CONFIG)
        sections+=awg_core.parse('[Peer]\nPublicKey = disabled\nAllowedIPs = 10.8.1.4/32\n')
        address=awg_core.allocate(sections, '', '10.8.1.1/32')
        self.assertEqual(address, '10.8.1.5/32')
    def test_disable_persists_before_runtime_removal(self):
        with tempfile.TemporaryDirectory() as d, patch.object(server,'STATE',Path(d)), patch.object(server.S,'read',return_value=CONFIG), patch.object(server,'backup_write') as write, patch.object(server.S,'call') as call:
            def removal(*args,**kwargs):
                self.assertIn(KEY, json.loads((Path(d)/'disabled.json').read_text()))
            call.side_effect=removal
            server.mutate(KEY,'disable')
            self.assertNotIn(KEY,write.call_args.args[0])
            call.assert_called_once_with('awg','set',server.INTERFACE,'peer',KEY,'remove')
    def test_enable_failure_keeps_disabled_and_restores_file(self):
        with tempfile.TemporaryDirectory() as d, patch.object(server,'STATE',Path(d)), patch.object(server.S,'read',return_value='[Interface]\n'), patch.object(server,'backup_write') as write, patch.object(server,'add_runtime',side_effect=RuntimeError()):
            server.atomic(Path(d)/'disabled.json',json.dumps({KEY:{'block':PEER}}))
            with self.assertRaises(RuntimeError): server.mutate(KEY,'enable')
            self.assertIn(KEY,server.state())
            self.assertEqual(write.call_args.args[0],'[Interface]\n')

if __name__=='__main__': unittest.main()
