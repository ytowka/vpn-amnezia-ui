import hashlib
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import container_init

class ContainerInitTest(unittest.TestCase):
    def test_initialize_and_restart_preserve_secrets(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d)
            template=root/'template.conf'
            template.write_text('working template')
            state=root/'state'
            env={'STATE_DIR':str(state),'CLIENT_DIR':str(root/'clients'),'CLIENT_TEMPLATE':str(template)}
            def certificate(args,**kwargs):
                (state/'cert.pem').write_text('cert')
                (state/'key.pem').write_text('key')
            with patch.dict(os.environ,env),patch('container_init.subprocess.run',side_effect=certificate) as run:
                container_init.initialize()
                before={p.name:p.read_bytes() for p in state.iterdir()}
                record=json.loads((state/'credentials.json').read_text())
                password=(state/'admin-password.txt').read_text().strip()
                self.assertEqual(hashlib.scrypt(password.encode(),salt=bytes.fromhex(record['salt']),n=16384,r=8,p=1).hex(),record['hash'])
                container_init.initialize()
                self.assertEqual(before,{p.name:p.read_bytes() for p in state.iterdir()})
                run.assert_called_once()
    def test_missing_template_does_not_generate_credentials(self):
        with tempfile.TemporaryDirectory() as d, patch.dict(os.environ,{'STATE_DIR':d+'/state','CLIENT_TEMPLATE':d+'/missing'}):
            with self.assertRaises(RuntimeError): container_init.initialize()
            self.assertFalse(Path(d+'/state').exists())
    def test_incomplete_certificate_is_not_silently_replaced(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);(root/'template').touch();(root/'key.pem').touch()
            with patch.dict(os.environ,{'STATE_DIR':d,'CLIENT_DIR':d+'/clients','CLIENT_TEMPLATE':d+'/template'}):
                with self.assertRaises(RuntimeError): container_init.initialize()
                self.assertEqual((root/'key.pem').read_text(),'')

if __name__=='__main__': unittest.main()
