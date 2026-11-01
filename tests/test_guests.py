import concurrent.futures
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import guest_access

class GuestTest(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.service=guest_access.Invitations(self.temp.name)
    def test_single_use_and_only_hash_is_stored(self):
        invite=self.service.create(24)
        name,conf=self.service.redeem(invite['key'],'phone','ip',lambda name:b'private config')
        self.assertEqual(conf,b'private config')
        self.assertTrue(name.startswith('phone-g-'))
        with self.assertRaises(guest_access.GuestError):self.service.claim(invite['key'],'other','ip')
        self.assertNotIn(invite['key'],json.dumps(self.service.listing()))
        self.assertNotIn(invite['key'].encode(),self.service.path.read_bytes())
        self.assertEqual(self.service.listing()[0]['status'],'used')
    def test_concurrent_claim_only_provisions_one_client(self):
        invite=self.service.create(1)
        calls=[]
        def redeem(i):
            try:return self.service.redeem(invite['key'],'phone',str(i),lambda name:calls.append(name) or b'config')
            except guest_access.GuestError:return None
        with concurrent.futures.ThreadPoolExecutor(max_workers=5) as pool:
            results=list(pool.map(redeem,range(5)))
        self.assertEqual(len(calls),1)
        self.assertEqual(sum(r is not None for r in results),1)
    def test_expiry_revocation_and_invalid_device(self):
        invite=self.service.create(1)
        with patch('guest_access.time.time',return_value=invite['expires']+1):
            with self.assertRaises(guest_access.GuestError):self.service.claim(invite['key'],'phone','ip')
        invite=self.service.create(1)
        with self.assertRaises(guest_access.GuestError):self.service.claim(invite['key'],'../oops','ip')
        self.assertEqual(self.service.listing()[0]['status'],'active')
        self.service.revoke(invite['id'])
        with self.assertRaises(guest_access.GuestError):self.service.claim(invite['key'],'phone','ip')
    def test_cooldown_persists_and_no_peer_is_created(self):
        for i in range(5):
            with self.assertRaises(guest_access.GuestError) as error:self.service.claim('bad','phone','ip')
            self.assertEqual(error.exception.status,403)
        restarted=guest_access.Invitations(self.temp.name)
        valid=restarted.create(1)
        with self.assertRaises(guest_access.GuestError) as error:restarted.claim(valid['key'],'phone','ip')
        self.assertEqual(error.exception.status,429)
        self.assertGreater(error.exception.retry,0)
        # A different IP is not locked out by another user's failures.
        self.assertTrue(restarted.claim(valid['key'],'phone','other'))
    def test_failure_and_interrupted_issue_never_reuse_token(self):
        invite=self.service.create(1)
        def fail(name):raise RuntimeError('sensitive error')
        with self.assertRaises(guest_access.GuestError):self.service.redeem(invite['key'],'phone','ip',fail)
        self.assertEqual(self.service.listing()[0]['status'],'failed')
        with self.assertRaises(guest_access.GuestError):self.service.claim(invite['key'],'phone','ip')
        invite=self.service.create(1)
        self.service.claim(invite['key'],'phone','ip')
        restarted=guest_access.Invitations(self.temp.name)
        with self.assertRaises(guest_access.GuestError):restarted.claim(invite['key'],'phone','ip')
    def test_request_rate_and_revoked_key(self):
        with patch('guest_access.time.time',return_value=100000):
            for i in range(10):self.service.throttle('ip')
            with self.assertRaises(guest_access.GuestError) as error:self.service.throttle('ip')
            self.assertEqual(error.exception.status,429)
        with patch('guest_access.time.time',return_value=100061):self.service.throttle('ip')


class GuestHTTPTest(unittest.TestCase):
    def test_public_download_and_protected_admin_endpoints(self):
        from http.client import HTTPConnection
        import threading
        import time
        import server
        with tempfile.TemporaryDirectory() as d, patch.object(server,'INVITATIONS',guest_access.Invitations(d)), patch.object(server,'create_client',return_value=b'[Interface]\nPrivateKey = test-only\n') as provision:
            http=server.ThreadingHTTPServer(('127.0.0.1',0),server.Handler)
            thread=threading.Thread(target=http.serve_forever,daemon=True);thread.start()
            session='test-admin-session'
            server.SESSIONS[session]={'csrf':'test-csrf','expires':time.time()+60}
            def request(method,path,payload=None,admin=False,csrf=True):
                conn=HTTPConnection('127.0.0.1',http.server_port,timeout=10)
                headers={'Content-Type':'application/json'}
                if admin:headers['Cookie']='session='+session
                if csrf:headers['X-CSRF-Token']='test-csrf'
                conn.request(method,path,json.dumps(payload) if payload is not None else None,headers)
                response=conn.getresponse();body=response.read();status=response.status;conn.close()
                return status,body
            try:
                self.assertEqual(request('GET','/guest')[0],200)
                self.assertEqual(request('GET','/api/invites')[0],401)
                self.assertEqual(request('POST','/api/invites/create',{'hours':1},True,False)[0],403)
                status,body=request('POST','/api/invites/create',{'hours':1},True)
                self.assertEqual(status,201)
                key=json.loads(body)['key']
                status,body=request('POST','/api/guest/redeem',{'key':key,'name':'phone'})
                self.assertEqual(status,200)
                self.assertIn(b'PrivateKey',body)
                self.assertEqual(request('POST','/api/guest/redeem',{'key':key,'name':'other'})[0],403)
                provision.assert_called_once()
                listing=json.loads(request('GET','/api/invites',admin=True)[1])
                self.assertEqual(listing['invites'][0]['status'],'used')
                self.assertNotIn(key,json.dumps(listing))
            finally:
                http.shutdown();http.server_close();thread.join()
                server.SESSIONS.pop(session,None)

if __name__=='__main__':unittest.main()

class ProxyAddressTest(unittest.TestCase):
    def test_only_authenticated_proxy_can_supply_client_address(self):
        import server
        handler=object.__new__(server.Handler)
        handler.client_address=('172.18.0.1',1234)
        secret='a'*43
        with patch.dict('os.environ',{'TRUSTED_PROXY_TOKEN':secret}):
            for headers, expected in [
                ({'X-Real-IP':'203.0.113.7'},'172.18.0.1'),
                ({'X-Real-IP':'203.0.113.7','X-Console-Proxy-Token':'wrong'},'172.18.0.1'),
                ({'X-Real-IP':'203.0.113.7','X-Console-Proxy-Token':secret},'203.0.113.7'),
                ({'X-Real-IP':'2001:db8::7','X-Console-Proxy-Token':secret},'2001:db8::7'),
                ({'X-Real-IP':'bad,ip','X-Console-Proxy-Token':secret},'172.18.0.1')]:
                handler.headers=headers
                self.assertEqual(handler.client_ip(),expected)
        with patch.dict('os.environ',{'TRUSTED_PROXY_TOKEN':''}):
            handler.headers={'X-Real-IP':'203.0.113.7','X-Console-Proxy-Token':''}
            self.assertEqual(handler.client_ip(),'172.18.0.1')
