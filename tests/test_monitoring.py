import tempfile
import unittest
from unittest.mock import patch
import monitoring

class MonitoringTest(unittest.TestCase):
    def test_rates_and_counter_reset(self):
        self.assertEqual(monitoring.rates({'rx':100,'tx':20},{'rx':300,'tx':60},10),{'rx':20,'tx':4})
        self.assertIsNone(monitoring.rates({'rx':100},{'rx':0},10))
        self.assertIsNone(monitoring.rates({'rx':100},{'rx':300},40))
    def test_retention_persistence_and_separate_peer_series(self):
        with tempfile.TemporaryDirectory() as d:
            monitor=monitoring.Monitor(d,'container','awg0')
            def sample(rx):
                return {'total':{'rx':rx*2,'tx':0,'rx_packets':rx//10,'tx_packets':0},'peers':{'key':{'rx':rx,'tx':0,'handshake':0}}}
            for stamp,rx in [(100,0),(100000,100),(100010,200),(100020,300)]:
                with patch('monitoring.time.time',return_value=stamp), patch('monitoring.snapshot',return_value=sample(rx)):
                    monitor.sample()
            reloaded=monitoring.Monitor(d,'container','awg0')
            with reloaded.connect() as db:
                self.assertEqual(db.execute('SELECT count(*) FROM samples').fetchone()[0],3)
            with patch('monitoring.time.time',return_value=100021):
                peer=reloaded.history('key',1)
                total=reloaded.history('',1)
                self.assertFalse(peer['packet_counts'])
                self.assertTrue(total['packet_counts'])
                self.assertTrue(any(p['value'] and p['value']['rx']==10 for p in peer['points']))
                self.assertTrue(any(p['value'] and p['value']['rx_packets']==1 for p in total['points']))
                self.assertTrue(all(p['value'] is None for p in reloaded.history('missing',1)['points']))

if __name__=='__main__': unittest.main()
