#!/usr/bin/env python3
"""Unit tests for proxy_router module."""

import os
import unittest
import tempfile
import proxy_router

class TestProxyRouter(unittest.TestCase):

    def test_proxy_initialization(self):
        p = proxy_router.Proxy(host="192.168.1.10", port=8080, protocol="http", username="user", password="pass")
        self.assertEqual(p.host, "192.168.1.10")
        self.assertEqual(p.port, 8080)
        self.assertEqual(p.protocol, "http")
        self.assertEqual(p.url(), "http://user:pass@192.168.1.10:8080")

    def test_proxy_serialization(self):
        p = proxy_router.Proxy(host="10.0.0.1", port=3128, protocol="https")
        d = p.to_dict()
        self.assertEqual(d['host'], "10.0.0.1")
        self.assertEqual(d['port'], 3128)
        self.assertEqual(d['protocol'], "https")

        p2 = proxy_router.Proxy.from_dict(d)
        self.assertEqual(p2.host, p.host)
        self.assertEqual(p2.port, p.port)
        self.assertEqual(p2.protocol, p.protocol)

    def test_proxy_pool_subnet_generation(self):
        pool = proxy_router.ProxyPool()
        proxies = pool.generate_from_subnet("192.168.1.0/30", base_port=8000)
        # 192.168.1.0/30 has usable host addresses: .1 and .2
        self.assertEqual(len(proxies), 2)
        self.assertEqual(proxies[0].host, "192.168.1.1")
        self.assertEqual(proxies[0].port, 8000)
        self.assertEqual(proxies[1].host, "192.168.1.2")
        self.assertEqual(proxies[1].port, 8001)

    def test_proxy_rotation(self):
        pool = proxy_router.ProxyPool()
        p1 = proxy_router.Proxy("10.0.0.1", 8080)
        p2 = proxy_router.Proxy("10.0.0.2", 8080)
        pool.add_proxy(p1)
        pool.add_proxy(p2)

        # Round robin check
        self.assertEqual(pool.get_next('round_robin').host, "10.0.0.1")
        self.assertEqual(pool.get_next('round_robin').host, "10.0.0.2")
        self.assertEqual(pool.get_next('round_robin').host, "10.0.0.1")

        # Random check
        rand_p = pool.get_next('random')
        self.assertIn(rand_p.host, ["10.0.0.1", "10.0.0.2"])

    def test_save_and_load_file(self):
        pool = proxy_router.ProxyPool()
        pool.generate_from_subnet("172.16.0.0/29", base_port=9000, count=3)

        with tempfile.NamedTemporaryFile(delete=False) as tmp:
            tmp_path = tmp.name

        try:
            pool.save_to_file(tmp_path)
            new_pool = proxy_router.ProxyPool()
            new_pool.load_from_file(tmp_path)
            self.assertEqual(len(new_pool.proxies), 3)
            self.assertEqual(new_pool.proxies[0].host, pool.proxies[0].host)
        finally:
            if os.path.exists(tmp_path):
                os.remove(tmp_path)

if __name__ == "__main__":
    unittest.main()
