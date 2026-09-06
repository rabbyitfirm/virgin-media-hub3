#!/usr/bin/env python3
"""IP Proxy Generator, Pool Manager, and Router.

This module allows generating IP proxies (e.g. from CIDR ranges or list),
managing proxy pools, rotating proxies, and starting a local/remote proxy router
server to route traffic anywhere across Windows, Linux, VMs, and third-party networks.
"""

import base64
import http.server
import json
import random
import socket
import socketserver
import select
import urllib.parse
import urllib.request
import netaddr

class Proxy:
    """Represents a single IP Proxy configuration."""

    def __init__(self, host, port, protocol='http', username=None, password=None, active=True):
        self.host = str(host)
        self.port = int(port)
        self.protocol = protocol.lower()
        self.username = username
        self.password = password
        self.active = active

    def to_dict(self):
        """Serialize Proxy to dict."""
        res = {
            'host': self.host,
            'port': self.port,
            'protocol': self.protocol,
            'active': self.active
        }
        if self.username:
            res['username'] = self.username
        if self.password:
            res['password'] = self.password
        return res

    @classmethod
    def from_dict(cls, data):
        """Deserialize Proxy from dict."""
        return cls(
            host=data['host'],
            port=data['port'],
            protocol=data.get('protocol', 'http'),
            username=data.get('username'),
            password=data.get('password'),
            active=data.get('active', True)
        )

    def url(self):
        """Return proxy URL string representation."""
        auth = ""
        if self.username and self.password:
            auth = f"{self.username}:{self.password}@"
        return f"{self.protocol}://{auth}{self.host}:{self.port}"

    def __repr__(self):
        return f"Proxy({self.url()}, active={self.active})"


class ProxyPool:
    """Manages a pool of IP proxies with rotation strategies and generation."""

    def __init__(self, proxies=None):
        self.proxies = proxies if proxies else []
        self._index = 0

    def add_proxy(self, proxy):
        """Add a Proxy instance to the pool."""
        self.proxies.append(proxy)

    def generate_from_subnet(self, cidr_or_range, base_port, count=None, protocol='http'):
        """Generate proxy list from an IP subnet or IP range."""
        net = netaddr.IPNetwork(cidr_or_range)
        generated = []
        port = int(base_port)
        for idx, ip in enumerate(net.iter_hosts()):
            if count and idx >= count:
                break
            proxy = Proxy(host=str(ip), port=port + (idx % 1000), protocol=protocol)
            self.add_proxy(proxy)
            generated.append(proxy)
        return generated

    def get_active_proxies(self):
        """Get all currently active proxies."""
        return [p for p in self.proxies if p.active]

    def get_next(self, strategy='round_robin'):
        """Get the next proxy from pool according to rotation strategy."""
        active = self.get_active_proxies()
        if not active:
            return None

        if strategy == 'random':
            return random.choice(active)

        # Default: round_robin
        proxy = active[self._index % len(active)]
        self._index = (self._index + 1) % len(active)
        return proxy

    def save_to_file(self, filename):
        """Save proxy pool configuration to JSON file."""
        with open(filename, 'w') as f:
            json.dump([p.to_dict() for p in self.proxies], f, indent=2)

    def load_from_file(self, filename):
        """Load proxy pool configuration from JSON file."""
        with open(filename, 'r') as f:
            data = json.load(f)
            self.proxies = [Proxy.from_dict(d) for d in data]


class ProxyRequestHandler(http.server.BaseHTTPRequestHandler):
    """HTTP request handler for local/remote Proxy Server with authentication."""

    pool = ProxyPool()
    rotation_strategy = 'round_robin'
    auth_username = None
    auth_password = None

    def _check_auth(self):
        """Validate Proxy-Authorization header if authentication is required."""
        if not self.auth_username or not self.auth_password:
            return True

        auth_header = self.headers.get('Proxy-Authorization')
        if not auth_header:
            self.send_response(407)
            self.send_header('Proxy-Authenticate', 'Basic realm="Proxy Router"')
            self.end_headers()
            return False

        try:
            auth_type, encoded = auth_header.split(' ', 1)
            if auth_type.lower() == 'basic':
                decoded = base64.b64decode(encoded).decode('utf-8')
                user, passwd = decoded.split(':', 1)
                if user == self.auth_username and passwd == self.auth_password:
                    return True
        except Exception:
            pass

        self.send_response(407)
        self.send_header('Proxy-Authenticate', 'Basic realm="Proxy Router"')
        self.end_headers()
        return False

    def do_CONNECT(self):
        """Handle HTTP CONNECT method for SSL tunneling."""
        if not self._check_auth():
            return

        upstream = self.pool.get_next(self.rotation_strategy)
        target_host, target_port = self.path.split(':')
        target_port = int(target_port)

        try:
            if upstream:
                outbound_sock = socket.create_connection((upstream.host, upstream.port), timeout=10)
            else:
                outbound_sock = socket.create_connection((target_host, target_port), timeout=10)

            self.send_response(200, 'Connection Established')
            self.end_headers()

            sockets = [self.connection, outbound_sock]
            while True:
                readable, _, _ = select.select(sockets, [], [], 10)
                if not readable:
                    break
                for s in readable:
                    other = outbound_sock if s is self.connection else self.connection
                    data = s.recv(8192)
                    if not data:
                        return
                    other.sendall(data)
        except Exception as e:
            self.send_error(502, f"Proxy Error: {e}")

    def do_GET(self):
        self._forward_request()

    def do_POST(self):
        self._forward_request()

    def do_PUT(self):
        self._forward_request()

    def do_DELETE(self):
        self._forward_request()

    def _forward_request(self):
        """Forward HTTP request directly or via upstream proxy."""
        if not self._check_auth():
            return

        upstream = self.pool.get_next(self.rotation_strategy)
        req_headers = {key: val for key, val in self.headers.items() if key.lower() != 'proxy-authorization'}

        content_len = int(self.headers.get('Content-Length', 0))
        body = self.rfile.read(content_len) if content_len > 0 else None

        req = urllib.request.Request(self.path, data=body, headers=req_headers, method=self.command)

        if upstream:
            req.set_proxy(f"{upstream.host}:{upstream.port}", upstream.protocol)

        try:
            with urllib.request.urlopen(req, timeout=10) as resp:
                self.send_response(resp.status)
                for key, val in resp.headers.items():
                    self.send_header(key, val)
                self.end_headers()
                self.wfile.write(resp.read())
        except Exception as e:
            self.send_error(502, f"Proxy Forward Error: {e}")


class ProxyServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
    """Threaded Proxy Router Server."""
    daemon_threads = True

    def __init__(self, host='0.0.0.0', port=8080, pool=None, rotation_strategy='round_robin', auth_user=None, auth_pass=None):
        ProxyRequestHandler.pool = pool if pool else ProxyPool()
        ProxyRequestHandler.rotation_strategy = rotation_strategy
        ProxyRequestHandler.auth_username = auth_user
        ProxyRequestHandler.auth_password = auth_pass
        super().__init__((host, int(port)), ProxyRequestHandler)
