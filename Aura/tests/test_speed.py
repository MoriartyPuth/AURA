import threading
import time
import unittest

from core.parallel import http_workers, pmap, run_parallel, tool_workers
from modules.recon import service_mgr
from modules.recon.surface_mgr import parse_naabu_ports


class TestPmap(unittest.TestCase):
    def test_order_preserved_and_concurrent(self):
        def slow(i):
            time.sleep(0.05)
            return i * 2

        start = time.monotonic()
        out = pmap(slow, range(8), 8)
        elapsed = time.monotonic() - start
        self.assertEqual(out, [i * 2 for i in range(8)])
        self.assertLess(elapsed, 0.3)  # serial would be 0.4s

    def test_single_worker_is_serial(self):
        seen = []
        lock = threading.Lock()

        def rec(i):
            with lock:
                seen.append(threading.current_thread().name)
            return i

        self.assertEqual(pmap(rec, [1, 2, 3], 1), [1, 2, 3])
        self.assertEqual(len(set(seen)), 1)

    def test_empty(self):
        self.assertEqual(pmap(lambda x: x, [], 4), [])

    def test_run_parallel(self):
        self.assertEqual(run_parallel(lambda: "a", lambda: "b"), ["a", "b"])

    def test_worker_settings(self):
        self.assertEqual(http_workers({}), 8)
        self.assertEqual(tool_workers({"settings": {"tool_workers": 0}}), 1)
        self.assertEqual(http_workers({"settings": {"http_workers": "bad"}}), 8)


class TestNaabuPorts(unittest.TestCase):
    def test_parse(self):
        out = "x.com:443\nx.com:80\n\nx.com:443\nnoise\nx.com:99999\n"
        self.assertEqual(parse_naabu_ports(out), [80, 443])


class FakeEngine:
    domain = "x.com"
    config = {}


class TestServiceUsesNaabuPorts(unittest.TestCase):
    def _run(self, ports):
        calls = []
        orig = (service_mgr.collect_open_ports, service_mgr.run_command, service_mgr.is_tool_available)
        service_mgr.collect_open_ports = lambda _e: ports
        service_mgr.is_tool_available = lambda _t: True
        service_mgr.run_command = lambda cmd, timeout=0: (calls.append(cmd), (0, "", ""))[1]
        import builtins
        real_import = builtins.__import__

        def no_nmap(name, *a, **k):  # force the CLI path
            if name == "nmap":
                raise ImportError
            return real_import(name, *a, **k)

        builtins.__import__ = no_nmap
        try:
            service_mgr.run_service_enrichment(FakeEngine())
        finally:
            builtins.__import__ = real_import
            service_mgr.collect_open_ports, service_mgr.run_command, service_mgr.is_tool_available = orig
        return calls

    def test_only_naabu_ports_scanned(self):
        calls = self._run([22, 443])
        self.assertEqual(calls, [["nmap", "-Pn", "-sV", "-p", "22,443", "x.com"]])

    def test_fallback_when_naabu_unavailable(self):
        calls = self._run(None)
        self.assertEqual(calls, [["nmap", "-Pn", "-sV", "--top-ports", "100", "x.com"]])

    def test_skip_when_no_open_ports(self):
        self.assertEqual(self._run([]), [])


if __name__ == "__main__":
    unittest.main()
