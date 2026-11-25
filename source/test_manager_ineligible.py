"""Unit tests for the Antigravity 2.35.1 client-side gate patch.

Run from the source directory:
    python -m unittest test_manager_ineligible -v
"""

import unittest

from patcher.manager.patcher import (
    MANAGER_CLIENT_GATE_NEW,
    MANAGER_CLIENT_GATE_OLD,
    _apply_client_gate,
    _client_gate_state,
    _count_sub,
)


class ClientGateTests(unittest.TestCase):
    def test_rename_is_equal_length(self):
        self.assertEqual(len(MANAGER_CLIENT_GATE_OLD), len(MANAGER_CLIENT_GATE_NEW))
        self.assertEqual(MANAGER_CLIENT_GATE_OLD, b"ineligible")
        self.assertEqual(MANAGER_CLIENT_GATE_NEW, b"inexigible")

    def test_count_and_apply(self):
        data = bytearray(b"x ineligible y ineligible z")
        self.assertEqual(_count_sub(data, MANAGER_CLIENT_GATE_OLD), 2)
        patched, count = _apply_client_gate(data)
        self.assertEqual(count, 2)
        self.assertEqual(len(patched), len(data))
        self.assertEqual(_count_sub(patched, MANAGER_CLIENT_GATE_OLD), 0)
        self.assertEqual(_count_sub(patched, MANAGER_CLIENT_GATE_NEW), 2)

    def test_state(self):
        self.assertEqual(_client_gate_state(b"no gate here"), "not_applicable")
        self.assertEqual(_client_gate_state(b"ineligible"), "unpatched")
        self.assertEqual(_client_gate_state(b"inexigible"), "patched")
        self.assertEqual(_client_gate_state(b"ineligible inexigible"), "partial")

    def test_apply_without_gate_is_noop(self):
        data = b"no gate here"
        patched, count = _apply_client_gate(data)
        self.assertEqual(count, 0)
        self.assertEqual(patched, data)


if __name__ == "__main__":
    unittest.main()
