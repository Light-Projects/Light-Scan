# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.

"""
Unit tests for LightBPF Lexer, Parser, and Compiler.
"""

import unittest
import sys
from pathlib import Path

# Add project root to sys.path so LightPacket is always importable
sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

try:
    from LightPacket.LightBPF.Lexer import BpfLexer, Token
    from LightPacket.LightBPF.Parser import (
        BpfParser, ProtocolNode, KeywordFilterNode, ByteAccessNode,
        BinaryOpNode, UnaryOpNode, NumberNode, LengthNode, FieldNode
    )
    from LightPacket.LightBPF.Compiler import BpfCompiler, BpfEmulator
except ImportError:
    from LightBPF.Lexer import BpfLexer, Token
    from LightBPF.Parser import (
        BpfParser, ProtocolNode, KeywordFilterNode, ByteAccessNode,
        BinaryOpNode, UnaryOpNode, NumberNode, LengthNode, FieldNode
    )
    from LightBPF.Compiler import BpfCompiler, BpfEmulator


class TestLexer(unittest.TestCase):
    def test_addresses(self):
        toks = BpfLexer("host 192.168.1.1").tokenize()
        self.assertEqual(toks[0], Token("KEYWORD", "host"))
        self.assertEqual(toks[1], Token("IPV4", "192.168.1.1"))

        toks = BpfLexer("net 10.0.0.0/8").tokenize()
        self.assertEqual(toks[1], Token("IPV4_CIDR", "10.0.0.0/8"))

        toks = BpfLexer("host fe80::1").tokenize()
        self.assertEqual(toks[1], Token("IPV6", "fe80::1"))

        toks = BpfLexer("ether host aa:bb:cc:dd:ee:ff").tokenize()
        self.assertEqual(toks[2], Token("MAC", "aa:bb:cc:dd:ee:ff"))

    def test_hex_and_numbers(self):
        toks = BpfLexer("0x0800 1234").tokenize()
        self.assertEqual(toks[0], Token("NUMBER", "2048"))
        self.assertEqual(toks[1], Token("NUMBER", "1234"))

    def test_named_constants(self):
        toks = BpfLexer("tcp-syn tcp-ack icmp-echo").tokenize()
        self.assertEqual(toks[0], Token("NUMBER", "2"))
        self.assertEqual(toks[1], Token("NUMBER", "16"))
        self.assertEqual(toks[2], Token("NUMBER", "8"))

    def test_logical_normalization(self):
        toks = BpfLexer("tcp && !udp || arp").tokenize()
        self.assertEqual([t.value for t in toks], ["tcp", "and", "not", "udp", "or", "arp"])

    def test_unknown_char(self):
        with self.assertRaises(SyntaxError):
            BpfLexer("tcp @ udp").tokenize(strict=True)


class TestParser(unittest.TestCase):
    def parse(self, text):
        return BpfParser(BpfLexer(text).tokenize()).parse()

    def test_protocols(self):
        ast = self.parse("tcp")
        self.assertIsInstance(ast, ProtocolNode)
        self.assertEqual(ast.name, "tcp")

    def test_keywords(self):
        ast = self.parse("src port 80")
        self.assertIsInstance(ast, KeywordFilterNode)
        self.assertEqual(ast.keyword, "port")
        self.assertEqual(ast.value, 80)
        self.assertEqual(ast.direction, "src")

        ast = self.parse("dst host 10.0.0.1")
        self.assertIsInstance(ast, KeywordFilterNode)
        self.assertEqual(ast.keyword, "host")
        self.assertEqual(ast.value, "10.0.0.1")
        self.assertEqual(ast.direction, "dst")

    def test_byte_access(self):
        ast = self.parse("tcp[13] & 2 != 0")
        self.assertIsInstance(ast, BinaryOpNode)
        self.assertEqual(ast.op, "!=")
        self.assertIsInstance(ast.left, BinaryOpNode)
        self.assertEqual(ast.left.op, "&")
        self.assertIsInstance(ast.left.left, ByteAccessNode)
        self.assertEqual(ast.left.left.protocol, "tcp")
        self.assertEqual(ast.left.left.offset, NumberNode(13))

    def test_pseudo_fields(self):
        ast = self.parse("tcp[tcpflags] == 2")
        self.assertIsInstance(ast.left, ByteAccessNode)
        self.assertIsInstance(ast.left.offset, FieldNode)
        self.assertEqual(ast.left.offset.name, "tcpflags")

    def test_logical_precedence(self):
        # 'not' binds tighter than 'and', 'and' binds tighter than 'or'
        ast = self.parse("tcp or udp and not arp")
        self.assertIsInstance(ast, BinaryOpNode)
        self.assertEqual(ast.op, "or")
        self.assertEqual(ast.left.name, "tcp")
        self.assertEqual(ast.right.op, "and")
        self.assertEqual(ast.right.left.name, "udp")
        self.assertIsInstance(ast.right.right, UnaryOpNode)

    def test_syntax_errors(self):
        with self.assertRaises(SyntaxError):
            self.parse("")
        with self.assertRaises(SyntaxError):
            self.parse("port")
        with self.assertRaises(SyntaxError):
            self.parse("tcp[")
        with self.assertRaises(SyntaxError):
            self.parse("(tcp or udp")
        with self.assertRaises(SyntaxError):
            self.parse("and tcp")


class TestCompiler(unittest.TestCase):
    def test_compile_all_constructs(self):
        filters = [
            "ip", "ip6", "tcp", "udp", "icmp", "arp", "vlan", "mpls",
            "host 192.168.1.1", "src host 10.0.0.1", "dst host 10.0.0.2",
            "net 10.0.0.0/8", "net 192.168.1.0 mask 255.255.255.0",
            "port 80", "src port 443", "dst port 8080", "portrange 1000-2000",
            "tcp[13] & 2 != 0", "tcp[tcpflags] & tcp-syn != 0",
            "ip[0] & 0xf > 5", "len > 60", "less 1500", "greater 64",
            "broadcast", "multicast", "ip proto 6", "ip proto tcp",
            "(tcp or udp) and not dst port 53",
            "tcp and port 80 or udp and port 53"
        ]
        for f in filters:
            insns = BpfCompiler.compile_str(f)
            self.assertGreaterEqual(len(insns), 2, f"Filter '{f}' generated too few instructions")
            raw_bytes = BpfCompiler.to_bytes(insns)
            self.assertEqual(len(raw_bytes), len(insns) * 8)
            fprog = BpfCompiler.to_fprog(insns)
            self.assertEqual(fprog.len, len(insns))


if __name__ == "__main__":
    unittest.main()
