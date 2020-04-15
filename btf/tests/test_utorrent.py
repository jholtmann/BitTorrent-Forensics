import unittest

from ..utorrent import resume, dht

class TestResumePeersFromHexValid(unittest.TestCase):
	def setUp(self):
		self.expected = [
			[
				1,
				'00000000000000000000',
				65535,
				'161.178.195.212',
				1449
			]
		]
		self.result = resume.get_peers_from_hex('0x00000000000000000000FFFFA1B2C3D4A905', True)

	def test_count_eq(self):
		self.assertCountEqual(self.result, self.expected)

	def test_list_eq(self):
		self.assertListEqual(self.result, self.expected)

class TestResumePeersFromHexInvalid(unittest.TestCase):
	def test_missing_start(self):
		self.assertRaises(ValueError,
			resume.get_peers_from_hex, '00000000000000000000FFFFA1B2C3D4A905', True)

	def test_invalid_length(self):
		self.assertRaises(ValueError,
			resume.get_peers_from_hex, '0x00000000000000000000FFFFA1B2C3D4A905A', True)

	def test_empty(self):
		self.assertRaises(ValueError,
			resume.get_peers_from_hex, '', True)

	def test_whitespace(self):
		self.assertRaises(ValueError,
			resume.get_peers_from_hex, '      ', True)

	def test_invalid_length_with_whitespace_end(self):
		self.assertRaises(ValueError,
			resume.get_peers_from_hex, '0x00000000000000000000FFFFA1B2C3D      ', True)

	def test_invalid_length_with_whitespace_middle(self):
		self.assertRaises(ValueError,
			resume.get_peers_from_hex, '0x000000000000000      00000FFFFA1B2C3D', True)

	def test_invalid_length_with_whitespace_begin(self):
		self.assertRaises(ValueError,
			resume.get_peers_from_hex, '0x00      000000000000000000FFFFA1B2C3D', True)

class TestDhtPeersFromHexValid(unittest.TestCase):
	def setUp(self):
		self.expected = [
			[
				1,
				'1234567898765432112345678987654321234567',
				'161.178.195.212',
				1449
			]
		]
		self.result = dht.get_peers_from_hex('0x1234567898765432112345678987654321234567A1B2C3D405A9', True)

	def test_count_eq(self):
		self.assertCountEqual(self.result, self.expected)

	def test_list_eq(self):
		self.assertListEqual(self.result, self.expected)

class TestDhtPeersFromHexInvalid(unittest.TestCase):
	def test_missing_start(self):
		self.assertRaises(ValueError,
			dht.get_peers_from_hex, '1234567898765432112345678987654321234567A1B2C3D405A9', True)

	def test_invalid_length(self):
		self.assertRaises(ValueError,
			dht.get_peers_from_hex, '0x1234567898765432112345678987654321234567A1B2C3D405A9A', True)

	def test_empty(self):
		self.assertRaises(ValueError,
			dht.get_peers_from_hex, '', True)

	def test_whitespace(self):
		self.assertRaises(ValueError,
			dht.get_peers_from_hex, '      ', True)

	def test_invalid_length_with_whitespace_end(self):
		self.assertRaises(ValueError,
			dht.get_peers_from_hex, '1234567898765432112345678987654321234567A1B2       ', True)

	def test_invalid_length_with_whitespace_middle(self):
		self.assertRaises(ValueError,
			dht.get_peers_from_hex, '1234567898765432       112345678987654321234567A1B2', True)

	def test_invalid_length_with_whitespace_begin(self):
		self.assertRaises(ValueError,
			dht.get_peers_from_hex, '       1234567898765432112345678987654321234567A1B2', True)