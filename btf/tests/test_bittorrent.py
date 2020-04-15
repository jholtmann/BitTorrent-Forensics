import unittest
import binascii

from ..bittorrent import pieces

class TestPiecesValid(unittest.TestCase): # test file with content 'hello world'
	def setUp(self):
		hashes = [
			'C4D871AD13AD00FDE9A7BB7FF7ED2543AEC54241', 
			'9591818C07E900DB7E1E0BC4B884C945E6A61B24'
		]
		data = b'68656c6c6f20776f726c640a'

		self.expected = [
			[
				1,
				'C4D871AD13AD00FDE9A7BB7FF7ED2543AEC54241'.lower(),
				'C4D871AD13AD00FDE9A7BB7FF7ED2543AEC54241'.lower(),
				True
			],
			[
				2,
				'9591818C07E900DB7E1E0BC4B884C945E6A61B24'.lower(),
				'9591818C07E900DB7E1E0BC4B884C945E6A61B24'.lower(),
				True
			]
		]

		self.result = pieces.get_table_from_pieces(data, hashes, 12, silent=True, threaded=False)

	def test_list_eq(self):
		self.assertListEqual(self.result, self.expected)

class TestPiecesWrongPieceLength(unittest.TestCase):
	def setUp(self):
		self.hashes = [
			'C4D871AD13AD00FDE9A7BB7FF7ED2543AEC54241', 
			'9591818C07E900DB7E1E0BC4B884C945E6A61B24'
		]
		self.data = b'68656c6c6f20776f726c640a'

	def test_list_eq(self):
		self.assertRaises(ValueError,
			pieces.get_table_from_pieces, self.data, self.hashes, 24, silent=True, threaded=False)
