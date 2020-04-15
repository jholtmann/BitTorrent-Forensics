import hashlib
import binascii

def compute_sha1(data):
	"""
	Computes SHA1 hash of hexlified data
	"""
	return hashlib.sha1(binascii.unhexlify(data)).hexdigest()
