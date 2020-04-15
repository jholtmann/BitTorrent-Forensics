def swap_endianness(hex):
	"""
	Swap endianness of hex string
	"""
	if len(hex) == 0 or len(hex) % 2 != 0: raise ValueError('Swap Endianness only possible with strings with length multiple of two')
	return ''.join([hex[i:i+2] for i in range(0, len(hex), 2)][::-1])

def port_from_hex(hex):
	"""
	Decode 4 character big endian hex string to int port number
	"""
	if len(hex) != 4: raise ValueError('Invalid hex length for Little Endian port, must be 4')
	return int(hex, 16)

def port_from_little_endian_hex(hex):
	"""
	Decode 4 character little endian hex string to int port number
	"""
	if len(hex) != 4: raise ValueError('Invalid hex length for Little Endian port, must be 4')
	return port_from_hex(swap_endianness(hex))

def ipv4_from_hex(hex):
	"""
	Decode 8 character big endian hex string to IPv4 address
	"""
	if len(hex) != 8: raise ValueError('Invalid hex length for IPv4, must be 8')
	return	str(int(hex[0:2], 16)) + '.' + \
			str(int(hex[2:4], 16)) + '.' + \
			str(int(hex[4:6], 16)) + '.' + \
			str(int(hex[6:8], 16))