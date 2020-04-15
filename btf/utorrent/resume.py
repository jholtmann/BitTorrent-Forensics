import os
import sys

from tabulate import tabulate

from ..utility.io import write_csv
from ..utility.hex import swap_endianness, port_from_little_endian_hex, ipv4_from_hex

"""
Functions for parsing uTorrent resume.dat files.
"""

RESUME_PEERS_HEADER = ['#', 'IPv6', 'Local IPv6 Port', 'IPv4', 'Local IPv4 Port']

def get_peers_from_hex(hex, silent=True):
	"""
	Return parsed table of IP addresses from given hex-encoded data string (from resume.dat). 
	:returns: list of lists with header '#, IPv6, Local IPv6 port, IPv4, Local IPv4 Port'
	"""
	if hex is None or len(hex) == 0:
		raise ValueError('Error: hex cannot be empty')
	if hex[0:2] != '0x':
		raise ValueError('Error: hex string must start with 0x')
	if not (len(hex) - 2) % 36 == 0:
		raise ValueError('Error: hex string must have length multiple of 36 (excluding 0x)')
	
	if not silent: print('\n==========================')
	
	nodes = list()
	peer_chunks = [hex[2:][i:i+36] for i in range(0, len(hex), 36)]
	
	table = list()
	id = 1
	for peer_chunk in peer_chunks:
		if not peer_chunk: continue # skip empty lines
				
		table.append([
			id, 
			peer_chunk[0:20],
			port_from_little_endian_hex(peer_chunk[20:24]),
			ipv4_from_hex(peer_chunk[24:32]),
			port_from_little_endian_hex(peer_chunk[32:36])
		])
		
		id += 1
	
	if not silent: print(tabulate(table, RESUME_PEERS_HEADER))
	if not silent: print('==========================\n')
	
	return table

def _parse_resume_peers(args):
	if 'csv' in args:
		if args.csv and not os.path.isdir(args.csv):
			sys.exit('--csv must refer to folder')

	if 'hex_str' in args and args.hex_str is not None and len(args.hex_str) != 0:
		print("Processing hex...")
		table = get_peers_from_hex(args.hex_str, args.silent)
		if 'csv' in args: write_csv(os.path.join(args.csv, 'resume_peers.csv'), table, RESUME_PEERS_HEADER)
	
	if 'file' in args and args.file:
		if not os.path.exists(args.file):
			sys.exit('Invalid file')
		
		with open(args.file, 'r') as nodes_file:
			line_count = 1
			for line in nodes_file:
				if line is None or len(line) == 0: continue
				print('Processing line ' + str(line_count))
				table = get_peers_from_hex(line.rstrip(), args.silent)
				if 'csv' in args: write_csv(os.path.join(args.csv, f'resume_peers_{line_count}.csv'), table, RESUME_PEERS_HEADER)
				line_count += 1