import os
import sys

from tabulate import tabulate

from ..utility.io import write_csv
from ..utility.hex import ipv4_from_hex

"""
Functions for parsing uTorrent dht.dat files.
"""

DHT_NODES_HEADER = ['#', 'Node ID', 'IPv4', 'Port']

def get_peers_from_hex(hex, silent=True):
	"""
	Return parsed table of IP addresses from given hex-encoded data string (from dht.dat). 
	:returns: list of lists with header '#, Node ID, IPv4, Port'
	"""
	if hex is None or len(hex) == 0:
		raise ValueError('Error: hex cannot be empty')
	if hex[0:2] != '0x':
		raise ValueError('Error: hex string must start with 0x')
	if not (len(hex) - 2) % 52 == 0:
		raise ValueError('Error: hex string must have length multiple of 52 (excluding 0x)')
	
	if not silent: print('\n==========================')
	
	nodes = list()
	node_chunks = [hex[2:][i:i+52] for i in range(0, len(hex), 52)]
	
	table = list()
	id = 1
	for node_chunk in node_chunks:
		if not node_chunk: continue # skip empty lines
		
		table.append([
			id, 
			node_chunk[0:40], 
			ipv4_from_hex(node_chunk[40:48]),
			int(node_chunk[48:52], 16)
		])
		
		id += 1
	
	if not silent: print(tabulate(table, DHT_NODES_HEADER))
	if not silent: print('==========================\n')
	
	return table

def _parse_dht_nodes(args):
	if 'csv' in args:
		if args.csv and not os.path.isdir(args.csv): sys.exit('--csv must refer to folder')

	if 'hex_str' in args and args.hex_str is not None and len(args.hex_str) != 0:
		print("Processing hex...")
		table = get_peers_from_hex(args.hex_str, args.silent)
		if 'csv' in args: write_csv(os.path.join(args.csv, 'dht_peers.csv'), table, DHT_NODES_HEADER)
	
	if 'file' in args and args.file:
		if not os.path.exists(args.file):
			sys.exit('Invalid file')
		
		with open(args.file, 'r') as nodes_file:
			line_count = 1
			for line in nodes_file:
				if line is None or len(line) == 0: continue
				print('Processing line ' + str(line_count))
				table = get_peers_from_hex(line.rstrip(), args.silent)
				if 'csv' in args: write_csv(os.path.join(args.csv, f'dht_peers_{line_count}.csv'), table, DHT_NODES_HEADER)
				line_count += 1