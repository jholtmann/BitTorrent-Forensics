#!/usr/bin/env python

""" Python script for processing BitTorrent and uTorrent forensic artifacts

This program is free software: you can redistribute it and/or modify it under
the terms of the GNU General Public License as published by the Free Software
Foundation, either version 3 of the License, or (at your option) any later
version.

This program is distributed in the hope that it will be useful, but WITHOUT
ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with
this program. If not, see <http://www.gnu.org/licenses/>.
"""

import csv
import sys
import argparse
import os
import gc
import multiprocessing
import binascii
import hashlib
from itertools import islice

import bencode
import colorama
from tqdm import tqdm
from tabulate import tabulate
from termcolor import colored, cprint

__author__ = "Jonathan Holtmann"
__copyright__ = "Copyright 2020"
__credits__ = ["Jonathan Holtmann"]
__license__ = "GPLv3"
__version__ = "0.0.1"
__maintainer__ = "Jonathan Holtmann"
__email__ = "jholtmann.contact@gmail.com"
__status__ = "Production"

colorama.init() # initialize colorama so terminal colors work

# define table/csv headers

dht_nodes_header = ['#', 'Node ID', 'IPv4', 'Port']
resume_peers_header = ['#', 'IPv6', 'Local IPv6 Port', 'IPv4', 'Local IPv4 Port']
piece_analysis_header = ['Piece #', 'Data Hash', 'Piece Hash', 'Match']

def swap_endianness(hex):
	"""
	Swap endianness of hex string
	"""
	if len(hex) == 0 or len(hex) % 2 != 0: raise ValueError('Swap Endianness only possible with strings with length multiple of two')
	return ''.join([hex[i:i+2] for i in range(0, len(hex), 2)][::-1])

def decode_little_endian_hex_port(hex):
	"""
	Decode 4 character little endian hex string to int port number
	"""
	if len(hex) != 4: raise ValueError('Invalid hex length for Little Endian port, must be 4')
	return int(swap_endianness(hex), 16)

def ipv4_from_hex(hex):
	"""
	Decode 8 character big endian hex string to IPv4 address
	"""
	if len(hex) != 8: raise ValueError('Invalid hex length for IPv4, must be 8')
	return	str(int(hex[0:2], 16)) + '.' + \
			str(int(hex[2:4], 16)) + '.' + \
			str(int(hex[4:6], 16)) + '.' + \
			str(int(hex[6:8], 16))

def resume_peers_from_hex(hex, silent=False):
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
			decode_little_endian_hex_port(peer_chunk[20:24]),
			ipv4_from_hex(peer_chunk[24:32]),
			decode_little_endian_hex_port(peer_chunk[32:36])
		])
		
		id += 1
	
	if not silent: print(tabulate(table, resume_peers_header))
	if not silent: print('==========================\n')
	
	return table

def dht_peers_from_hex(hex, silent=False):
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
	
	if not silent: print(tabulate(table, dht_nodes_header))
	if not silent: print('==========================\n')
	
	return table

def write_csv(path, table, header):
	"""
	Write table (list containing lists where each item is a row entry) to path with given header
	"""
	if path is None or header is None or table is None or len(table) == 0: return
	
	if not (type(table) == list and type(table[0] == list)): raise ValueError("Invalid type for table")

	with open(path, 'w', newline='') as file:
		writer = csv.writer(file, dialect='excel')
		writer.writerow(header)
		for entry in table: writer.writerow(entry)

def parse_dht_nodes(args):
	if 'csv' in args:
		if csv and not os.path.isdir(args.csv): sys.exit('--csv must refer to folder')

		if 'hex_str' in args and args.hex_str is not None and len(args.hex_str) != 0:
			print("Processing hex...")
			table = dht_peers_from_hex(args.hex_str, args.silent)
			if 'csv' in args: write_csv(os.path.join(args.csv, 'dht_peers.csv'), table, dht_nodes_header)
		
		if 'file' in args and args.file:
			if not os.path.exists(args.file):
				sys.exit('Invalid file')
			
			with open(args.file, 'r') as nodes_file:
				line_count = 1
				for line in nodes_file:
					if line is None or len(line) == 0: continue
					print('Processing line ' + str(line_count))
					table = dht_peers_from_hex(line.rstrip(), args.silent)
					if 'csv' in args: write_csv(os.path.join(args.csv, f'dht_peers_{line_count}.csv'), table, dht_nodes_header)
					line_count += 1

def parse_resume_peers(args):
	if 'csv' in args:
		if csv and not os.path.isdir(args.csv): sys.exit('--csv must refer to folder')

		if 'hex_str' in args and args.hex_str is not None and len(args.hex_str) != 0:
			print("Processing hex...")
			table = resume_peers_from_hex(args.hex_str, args.silent)
			if 'csv' in args: write_csv(os.path.join(args.csv, 'resume_peers.csv'), table, resume_peers_header)
		
		if 'file' in args and args.file:
			if not os.path.exists(args.file):
				sys.exit('Invalid file')
			
			with open(args.file, 'r') as nodes_file:
				line_count = 1
				for line in nodes_file:
					if line is None or len(line) == 0: continue
					print('Processing line ' + str(line_count))
					table = resume_peers_from_hex(line.rstrip(), args.silent)
					if 'csv' in args: write_csv(os.path.join(args.csv, f'resume_peers_{line_count}.csv'), table, resume_peers_header)
					line_count += 1

def compute_sha1(data):
	"""
	Computes SHA1 hash of hexlified data
	"""
	return hashlib.sha1(binascii.unhexlify(data)).hexdigest()

def piece_analysis_hex_blobs(data_hex, hashes, piece_length):
	if data_hex is None or len(data_hex) == 0 or hashes is None or len(hashes) == 0:
		print("ERRROR: Can't perform piece analysis on hex blobs when data or hashes are empty")
		return
	
	gc.collect()

	cprint('Starting piece analysis', 'green')
	
	cprint('\t\nCutting data into pieces', 'cyan')
	pieces = [data_hex[i:i+piece_length] for i in tqdm(range(0, len(data_hex), piece_length))]

	pieces_len = len(pieces)
	hashes_len = len(hashes)

	cprint(f'\tNumber of pieces from data is {pieces_len}', 'cyan')
	cprint(f'\tNumber of hashes from torrent file is {hashes_len}', 'cyan')
	
	table = list()

	cprint(f'\n\tComputing hashes', 'cyan')
	with multiprocessing.Pool() as pool:
		piece_hashes = list(tqdm(pool.imap(compute_sha1, pieces), total=len(pieces)))
 
	cprint(f'\t\nGenerating table', 'cyan')
	for i in tqdm(range(0, min(hashes_len, pieces_len))):
		if i >= pieces_len or i >= hashes_len: break
		torrent_hash = hashes[i].decode()
		table.append([i + 1, piece_hashes[i], torrent_hash, piece_hashes[i] == torrent_hash])
	
	return table

def piece_analysis(torrent_file_path, data_file_path, out_file_path, silent=False, write_blob=False):
	if not os.path.isfile(torrent_file_path):
		cprint(f"ERROR: torrent file '{torrent_file_path}' does not exist", 'red')
		return
		
	if not os.path.exists(data_file_path):
		cprint(f"ERROR: data file '{data_file_path}' does not exist", 'red')
		return
	
	cprint(f'Performing piece analysis on torrent file {torrent_file_path} and content {data_file_path}', 'green')

	with open(torrent_file_path, 'rb') as torrent_file:
		torrent_file_content = torrent_file.read()
			
		if b'pieces' not in torrent_file_content:
			cprint('Error: pieces key not found', 'red')
			return
		
		split = torrent_file_content.split(b'e6:pieces')

		binary_data = binascii.hexlify(torrent_file_content)
		
	piece_hashes = binary_data[:-4] # trim 6565 off the end
	piece_hashes = b''.join(piece_hashes.split(b'706965636573')[1:])
	piece_hashes = b'3a'.join(piece_hashes.split(b'3a')[1:])

	piece_hashes = [piece_hashes[i:i+40] for i in range(0, len(piece_hashes), 40)]
	
	cprint(f'Found hashes for {len(piece_hashes)} pieces', 'green')
	
	parsed_data = bencode.decode(split[0].decode('utf-8') + 'eee')
	
	piece_length = int(parsed_data["info"]["piece length"])
	
	cprint(f'Piece length: {piece_length} bytes', 'green')
	
	if os.path.isfile(data_file_path):
		cprint('Data is file, reading', 'green')
		with open(data_file_path, 'rb') as data_file:
			table = piece_analysis_hex_blobs(data_file.read(), piece_hashes, int(piece_length * 2))
	elif os.path.isdir(data_file_path):
		cprint('Data is directory, assembling into hex blob for analysis', 'green')
		
		file_list = list()
		for file_part in parsed_data['info']['files']:
			file_list.append(os.path.join(data_file_path ,*file_part['path']))
			
		hex_data = b''

		fill_queue = list()
		missing_files = 0

		i = 0
		for file in file_list:
			
			expected_file_size = parsed_data['info']['files'][i]['length']

			if os.path.isfile(file):
				cprint(f'\tFOUND:   {file.replace(data_file_path, "")}', 'cyan')
				with open(file, 'rb') as file_bin:
					cprint(f'\t\t   => Reading file...', 'blue')
					file_data = binascii.hexlify(file_bin.read())
					hex_data += file_data

					file_size = int(len(file_data) / 2)

					if file_size == expected_file_size:
						cprint(f'\t\t   => File size {file_size}b matched expected', 'blue')
					elif file_size < expected_file_size:
						cprint(f'\t\t   => File size {file_size}b less than expected {expected_file_size}b', 'red')
						adjustment = int(expected_file_size-file_size)
						cprint(f'\t\t   => Queueing hex blob adjustment of size {adjustment}b', 'cyan')
						fill_queue.append([len(hex_data), adjustment])
					else:
						cprint(f'\t\t   => File size {file_size}b greater than expected {expected_file_size}b', 'red')
						adjustment = int(file_size-expected_file_size)
						cprint(f'\t\t   => Trimmming {adjustment}b from end of file to compensate', 'red')
						hex_data = hex_data[:-adjustment]
			else:
				cprint(f'\tMISSING: {file.replace(data_file_path, "")}', 'red')
				missing_files += 1
				fill_queue.append([len(hex_data), expected_file_size])
				cprint(f'\t\t   => Queueing hex blob adjustment of size {expected_file_size}b', 'cyan')
			i += 1
		
		if len(fill_queue) > 0:
			if len(fill_queue) == missing_files:
				cprint(f"All files are missing, cannot perform piece analysis", 'red')
				return
			cprint(f"{len(fill_queue)} file(s) missing. Filling missing data with '30's to allow chance at partial piece analysis for other files", 'red')
			
			for missing_file in fill_queue:
				cprint('\tGenerating fill data...', 'cyan')
				fill_data = binascii.hexlify(b'0' * missing_file[1])
				
				cprint(f'\tCurrent hex blob size is {int(len(hex_data) / 2)} bytes', 'green')
				cprint(f'\tInserting {int(len(fill_data) / 2)} bytes at index {int(missing_file[0] / 2)}', 'green')

				hex_data = hex_data[:missing_file[0]] + fill_data + hex_data[missing_file[0]:]

				cprint(f'\tInserted, new hex blob size is {int(len(hex_data) / 2)} bytes', 'green')
	
		cprint('Assembled hex blob of size: ' + str(int(len(hex_data) / 2)) + ' bytes', 'green')

		if write_blob:
			cprint('Writing blob to blob.txt', 'red')
			with open('blob.txt', 'wb') as blob_out:
				blob_out.write(binascii.unhexlify(hex_data))
			cprint('Done', 'red')
				

		table = piece_analysis_hex_blobs(hex_data, piece_hashes, int(piece_length * 2))
		
		if not out_file_path:
			print(tabulate(table, hedaer=piece_analysis_header))
		else:
			cprint('\nWriting table to csv', 'green')
			write_csv(out_file_path, table, piece_analysis_header)
	
def main():
	parser = argparse.ArgumentParser()

	parser.add_argument('--version', action='version', version='BitTorrent Forensics {version}'.format(version=__version__))

	subparsers = parser.add_subparsers(help='Options')

	torrent_piece = subparsers.add_parser('torrent-piece-analysis', help='Perform piece analysis on .torrent file and content file/folder')
	torrent_piece.set_defaults(which='torrent_piece_analysis')
	torrent_piece.add_argument('-t', '--torrent-file', help='Torrent file', required=True)
	torrent_piece.add_argument('-d', '--data-file', help='File to check against torrent file', required=True)
	torrent_piece.add_argument('-o', '--out', help='File to write results to', required=False)
	torrent_piece.add_argument('--silent', help='Do not print results to terminal', action='store_true', default=False)
	torrent_piece.add_argument('--write-blob', help='Write assembled hex blob to disk', action='store_true', default=False)

	dht_nodes = subparsers.add_parser('uTorrent-dht-nodes', help='Parse hex from dht.dat nodes key')
	dht_nodes.set_defaults(which='uTorrent_dht_nodes')
	dht_nodes_group = dht_nodes.add_mutually_exclusive_group(required=True)
	dht_nodes_group.add_argument('-s', '--hex_str', type=str, help='String starting with 0x to decode')
	dht_nodes_group.add_argument('-f', '--file', help='File containing string(s) starting with 0x to decode, one per line')
	dht_nodes.add_argument('-c', '--csv', help='Folder to write csv file to')
	dht_nodes.add_argument('--silent', help='Do not print results to terminal', action='store_true', default=False)
	
	resume_peers = subparsers.add_parser('uTorrent-resume-peers', help='Parse hex from resume.dat peers6 key')
	resume_peers.set_defaults(which='uTorrent_resume_peers')
	resume_peers_group = resume_peers.add_mutually_exclusive_group(required=True)
	resume_peers_group.add_argument('-s', '--hex_str', type=str, help='String starting with 0x to decode')
	resume_peers_group.add_argument('-f', '--file', help='File containing string(s) starting with 0x to decode, one per line')
	resume_peers.add_argument('-c', '--csv', help='Folder to write csv file to')
	
	resume_peers.add_argument('--silent', help='Do not print results to terminal', action='store_true', default=False)
	args = parser.parse_args()

	if 'which' not in args:
		parser.print_help()
		parser.exit()

	if args.which == 'torrent_piece_analysis':
		print(args.data_file)
		piece_analysis(args.torrent_file, args.data_file, args.out, args.silent, args.write_blob)
	elif args.which == 'uTorrent_dht_nodes':
		parse_dht_nodes(args)
	elif args.which == 'uTorrent_resume_peers':
		parse_resume_peers(args)

if __name__ == '__main__': main()