import os
import binascii
import multiprocessing

import bencode
import colorama
from tqdm import tqdm
from tabulate import tabulate
from termcolor import colored, cprint

from ..utility.io import write_csv
from ..utility.threading import compute_sha1

"""
Functions for performing piece analysis on .torrent file and related data.
"""

PIECE_ANALYSIS_HEADER = ['Piece #', 'Data Hash', 'Piece Hash', 'Match']

def get_table_from_pieces(data_hex, hashes, piece_length, *, silent=False, threaded=True):
	"""
	Compute hashes for given hex blob and compare to values from pieces key in .torrent file. 
	:returns: list of lists with header 'Piece #, Data Hash, Piece Hash, Match'
	"""
	if data_hex is None or len(data_hex) == 0 or hashes is None or len(hashes) == 0:
		raise ValueError("ERRROR: Can't perform piece analysis on hex blobs when data or hashes are empty")

	if not silent: cprint('Starting piece analysis', 'green')
	
	if not silent: cprint('\t\nCutting data into pieces', 'cyan')
	pieces = [data_hex[i:i+piece_length] for i in tqdm(range(0, len(data_hex), piece_length), disable=silent)]

	pieces_len = len(pieces)
	hashes_len = len(hashes)

	if pieces_len != hashes_len: raise ValueError(f'Number of pieces ({pieces_len}) must match number of hashes ({hashes_len})')

	if not silent: cprint(f'\tNumber of pieces from data is {pieces_len}', 'cyan')
	if not silent: cprint(f'\tNumber of hashes from torrent file is {hashes_len}', 'cyan')
	
	table = list()

	if not silent: cprint(f'\n\tComputing hashes', 'cyan')
	if threaded:
		with multiprocessing.Pool() as pool:
			piece_hashes = list(tqdm(pool.imap(compute_sha1, pieces), total=len(pieces), disable=silent))
	else:
		piece_hashes = [compute_sha1(x).lower() for x in pieces]
 
	if not silent: cprint(f'\t\nGenerating table', 'cyan')
	for i in tqdm(range(0, min(hashes_len, pieces_len)), disable=silent):
		if i >= pieces_len or i >= hashes_len: break
		torrent_hash = hashes[i].lower()
		table.append([i + 1, piece_hashes[i], torrent_hash, piece_hashes[i] == torrent_hash])
	
	return table

def _perform_piece_analysis(torrent_file_path, data_file_path, out_file_path, silent=False, write_blob=False):
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

	piece_hashes = [piece_hashes[i:i+40].decode() for i in range(0, len(piece_hashes), 40)]
	
	cprint(f'Found hashes for {len(piece_hashes)} pieces', 'green')
	
	parsed_data = bencode.decode(split[0].decode('utf-8') + 'eee')
	
	piece_length = int(parsed_data["info"]["piece length"])
	
	cprint(f'Piece length: {piece_length} bytes', 'green')
	
	if os.path.isfile(data_file_path):
		cprint('Data is file, reading', 'green')
		with open(data_file_path, 'rb') as data_file:
			table = get_table_from_pieces(binascii.hexlify(data_file.read()), piece_hashes, int(piece_length * 2))
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
				

		table = get_table_from_pieces(hex_data, piece_hashes, int(piece_length * 2))
		
	if not out_file_path:
		print(tabulate(table, header=PIECE_ANALYSIS_HEADER))
	else:
		cprint('\nWriting table to csv', 'green')
		write_csv(out_file_path, table, PIECE_ANALYSIS_HEADER)