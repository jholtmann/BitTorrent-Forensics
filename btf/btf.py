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

import argparse
import colorama

from btf.utorrent import resume, dht
from btf.bittorrent import pieces
from btf.utility.threading import compute_sha1

__version__ = "0.0.0.1"

def main():
	colorama.init() # initialize colorama so terminal colors work

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
		pieces._perform_piece_analysis(args.torrent_file, args.data_file, args.out, args.silent, args.write_blob)
	elif args.which == 'uTorrent_dht_nodes':
		dht._parse_dht_nodes(args)
	elif args.which == 'uTorrent_resume_peers':
		resume._parse_resume_peers(args)

if __name__ == '__main__': main()