# BitTorrent-Forensics
Python script for analyzing .torrent files and uTorrent .dat files

## Functionality

1. Perform piece analysis on `.torrent` files to verify that a file/folder was downloaded using the `.torrent` file
2. Retrieve a list of DHT peers from the `dht.dat` file
3. Retrieve a list of peers from the `resume.dat` file

## Installation

`$ python3 setup.py install`

## Usage

`$ bittorrent-forensics --help`

```
usage: bittorrent-forensics [-h] [--version] {torrent-piece-analysis,uTorrent-dht-nodes,uTorrent-resume-peers} ...

positional arguments:
  {torrent-piece-analysis,uTorrent-dht-nodes,uTorrent-resume-peers}
                        Options
    torrent-piece-analysis
                        Perform piece analysis on .torrent file and content file/folder
    uTorrent-dht-nodes  Parse hex from dht.dat nodes key
    uTorrent-resume-peers
                        Parse hex from resume.dat peers6 key

optional arguments:
  -h, --help            show this help message and exit
  --version             show program's version number and exit
```

### General

#### Torrent File Piece Analysis

`bittorrent-forensics torrent-piece-analysis --help`

```
usage: bittorrent-forensics torrent-piece-analysis [-h] -t TORRENT_FILE -d DATA_FILE [-o OUT] [--silent] [--write-blob]

optional arguments:
  -h, --help            show this help message and exit
  -t TORRENT_FILE, --torrent-file TORRENT_FILE
                        Torrent file
  -d DATA_FILE, --data-file DATA_FILE
                        File to check against torrent file
  -o OUT, --out OUT     File to write results to
  --silent              Do not print results to terminal
  --write-blob          Write assembled hex blob to disk
```

**Example:**

1. Process torrent file that downloads *test_torrent.jpg*:
`bittorrent-forensics torrent-piece-analysis -t test_torrent.torrenmt -d test_torrent.jpg -o result.csv`

2. Process torrent file that downloads folder *test*:
`bittorrent-forensics torrent-piece-analysis -t test_torrent.torrenmt -d test -o result.csv`

### uTorrent

#### DHT Peers Processing

`bittorrent-forensics uTorrent-dht-nodes --help`

```
usage: bittorrent-forensics uTorrent-dht-nodes [-h] (-s HEX_STR | -f FILE) [-c CSV] [--silent]

optional arguments:
  -h, --help            show this help message and exit
  -s HEX_STR, --hex_str HEX_STR
                        String starting with 0x to decode
  -f FILE, --file FILE  File containing string(s) starting with 0x to decode, one per line
  -c CSV, --csv CSV     Folder to write csv file to
  --silent              Do not print results to terminal
```

#### Resume Peers Processing

`bittorrent-forensics uTorrent-resume-peers --help`

```
usage: bittorrent-forensics uTorrent-resume-peers [-h] (-s HEX_STR | -f FILE) [-c CSV] [--silent]

optional arguments:
  -h, --help            show this help message and exit
  -s HEX_STR, --hex_str HEX_STR
                        String starting with 0x to decode
  -f FILE, --file FILE  File containing string(s) starting with 0x to decode, one per line
  -c CSV, --csv CSV     Folder to write csv file to
  --silent              Do not print results to terminal
```