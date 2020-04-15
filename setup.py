from setuptools import setup, find_packages
from os import path

here = path.abspath(path.dirname(__file__))

with open(path.join(here, 'README.md'), encoding='utf-8') as f:
    long_description = f.read()

setup(
    name='bittorrent-forensics',
    version='0.0.1',
    description='Python project for analyzing BitTorrent forensic artifacts',
    long_description=long_description,
    long_description_content_type='text/markdown',
    url='https://github.com/jholtmann/BitTorrent-Forensics',
    author='Jonathan Holtmann',
    author_email='jholtmann.contact@gmail.com',
    classifiers=[
        'Development Status :: 3 - Alpha',
        'License :: OSI Approved :: GNU General Public License v3 (GPLv3)',
        'Programming Language :: Python :: 3'
    ],
    keywords='bittorrent utorrent forensics',
    # package_dir={'': 'src'},
    packages=find_packages(where='.'),
    python_requires='>=3.3',
    install_requires=[
        'bencode-parser',
        'colorama',
        'tqdm',
        'tabulate',
        'termcolor'
    ],
    entry_points={
        'console_scripts': [
            'bittorrent-forensics=btf.btf:main'
        ],
    },
    project_urls={
        'Bug Reports': 'https://github.com/jholtmann/BitTorrent-Forensics/issues',
        'Source': 'https://github.com/jholtmann/BitTorrent-Forensics/tree/master/btf',
    },
    test_suite='nose2.collector.collector',
    tests_require=['nose2']
)