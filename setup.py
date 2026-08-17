from setuptools import setup, find_packages

try:
    from wifi_shadow.config import Configuration
    version = Configuration.version
except Exception:
    version = '3.0.0'

setup(
    name='wifi-shadow',
    version=version,
    author='Ships2024',
    author_email='',
    url='https://github.com/Ships2024/wifi-shadow',
    packages=find_packages(exclude=['tests*']),
    data_files=[
        ('share/dict', ['wordlist-top4800-probable.txt'])
    ],
    entry_points={
        'console_scripts': [
            'wifi-shadow = wifi_shadow.__main__:entry_point',
        ]
    },
    install_requires=[],
    python_requires='>=3.9',
    license='GNU GPLv2',
    scripts=['bin/wifi-shadow'],
    description='Wireless Network Auditor for Linux — wifi-shadow',
    long_description='''Wireless Network Auditor for Linux.

Cracks WEP, WPA, and WPS encrypted networks.

Depends on Aircrack-ng Suite and optionally scapy / pycryptodome for
active PMKID harvest, WPS PBC, and targeted hidden-AP decloak.''',
    classifiers=[
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.9',
        'Programming Language :: Python :: 3.10',
        'Programming Language :: Python :: 3.11',
        'Programming Language :: Python :: 3.12',
        'Operating System :: POSIX :: Linux',
    ],
)
