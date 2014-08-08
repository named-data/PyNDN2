# -*- Mode: python; py-indent-offset: 4; indent-tabs-mode: nil; coding: utf-8; -*-

# This uses the template https://github.com/pypa/sampleproject/blob/master/setup.py
# and from Alex Afanasyev's file at https://github.com/cawka/PyNDN2/blob/master/setup.py

from setuptools import setup, find_packages  # Always prefer setuptools over distutils
from codecs import open  # To use a consistent encoding
from os import path

setup(
    name='PyNDN',

    version='2.0a3',

    description='An NDN client library with TLV wire format support in native Python',

    url='https://github.com/named-data/PyNDN2',

    maintainer='Jeff Thompson',
    maintainer_email='jefft0@remap.ucla.edu',

    license='LGPLv3',

    # See https://pypi.python.org/pypi?%3Aaction=list_classifiers
    classifiers=[
        'Development Status :: 3 - Alpha',

        'Intended Audience :: Developers',
        'Topic :: Software Development :: Libraries',

        'License :: OSI Approved :: GNU Lesser General Public License v3 or later (LGPLv3+)',

        'Programming Language :: Python :: 2',
        'Programming Language :: Python :: 2.6',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.2',
        'Programming Language :: Python :: 3.3',
        'Programming Language :: Python :: 3.4',
    ],

    keywords='NDN',

    packages=find_packages('python'),
    package_dir = {'':'python'},

    install_requires=['pycrypto', 'trollius', 'protobuf']
)
