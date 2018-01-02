PyNDN: A Named Data Networking client library with TLV wire format support in native Python
===========================================================================================

PyNDN 2.0 is a new implementation of a Named Data Networking client library written in pure Python.
It is wire format compatible with the NDN-TLV encoding.

---

See the file [INSTALL.md](https://github.com/named-data/PyNDN2/blob/master/INSTALL.md)
for instructions to build and run from the full distribution.

If you are new to the NDN community of software generally, read the
[Contributor's Guide](https://github.com/named-data/NFD/blob/master/CONTRIBUTING.md).
Proposed code contributions should use a
[GitHub pull request](https://github.com/named-data/PyNDN2/pulls).

If you only need to install the pyndn Python module, you can use easy_install.
(If you don't have easy_install, see the instructions at
https://pypi.python.org/pypi/setuptools#installation-instructions .)
To avoid installation problems, make sure you have the latest version of pip.

For OS X, in a terminal, enter:

    sudo easy_install pip
    sudo CFLAGS=-Qunused-arguments pip install cryptography
    sudo easy_install pyndn

For Ubuntu or Raspbian (Raspberry Pi), in a terminal, enter:

    sudo apt-get install build-essential libssl-dev libffi-dev python-dev python-pip
    sudo easy_install pyndn

For Windows Cygwin, in the Cygwin installer, select and install the "Devel"
packages at the top level of the installer. In a terminal, enter:

    easy_install pyndn

This installs the pyndn module on the Python search path so that applications
which depend on it can use it, but does not install the sample tests or documentation
files. If you need these other files, then use the full distribution and see the INSTALL.md file.

---

Please submit any bugs or issues to the PyNDN issue tracker:
http://redmine.named-data.net/projects/pyndn/issues

---
	
The library currently requires a remote NDN daemon, and has been tested with NFD from the package
https://github.com/named-data/NFD .

The API follows the NDN Common Client Library API also used by ndn-cpp (C++) and ndn-js (JavaScript).
See http://named-data.net/doc/ndn-ccl-api .

Since PyNDN 2.0 conforms to the new Common Client Library API, applications written in the pre-2.0 version
of PyNDN need to be upgraded.

License
-------
This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Lesser General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU Lesser General Public License for more details.

You should have received a copy of the GNU Lesser General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
A copy of the GNU Lesser General Public License is in the file COPYING.
