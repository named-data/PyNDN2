PyNDN: An Named Data Networking client library with TLV wire format support in native Python
============================================================================================

PyNDN 2.0 is a new implementation of a Named Data Networking client library written in pure Python.
It is wire format compatible with the new NDN-TLV encoding, with ndnd-tlv and NFD.
	
See the file INSTALL.md for build and install instructions.

Please submit any bugs or issues to the PyNDN issue tracker:
http://redmine.named-data.net/projects/pyndn/issues

---
	
The library currently requires a remote NDN daemon, and has been tested with ndnd-tlv, from
the NDN-TLV package: https://github.com/named-data/ndnd-tlv .

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
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
A copy of the GNU General Public License is in the file COPYING.
