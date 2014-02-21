PyNDN: An Named Data Networking client library with TLV wire format support in native Python
============================================================================================

PyNDN 2.0 is a new implementation of a Named Data Networking client library written in pure Python.
It is wire format compatible with the new NDN-TLV encoding, with ndnd-tlv and NFD.
	
PyNDN is open source under a license described in the file COPYING.  While the license
does not require it, we really would appreciate it if others would share their
contributions to the library if they are willing to do so under the same license. 

See the file INSTALL for build and install instructions.

Please submit any bugs or issues to the PyNDN issue tracker:
http://redmine.named-data.net/projects/pyndn/issues

---
	
The library currently requires a remote NDN daemon, and has been tested with ndnd-tlv, from
the NDN-TLV package: https://github.com/named-data/ndnd-tlv .

The API follows the NDN Common Client Library API also used by ndn-cpp (C++) and ndn-js (JavaScript).
See http://named-data.net/doc/ndn-ccl-api .
Since PyNDN 2.0 conforms to the new Common Client Library API, applications written in pre-2.0 version
of PyNDN need to be upgraded.

