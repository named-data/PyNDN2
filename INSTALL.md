PyNDN: A Named Data Networking client library with TLV wire format support in native Python
===========================================================================================

Prerequisites
=============
* Required: Python 2.7 or later
* Required: PyCrypto
* Optional: trollius (for asyncio in Python 2.7)

Following are the detailed steps for each platform to install the prerequisites.

## Mac OS X 10.7.3, Mac OS X 10.8.5
Install Xcode.  
In Xcode Preferences > Downloads, install "Command Line Tools".  
In a terminal, enter:  

    sudo easy_install pip
    sudo pip install pycrypto

Optional: To install trollius (Python 2.7), in a terminal enter:

    sudo pip install trollius

## Mac OS X 10.9
Install Xcode.  (Xcode on OS X 10.9 seems to already have the Command Line Tools.)  
In a terminal, enter:

    sudo easy_install pip
    sudo pip install pycrypto

Optional: To install trollius (Python 2.7), in a terminal enter:

    sudo pip install trollius

## Ubuntu 12.04 (64 bit and 32 bit)
Need to build/install the latest PyCrypto. In a terminal, enter:

    cd ~
    sudo apt-get install git
    git clone https://github.com/dlitz/pycrypto.git
    cd pycrypto
    sudo apt-get install python-dev
    python setup.py build
    sudo python setup.py install

Optional: To install trollius (Python 2.7), in a terminal enter:

    sudo apt-get install python-pip
    sudo pip install trollius

## Ubuntu 13.10 (64 bit)
(PyCrypto is already installed.)

Optional: To install trollius (Python 2.7), in a terminal enter:

    sudo apt-get install python-pip
    sudo pip install trollius

## Windows Cygwin
Cygwin is tested on Windows 7 64-bit. 

In the Cygwin installer, select and install the "Devel" packages at the top level of the installer.  
In a Cygwin terminal, enter:

    easy_install pip
    pip install pycrypto

Optional: To install trollius (Python 2.7), in a terminal enter:

    pip install trollius

## Windows 7 (no Cygwin)
In the following, change `c:\Python27\` or `c:\Python34\` to your correct Python directory
(or omit if you have python.exe in your PATH).

### Python 2.7 for Windows

To install pip, download get-pip.py from https://pip.pypa.io/en/latest/installing.html .  
In a command prompt, enter:

    c:\Python27\python.exe get-pip.py

This installs pip.exe in the Scripts subdirectory of the Python directory.

TODO: pip install pycrypto

Optional: To run trollius in Python 2.7, it apparently needs some DLLs from
Python 3. So, to run trollius in Python 2.7, install Python 3.  
To install trollius (Python 2.7), in a terminal enter:

    c:\Python27\Scripts\pip.exe install trollius

Build
=====
You need PyNDN on the Python path.  To temporarily set it, do the following.
If `<PyNDN root>` is the path to the root of the PyNDN distribution, in a terminal enter:

    export PYTHONPATH=$PYTHONPATH:<PyNDN root>/python

For examples, see the test files in `<PyNDN root>/tests`.  For example in a terminal enter:

    cd <PyNDN root>/tests
    python test_encode_decode_data.py
    python test_get_async.py

Files
=====
This has the following test files:

* tests/test_get_async.py: Connect to one of the NDN testbed hubs, express an interest and display the received data.
* tests/test_get_async_threadsafe.py: The same as test_get_async.py, but use asyncio and the ThreadsafeFace.
* tests/test_publish_async_ndnx.py: Connect to the local NDNx hub, accept interests with prefix /testecho and echo back a data packet. See test_echo_consumer.py.
* tests/test_publish_async_nfd.py: Connect to the local NFD hub, accept interests with prefix /testecho and echo back a data packet. See test_echo_consumer.py.
* tests/test_echo_consumer.py: Prompt for a word, send the interest /testecho/word to the local hub which is echoed by test_publish_async_nfd.py (or test_publish_async_ndnx.py).
* tests/test_encode_decode_interest.py: Encode and decode an interest, testing interest selectors and the name URI.
* tests/test_encode_decode_data.py: Encode and decode a data packet, including signing the data packet.
* tests/test_encode_decode_forwarding_entry.py: Encode and decode a forwarding entry packet, including signing the data packet.
