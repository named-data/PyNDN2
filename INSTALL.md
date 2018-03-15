PyNDN: A Named Data Networking client library with TLV wire format support in native Python
===========================================================================================

These are instructions to install and run from the full PyNDN distribution.
If you only need to install the pyndn Python module, you can use the easy_install instructions
from the [README.md](https://github.com/named-data/PyNDN2/blob/master/README.md) file.

Prerequisites
=============
* Required: Python 2.7 or later
* Required: The cryptography package
* Optional: trollius (for asyncio in Python <= 3.2)
* Optional: Protobuf (for the ProtobufTlv converter and ChronoSync)
* Optional: Sphinx (to make documentation)
* Optional: pytest and mock (for running unit tests)
* Optional: python-dev, libcrypto (for the _pyndn C module)

### Option to use easy_install

If you use easy_install to install the pyndn module, it automatically installs
the prerequisites for trollius/asyncio and Protobuf needed to run PyNDN.
To avoid installation problems, make sure you have the latest version of pip.

To use easy_install in OS X, change directory to the PyNDN root and enter:

    sudo easy_install pip
    sudo CFLAGS=-Qunused-arguments pip install cryptography
    sudo python setup.py install

To use easy_install in Ubuntu or Raspbian (Raspberry Pi), change directory to the PyNDN root and enter:

    sudo apt-get install build-essential libssl-dev libffi-dev python-dev python-pip
    sudo python setup.py install

To use easy_install in Windows Cygwin, in the Cygwin installer, select and
install the "Devel" packages at the top level of the installer. Change directory
to the PyNDN root and enter:

    python setup.py install

Otherwise, following are the detailed steps for each platform to manually install the prerequisites.

## OS X 10.10.2, OS X 10.11, macOS 10.12, macOS 10.13
Install Xcode.  (Xcode seems to already have the Command Line Tools.)
To install the cryptography package, in a terminal enter:

    sudo easy_install pip
    sudo CFLAGS=-Qunused-arguments pip install cryptography

Optional: To install trollius (Python <= 3.2), in a terminal enter:

    sudo pip install trollius

Optional: To install Protobuf in Python 2, in a terminal enter:

    sudo pip install protobuf

Optional: To install Protobuf in Python 3, in a terminal enter:

    sudo pip install protobuf-py3

Optional: To install Sphinx, in a terminal enter:

    sudo pip install sphinx

Optional: To install pytest and mock, in a terminal enter:

    sudo CFLAGS=-Qunused-arguments pip install pytest mock

If you get an error like "Uninstalling six-1.4.1. Operation not permitted", try this instead:

    sudo CFLAGS=-Qunused-arguments pip install pytest mock --ignore-installed six

Optional: To install libcrypto, install Xcode and install MacPorts from
http://www.macports.org/install.php . In a new terminal, enter:

    sudo port install openssl

The python-dev headers are already installed.

## Ubuntu 12.04 (64 bit and 32 bit)
To install the cryptography package, in a terminal enter:

    sudo apt-get install build-essential libssl-dev libffi-dev python-dev python-pip
    sudo pip install cryptography

Optional: To install trollius (Python <= 3.2), in a terminal enter:

    sudo apt-get install python-pip
    sudo pip install trollius

Optional: To install Sphinx, in a terminal enter:

    sudo apt-get install python-pip
    sudo pip install sphinx

Optional: To install pytest and mock, in a terminal enter:

    sudo apt-get install python-pip
    sudo pip install pytest mock

Optional: To install libcrypto, in a terminal enter:

    sudo apt-get install build-essential libssl-dev

(Protobuf is already installed.)

## Ubuntu 14.04 (64 bit and 32 bit), 15.04 (64 bit), 16.04 (64 bit and 32 bit) and 16.10 (64 bit)
To install the cryptography package, in a terminal enter:

    sudo apt-get install build-essential libssl-dev libffi-dev python-dev python-pip
    sudo pip install cryptography

Optional: To install trollius (Python <= 3.2), in a terminal enter:

    sudo apt-get install python-pip
    sudo pip install trollius

Optional: To install Sphinx, in a terminal enter:

    sudo apt-get install python-pip
    sudo pip install sphinx

Optional: To install Protobuf in Python 2, in a terminal enter:

    sudo apt-get install python-pip
    sudo pip install protobuf

Optional: To install Protobuf in Python 3, in a terminal enter:

    sudo apt-get install python-pip
    sudo pip install protobuf-py3

Optional: To install pytest and mock, in a terminal enter:

    sudo apt-get install python-pip
    sudo pip install pytest mock

Optional: To install python-dev and libcrypto, in a terminal enter:

    sudo apt-get install build-essential python-dev libssl-dev

## Raspbian Jessie (Raspberry Pi)
(pip is already installed.) To install the cryptography package, in a terminal, enter:

    sudo apt-get install build-essential libssl-dev libffi-dev python-dev
    sudo pip install cryptography

Optional: To install trollius (Python <= 3.2), in a terminal enter:

    sudo pip install trollius

Optional: To install Sphinx, in a terminal enter:

    sudo pip install sphinx

Optional: To install Protobuf in Python 2, in a terminal enter:

    sudo pip install protobuf

Optional: To install pytest and mock, in a terminal enter:

    sudo pip install pytest mock

## Windows Cygwin
Cygwin is tested on Windows 7 64-bit. 

In the Cygwin installer, select and install the "Devel" packages at the top level of the installer.  
To install the cryptography package, in a Cygwin terminal, enter:

    easy_install pip
    pip install cryptography

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
To use pip, you must have Visual Studio installed. 
Pip only looks at the environment variable `VS90COMNTOOLS` so you must set this 
to your version of Visual Studio as follows:

Visual Studio 2010

    SET VS90COMNTOOLS=%VS100COMNTOOLS%

Visual Studio 2012

    SET VS90COMNTOOLS=%VS110COMNTOOLS%

Visual Studio 2013

    SET VS90COMNTOOLS=%VS120COMNTOOLS%

To install the cryptography package, in a command prompt enter:

    c:\Python27\Scripts\pip.exe install cryptography

Optional: To run trollius in Python 2.7, it apparently needs some DLLs from
Python 3. So, to run trollius in Python 2.7, install Python 3.  
To install trollius (Python 2.7), in a command prompt enter:

    c:\Python27\Scripts\pip.exe install trollius

Build
=====
You need PyNDN on the Python path.  To temporarily set it, do the following.
If `<PyNDN root>` is the path to the root of the PyNDN distribution, in a terminal enter:

    export PYTHONPATH=$PYTHONPATH:<PyNDN root>/python

To run the unit tests, in a terminal change to the directory `<PyNDN root>/tests/unit_tests` and enter:

    python -m pytest test_*.py

To run the integration tests (you must be running NFD), in a terminal change to
the directory `<PyNDN root>/tests/integration_tests` and enter:

    python -m pytest test_*.py

Example files are in `<PyNDN root>/examples`.  For example in a terminal enter:

    cd <PyNDN root>/examples
    python test_encode_decode_data.py
    python test_get_async.py

To make the Sphinx documentation, in a terminal change to the doc subdirectory. Enter:
  
    make html

The documentation output is in `doc/_build/html/index.html`.

### _pyndn C module

To install the optional _pyndn C module, you need the prerequisites python-dev
and libcrypto. To build in a terminal, change directory to the PyNDN2 root.  Enter:

    ./configure
    make
    sudo make install

Notice where the modules are installed. On the Mac, depending on your installation
you may need to link the files from the correct packages folder:

    cd /Library/Python/2.7/site-packages/
    sudo ln -s /usr/local/lib/python2.7/site-packages/_pyndn.la
    sudo ln -s /usr/local/lib/python2.7/site-packages/_pyndn.so

Files
=====
This has the following example programs:

* examples/test_get_async.py: Connect to one of the NDN testbed hubs, express an interest and display the received data.
* examples/test_get_async_threadsafe.py: The same as test_get_async.py, but use asyncio and the ThreadsafeFace.
* examples/test_publish_async_nfd.py: Connect to the local NFD hub, accept interests with prefix /testecho and echo back a data packet. See test_echo_consumer.py.
* examples/test_echo_consumer.py: Prompt for a word, send the interest /testecho/word to the local hub which is echoed by test_publish_async_nfd.py (or test_publish_async_ndnx.py).
* examples/test_encode_decode_interest.py: Encode and decode an interest, testing interest selectors and the name URI.
* examples/test_encode_decode_data.py: Encode and decode a data packet, including signing the data packet.
* examples/test_encode_decode_fib_entry.py: Encode and decode a sample Protobuf message using ProtobufTlv.
* examples/test_chrono_chat.py: A command-line chat application using the ChronoSync2013 API, compatible with ChronoChat-js.
