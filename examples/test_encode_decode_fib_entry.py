# -*- Mode:python; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
#
# Copyright (C) 2014-2018 Regents of the University of California.
# Author: Jeff Thompson <jefft0@remap.ucla.edu>
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Lesser General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
# A copy of the GNU Lesser General Public License is in the file COPYING.

# This module is produced by: protoc --python_out=. fib-entry.proto
import fib_entry_pb2
from pyndn.encoding import ProtobufTlv
from pyndn.util import Blob

def dump(*list):
    result = ""
    for element in list:
        result += (element if type(element) is str else str(element)) + " "
    print(result)

def main():
    # Construct a sample FibEntry message using the structure in fib_entry_pb2
    # which was produced by protoc.
    message = fib_entry_pb2.FibEntryMessage()
    message.fib_entry.name.component.append(b"ndn")
    message.fib_entry.name.component.append(b"ucla")
    nextHopRecord = message.fib_entry.next_hop_records.add()
    nextHopRecord.face_id = 16
    nextHopRecord.cost = 1

    # Encode the Protobuf message object as TLV.
    encoding = ProtobufTlv.encode(message)

    decodedMessage = fib_entry_pb2.FibEntryMessage()
    ProtobufTlv.decode(decodedMessage, encoding)

    dump("Re-decoded FibEntry:")
    # This should print the same values that we put in message above.
    value = ""
    value += ProtobufTlv.toName(decodedMessage.fib_entry.name.component).toUri()
    value += " nexthops = {"
    for next_hop_record in decodedMessage.fib_entry.next_hop_records:
      value += ("faceid=" + repr(next_hop_record.face_id)
                + " (cost=" + repr(next_hop_record.cost) + ")")
    value += " }"
    dump(value)

main()
