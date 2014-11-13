# -*- Mode:python; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
#
# Copyright (C) 2014 Regents of the University of California.
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

from pyndn import ForwardingEntry
from pyndn import Name

def dump(*list):
    result = ""
    for element in list:
        result += (element if type(element) is str else repr(element)) + " "
    print(result)

def dumpForwardingEntry(forwardingEntry):
    dump("action:", forwardingEntry.getAction()
                    if forwardingEntry.getAction() != None else "<none>")
    dump("prefix:", forwardingEntry.getPrefix().toUri())
    dump("faceID:", forwardingEntry.getFaceId()
                    if forwardingEntry.getFaceId() != None else "<none>")

    flags = ""
    if forwardingEntry.getForwardingFlags().getActive():
        flags += " active"
    if forwardingEntry.getForwardingFlags().getChildInherit():
        flags += " childInherit"
    if forwardingEntry.getForwardingFlags().getAdvertise():
        flags += " advertise"
    if forwardingEntry.getForwardingFlags().getLast():
        flags += " last"
    if forwardingEntry.getForwardingFlags().getCapture():
        flags += " capture"
    if forwardingEntry.getForwardingFlags().getLocal():
        flags += " local"
    if forwardingEntry.getForwardingFlags().getTap():
        flags += " tap"
    if forwardingEntry.getForwardingFlags().getCaptureOk():
        flags += " captureOk"
    dump("forwardingFlags:" + flags)

    dump("freshnessPeriod (milliseconds):",
         forwardingEntry.getFreshnessPeriod()
         if forwardingEntry.getFreshnessPeriod() >= 0 else "<none>")


def main():
    forwardingEntry = ForwardingEntry()
    forwardingEntry.setAction("selfreg")
    forwardingEntry.setPrefix(Name("/meki"))
    forwardingEntry.setFaceId(1)
    forwardingEntry.getForwardingFlags().setForwardingEntryFlags(255)
    forwardingEntry.setFreshnessPeriod(1000000)

    reDecodedForwardingEntry = ForwardingEntry()
    reDecodedForwardingEntry.wireDecode(forwardingEntry.wireEncode())
    dump("Re-decoded forwarding entry:")
    dumpForwardingEntry(reDecodedForwardingEntry)

main()
