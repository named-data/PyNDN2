# -*- Mode:python; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
#
# Copyright (C) 2014 Regents of the University of California.
# Author: Jeff Thompson <jefft0@remap.ucla.edu>
# See COPYING for copyright and distribution information.
#

from pyndn import ForwardingEntry

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
    forwardingEntry.getPrefix().set("/meki")
    forwardingEntry.setFaceId(1)
    forwardingEntry.getForwardingFlags().setForwardingEntryFlags(255)
    forwardingEntry.setFreshnessPeriod(1000000)
    
    reDecodedForwardingEntry = ForwardingEntry()
    reDecodedForwardingEntry.wireDecode(forwardingEntry.wireEncode())
    dump("Re-decoded forwarding entry:")
    dumpForwardingEntry(reDecodedForwardingEntry)

main()
