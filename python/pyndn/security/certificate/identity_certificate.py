# -*- Mode:python; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
#
# Copyright (C) 2014 Regents of the University of California.
# Author: Jeff Thompson <jefft0@remap.ucla.edu>
# See COPYING for copyright and distribution information.
#

class IdentityCertificate(object):
    @staticmethod
    def certificateNameToPublicKeyName(certificateName):
        """
        Get the public key name from the full certificate name.
        
        :param certificateName: The full certificate name.
        :type name: Name
        :return: The related public key name.
        :rtype: Name
        """
        i = certificateName.size() - 1
        idString = "ID-CERT"
        while i >= 0:
            if certificateName.get(i).toEscapedString() == idString:
                break
            i -= 1

        tmpName = certificateName.getSubName(0, i)        
        keyString = "KEY"
        for i in range(tmpName.size()):
            if tmpName.get(i).toEscapedString() == keyString:
                break

        return tmpName.getSubName(0, i).append(
          tmpName.getSubName(i + 1, tmpName.size() - i - 1))
