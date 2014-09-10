
# -*- Mode:python; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
#
# Copyright (C) 2014 Regents of the University of California.
# Author: Adeola Bannis 
# 
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Lesser General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
# A copy of the GNU General Public License is in the file COPYING.

from collections import OrderedDict

#TODO: process includes

def shlex_split(s):
    """
    Similar to shlex.split, split s into an array of strings which are 
    separated by whitespace, treating a string within quotes as a single entity
    regardless of whitespace between the quotes. Also allow a backslash to
    escape the next character.
    
    :param str s: The input string to split.
    :return: An array of strings.
    :rtype: list of str
    """
    result = []
    if s == "":
        return result
    whiteSpace = " \t\n\r"
    iStart = 0

    while True:
        # Move iStart past whitespace.
        while s[iStart] in whiteSpace:
            iStart += 1
            if iStart >= len(s):
                # Done.
                return result

        # Move iEnd to the end of the token.
        iEnd = iStart
        inQuotation = False
        token = ""
        while True:
            if s[iEnd] == '\\':
                # Append characters up to the backslash, skip the backslash and
                #   move iEnd past the escaped character.
                token += s[iStart:iEnd]
                iStart = iEnd + 1
                iEnd = iStart
                if iEnd >= len(s):
                    # An unusual case: A backslash at the end of the string.
                    break
            else:
                if inQuotation:
                    if s[iEnd] == '\"':
                        # Append characters up to the end quote and skip.
                        token += s[iStart:iEnd]
                        iStart = iEnd + 1
                        inQuotation = False
                else:
                    if s[iEnd] == '\"':
                        # Append characters up to the start quote and skip.
                        token += s[iStart:iEnd]
                        iStart = iEnd + 1
                        inQuotation = True
                    else:
                        if s[iEnd] in whiteSpace:
                            break

            iEnd += 1
            if iEnd >= len(s):
                break

        token += s[iStart:iEnd]
        result.append(token)
        if iEnd >= len(s):
            # Done.
            return result

        iStart = iEnd

class BoostInfoTree(object):
    def __init__(self, value = None, parent = None):
        super(BoostInfoTree, self).__init__()
        self.subTrees = OrderedDict()
        self.value = value
        self.parent = parent

        self.lastChild = None

    def createSubtree(self, treeName, value=None ):
        newTree = BoostInfoTree(value, self)
        if treeName in self.subTrees:
            self.subTrees[treeName].append(newTree)
        else:
            self.subTrees[treeName] = [newTree]
        self.lastChild = newTree
        return newTree

    def __getitem__(self, key):
        # since there can be repeated keys, we may have to get creative
        found = self.subTrees[key]
        return list(found)

    def getValue(self):
        return self.value

    def _prettyprint(self, indentLevel=1):
        prefix = " "*indentLevel
        s = ""
        if self.parent is not None:
            if self.value is not None and len(self.value) > 0:
                s += "\"" + str(self.value) + "\""
            s+= "\n" 
        if len(self.subTrees) > 0:
            if self.parent is not None:
                s += prefix+ "{\n"
            nextLevel = " "*(indentLevel+2)
            for t in self.subTrees:
                for subTree in self.subTrees[t]:
                    s += nextLevel + str(t) + " " + subTree._prettyprint(indentLevel+2)
            if self.parent is not None:
                s +=  prefix + "}\n"
        return s

    def __str__(self):
        return self._prettyprint()


class BoostInfoParser(object):
    def __init__(self):
        self._root = BoostInfoTree()

    def read(self, filename):
        with open(filename, 'r') as stream:
            ctx = self._root
            for line in stream:
                ctx = self._parseLine(line.strip(), ctx)

    def write(self, filename):
        with open(filename, 'w') as stream:
            stream.write(str(self._root))

    def _parseLine(self, string, context):
        # skip blank lines and comments
        commentStart = string.find(";")
        if commentStart >= 0:
           string = string[:commentStart].strip()
        if len(string) == 0:
           return context

        # usually we are expecting key and optional value
        strings = shlex_split(string)
        isSectionStart = False
        isSectionEnd=False
        for s in strings:
            isSectionStart = isSectionStart or s == '{'
            isSectionEnd = isSectionEnd or s == '}'

        if not isSectionStart and not isSectionEnd:
            key = strings[0]
            if len(strings) > 1:
                val = strings[1]
            else:
                val = None
            context.createSubtree(key, val)

            return context
        # ok, who is the joker who put a { on the same line as the key name?!
        sectionStart = string.find('{')
        if sectionStart > 0:
            firstPart = string[:sectionStart]
            secondPart = string[sectionStart:]

            ctx = self._parseLine(firstPart, context)
            return self._parseLine(secondPart, ctx)


        #if we encounter a {, we are beginning a new context
        # TODO: error if there was already a subcontext here
        if string[0] == '{':
            context = context.lastChild 
            return context

        # if we encounter a }, we are ending a list context
        if string[0] == '}':
            context = context.parent
            return context

        raise RuntimeError("BoostInfoParser: input line is malformed")

    def getRoot(self):
        return self._root

    def __getitem__(self, key):
        ctxList = [self._root]
        path = key.split('/')
        for k in path:
            newList = []
            for ctx in ctxList:
                try:
                    newList.extend(ctx[k])
                except KeyError:
                    pass
            ctxList = newList
        
        return ctxList

def main():
    import sys
    try:
        filename = sys.argv[1]
        parser = BoostInfoParser()
        parser.read(filename)
        parser.write('test.conf')
        parser2 = BoostInfoParser()
        parser2.read('test.conf')
        print str(parser2.getRoot()) == str(parser.getRoot())
        print parser2.getRoot()
    except IndexError:
        print 'Usage: {} filename'.format(sys.argv[0])

if __name__ == '__main__':
    main()

