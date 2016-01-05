# -*- Mode:python; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
#
# Copyright (C) 2014-2016 Regents of the University of California.
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
# GNU Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
# A copy of the GNU Lesser General Public License is in the file COPYING.

from collections import OrderedDict
from pyndn.util.common import Common

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
"""
This class is provided for compatibility with the Boost INFO property list
format used in ndn-cxx.

Each node in the tree may have a name and a value as well as associated
sub-trees. The sub-tree names are not unique, and so sub-trees are stored as
dictionaries where the key is a sub-tree name and the values are the sub-trees
sharing the same name.

Nodes can be accessed with a path syntax, as long as nodes in the path do not
contain the path separator '/' in their names.
"""
class BoostInfoTree(object):
    def __init__(self, value = None, parent = None):
        super(BoostInfoTree, self).__init__()
        self.subtrees = OrderedDict()
        self.value = value
        self.parent = parent

        self.lastChild = None

    def clone(self):
        """
        Create a deep copy of this tree.
        """
        copy = BoostInfoTree(self.value)
        for subtreeName, subtrees in self.subtrees.items():
            for t in subtrees:
                newTree = t.clone()
                copy.addSubtree(subtreeName, newTree)
        return copy

    def addSubtree(self, treeName, newTree):
        """
        Insert a BoostInfoTree as a sub-tree with the given name.
        :param str treeName: The name of the new sub-tree.
        :param BoostInfoTree newTree: The sub-tree to add.
        """
        if treeName in self.subtrees:
            self.subtrees[treeName].append(newTree)
        else:
            self.subtrees[treeName] = [newTree]
        newTree.parent = self
        self.lastChild = newTree

    def createSubtree(self, treeName, value=None ):
        """
        Create a new BoostInfo and insert it as a sub-tree with the given name.
        :param str treeName: The name of the new sub-tree.
        :param str value: The value associated with the new sub-tree.
        :return: The created sub-tree.
        :rtype: BoostInfoTree
        """

        newTree = BoostInfoTree(value, self)
        self.addSubtree(treeName, newTree)
        return newTree

    def __getitem__(self, key):
        key = key.lstrip('/')
        path = key.split('/')
        if len(key) == 0:
            return [self]

        subtrees = self.subtrees[path[0]]
        if len(path) == 1:
            return subtrees

        newPath = '/'.join(path[1:])
        foundVals = []
        for t in subtrees:
            foundVals.extend(t.__getitem__(newPath))
        return foundVals

    def getValue(self):
        """
        :return: The value associated with this tree.
        :rtype: str
        """
        return self.value

    def _prettyprint(self, indentLevel=1):
        prefix = " "*indentLevel
        s = ""
        if self.parent is not None:
            if self.value is not None and len(self.value) > 0:
                s += "\"" + str(self.value) + "\""
            s+= "\n"
        if len(self.subtrees) > 0:
            if self.parent is not None:
                s += prefix+ "{\n"
            nextLevel = " "*(indentLevel+2)
            for t in self.subtrees:
                for subtree in self.subtrees[t]:
                    s += nextLevel + str(t) + " " + subtree._prettyprint(indentLevel+2)
            if self.parent is not None:
                s +=  prefix + "}\n"
        return s

    def __str__(self):
        return self._prettyprint()


"""
This class reads files in Boost's INFO format and constructs a BoostInfoTree.
"""
class BoostInfoParser(object):
    def __init__(self):
        self._root = BoostInfoTree()

    def read(self, fileNameOrInput, inputName = None):
        """
        Add the contents of the file or input string to the root BoostInfoTree.
        There are two forms:
        read(fileName) reads fileName from the file system.
        read(input, inputName) reads from the input, in which case inputName is
        used only for log messages, etc.

        :param str fileName: The path to the INFO file.
        :param str input: The contents of the INFO file, with lines separated by
          NL or CR/NL.
        :param str inputName: Use with input for log messages, etc.
        """
        if Common.typeIsString(inputName):
            input = fileNameOrInput
        else:
            # No inputName, so assume the first arg is the file name.
            fileName = fileNameOrInput
            inputName = fileName
            f = open(fileName, 'r')
            input = f.read()
            f.close()

        self._read(input, self._root)

    def readPropertyList(self, fromDict):
        """
        Import a python dict as a BoostInfoTree. Only leaf nodes will have
        associated values.
        :param dict fromDict: The dictionary to import.
        """
        if not isinstance(fromDict, dict):
            raise TypeError('BoostInfoTree must be initialized from dictionary')
        self._readDict(fromDict, self._root)
        return self._root

    def _read(self, input, ctx):
        """
        Internal import method with an explicit context node.
        :param str input: The contents of the INFO file, with lines separated by
          "\n" or "\r\n".
        :param BoostInfoTree ctx: The node currently being populated.
        :return: The ctx.
        :rtype: BoostInfoTree
        """
        for line in input.splitlines():
            ctx = self._parseLine(line.strip(), ctx)

        return ctx

    def _readList(self, fromList, intoNode, keyName):
        """
        Helper method for reading lists inside imported dictionaries.
        """
        # we can have lists of strings or dicts, ONLY
        for v in fromList:
            if hasattr(v, 'keys'):
                newNode = intoNode.createSubtree(keyName)
                self._readDict(v, newNode)
            else:
                intoNode.createSubtree(keyName, v)

    def _readDict(self, fromDict, currentNode):
        """
        Helper method for reading dictionaries inside imported dictionaries.
        """
        for k,v in fromDict.items():
            # HACK
            if k == '__name__':
                continue
            if hasattr(v, 'keys'):
                newNode = currentNode.createSubtree(k)
                self._readDict(v, newNode)
            elif hasattr(v, '__iter__'):
                self._readList(v, currentNode, k)
            else:
                # should be a string, should I check?
                currentNode.createSubtree(k,v)


    def write(self, filename):
        """
        Write the root tree of this BoostInfoParser as file in Boost's INFO
        format.
        :param str filename: The output path.
        """
        with open(filename, 'w') as stream:
            stream.write(str(self._root))

    def _parseLine(self, string, context):
        """
        Internal helper method for parsing INFO files line by line.
        """
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
            #if it is an "#include", load the new file instead of inserting keys
            if key == "#include":
                f = open(val, 'r')
                input = f.read()
                f.close()
                context = self._read(input, context)
            else:
                newTree = context.createSubtree(key, val)

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
        """
        :return: The root tree of this parser.
        :rtype: BoostInfoTree
        """
        return self._root

    def __getitem__(self, key):
        return self._root.__getitem__(key)
