#! /usr/bin/env python2.7

import getopt, sys, time, util
from wmbus import WMBusFrame
   
def main(argv):
    
    filename = ''
    text = ''
    usagetext = 'reader.py [-v]erbose -f <filename>\nreader.py [-v]erbose -t \'<CA FE BA BE...>\''
    verbosity = 0 

    # setup known keys dictionarry by their device id
    keys = {
    	'\x57\x00\x00\x44': '\xCA\xFE\xBA\xBE\x12\x34\x56\x78\x9A\xBC\xDE\xF0\xCA\xFE\xBA\xBE',
    	'\x00\x00\x00\x00': '\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF'
    }
    
    try:
        opts, args = getopt.getopt(argv,"vt:f:",["text=", "filename="])
    except getopt.GetoptError:
        print usagetext
        sys.exit(2)
    for opt, arg in opts:
        if opt in ("-f", "--filename"):
            filename = arg
            text = open(filename, 'r').read()
        if opt in ("-t", "--text"):
            text = arg
        if opt in ("-v"):
            verbosity = 2
    
    if verbosity > 0:
        print "verbosity: ", verbosity
        print "filename: ", filename
        print "txt: ",text

    capture = bytearray().fromhex(text)
    
    if verbosity > 0: 
        print "hex: ", util.tohex(capture)

    frame = WMBusFrame()
    frame.parse(capture, keys)
    frame.log(verbosity)


if __name__ == "__main__":
    main(sys.argv[1:])
