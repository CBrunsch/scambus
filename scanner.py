#! /usr/bin/env python2.7

import getopt, sys, time, util
from wmbus import WMBusFrame
from Crypto.Cipher import AES
   
def main(argv):
    
    samplefile = ''
    interface = '/dev/ttyUSB3'
    usagetext = 'scanner.py -hv -i <interface>'
    verbosity = 0
    
    # setup known keys dictionarry by their device id
    keys = {
    	'\x57\x00\x00\x44': '\xCA\xFE\xBA\xBE\x12\x34\x56\x78\x9A\xBC\xDE\xF0\xCA\xFE\xBA\xBE',
    	'\x00\x00\x00\x00': '\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF'
    }
    
    try:
        opts, args = getopt.getopt(argv,"v:hi:",["interface="])
    except getopt.GetoptError:
        print usagetext
        sys.exit(2)
    for opt, arg in opts:
        if opt == '-h':
            print usagetext
            sys.exit()
        else:
            if opt in ("-i", "--interface"):
                interface = arg
            if opt == "-v":
                verbosity = 1
                
                if arg == 'v':
                    verbosity = 2
                
                if arg == 'vv':
                    verbosity = 3

    while 1:
        # setup values
        arr = bytearray()
        state = 0
        frame_length = -1
        
        # connect sniffer device
        ser = util.connect_sniffer(interface)

        # sleep for a while in case there is no data available
        while ser.inWaiting() == 0:
            time.sleep(2)

        # data arrived, go and get it
        while ser.inWaiting() > 0:

            if (state == 0):
                '''
                let's get the leading two bytes from the serial stream and
                check whether they match hex FF 03. Do this until we reach 
                the next FF 03 start sequence
                
                TODO:
                - How is the trailing byte checksum calculated?
                '''
                arr.append(ser.read(1))
                
                if (arr[0] == 0xFF):
					# found 0xFF, let's see whether the following byte is 0x03
                	arr.append(ser.read(1))
                	
                	if (arr[0] == 0xFF and len(arr) == 2 and arr[1] == 0x03):
						# just hit a valid start sequence => enter next state
						state = 1
                else:
                    '''
                    just hit an invalid start sequence. let's drop the bytes 
                    and start over
                    '''
                    arr = bytearray()
            elif (state == 1):
                # let's read the frame length from the next byte
                arr.append(ser.read(1))
                frame_length = arr[2] -1
                state = 2
            elif (state == 2):
                '''
                in case the payload length is greater than zero bytes, read 
                frame_length bytes from the serial stream
                '''
                if (len(arr)-3 < frame_length):
                    for i in range(frame_length):
                        arr.append(ser.read(1))
                        
                    if (verbosity >= 3):
                        # print the whole wireless M-Bus frame in hex
                        print util.tohex(arr)
                    
                    # instantiate an wireless m-bus frame based on the data
                    frame = WMBusFrame() 
                    frame.parse(arr[2:], keys)
                    
                    # print wM-Bus frame information as log line
                    frame.log(verbosity)
                
                # clear array and go to detect the next start sequence
                arr = bytearray()
                state = 0
    
        
if __name__ == "__main__":
    main(sys.argv[1:])

    '''
    Class Scanner(threading.Thread):
        def __init__(self,dev):
        #something here that initialize serial port
        def run():
            while True:

        def pack(self):
        #something
        def checksum(self):
        #something
        def write(self):
        #something
    '''
