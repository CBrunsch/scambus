import serial 
from array import array

# global variables
debug = 0


def connect_sniffer(port):
	""" Connect to sniffer device on specified port.
	
	Provides means to connect to the serial tty which is commonly created by 
	FTDI based wireless M-Bus sniffer devices that deliver sniffed wM-Bus
	frames as continuous stream at the tty
	"""
	ser = serial.Serial(
		port=port,
		baudrate=9600,
		parity=serial.PARITY_NONE,
		stopbits=serial.STOPBITS_ONE,
		bytesize=serial.EIGHTBITS,
		#rtscts=False,
		timeout=30
	)
	
	ser.open()
	ser.isOpen()
	
	return ser

def loadsample(path):
	""" Load sample frame from file specified by path.
	
	The method supports to load captured wireless M-Bus frames from files for 
	any debugging or replay purposes
	"""
	
	f = open(path,'rb')
	a = array('B', f.read())
	
	if debug:
		print '-- file contents --'
		print a
		print '-- eof --'
		
	return a   
	
def tohex(v, split=' '):
    """ Return value in hex form as a string (for pretty printing purposes).
    
    The function provides a conversion of integers or byte arrays ('B') into 
    their hexadecimal form separated by the splitter string
    """
    if type(v) == array or type(v) == bytearray or type(v) == str:
        return split.join("%0.2X" % x for x in v)
    elif type(v) ==  int:
        return "%0.2X" % v
    else:
        return "tohex(): unsupported type"
