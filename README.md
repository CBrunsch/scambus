# scambus
Scambus is a python based wireless M-Bus scanner and dissector

# examples
## plaintext frames
```
scammer:~/Dev/scambus$ ./reader.py -v -f examples_captures/sample_amber_plaintext.hex 
verbosity:  2
filename:  examples_captures/sample_amber_plaintext.hex
txt:  46 44 a2 05 44 00 00 57 0c 37 72 44 00 00 57 a2 05 0c 37 50 00 00 00 2f 2f 0e 13 92 05 00 00 00 00 0d fd 11 20 65 64 6f 4d 20 53 20 21 6c 75 64 6f 6d 74 73 65 54 20 73 73 65 6c 65 72 69 77 20 52 45 42 4d 41 2f 2f
hex:  46 44 A2 05 44 00 00 57 0C 37 72 44 00 00 57 A2 05 0C 37 50 00 00 00 2F 2F 0E 13 92 05 00 00 00 00 0D FD 11 20 65 64 6F 4D 20 53 20 21 6C 75 64 6F 6D 74 73 65 54 20 73 73 65 6C 65 72 69 77 20 52 45 42 4D 41 2F 2F
cut:  0E 13 92 05 00 00 00 00 0D FD 11 20 65 64 6F 4D 20 53 20 21 6C 75 64 6F 6D 74 73 65 54 20 73 73 65 6C 65 72 69 77 20 52 45 42 4D 41
Nov 01 21:34:40 AMB 57 00 00 44 SND-NR Records: 2
--
CI Detail:	72 (EN 13757-3 Application Layer with long Transport Layer, SND-NR)
header:		long header
has errors:	False
access:		No access
config word:	00 00
mode:		0 (No encryption used)
--
DIFs:	0E (Instantaneous value, 12 digit BCD)
VIFs:	13 (Volume l)
Value:	00 00 00 00 05 92
--
DIFs:	0D (Instantaneous value, variable length)
VIFs:	FD 11 (Second extension of VIF-codes)
Value:	41 4D 42 45 52 20 77 69 72 65 6C 65 73 73 20 54 65 73 74 6D 6F 64 75 6C 21 20 53 20 4D 6F 64 65
--
```
## encrypted frames
In order to decrypt frames it is necessary to define keys. Keys are being defined as (device_id, key) pairs and cannot be passed on command line... currently.

Thus, edit reader.py accordingly
```
    # setup known keys dictionarry by their device id
    keys = {
    	'\x57\x00\x00\x44': '\xCA\xFE\xBA\xBE\x12\x34\x56\x78\x9A\xBC\xDE\xF0\xCA\xFE\xBA\xBE',
    	'\x00\x00\x00\x00': '\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF'
    }
```
scammer:~/Dev/scambus$ ./reader.py -v -f examples_captures/sample_amber_encrypted.hex verbosity:  2
filename:  examples_captures/sample_amber_encrypted.hex
txt:  46 44 a2 05 44 00 00 57 0c 37 72 44 00 00 57 a2 05 0c 37 a3 00 30 05 d8 98 c6 4f d0 c9 bd 26 34 36 50 84 e4 df 94 67 36 c7 1a 21 03 e4 5a 19 0c aa 1a 49 b6 02 e4 6c 9f 45 fc ee 79 af be 34 f0 c1 67 fd 85 7f 65 9e
hex:  46 44 A2 05 44 00 00 57 0C 37 72 44 00 00 57 A2 05 0C 37 A3 00 30 05 D8 98 C6 4F D0 C9 BD 26 34 36 50 84 E4 DF 94 67 36 C7 1A 21 03 E4 5A 19 0C AA 1A 49 B6 02 E4 6C 9F 45 FC EE 79 AF BE 34 F0 C1 67 FD 85 7F 65 9E
dec:  2F 2F 0E 13 75 06 00 00 00 00 0D FD 11 20 65 64 6F 4D 20 53 20 21 6C 75 64 6F 6D 74 73 65 54 20 73 73 65 6C 65 72 69 77 20 52 45 42 4D 41 2F 2F
cut:  0E 13 75 06 00 00 00 00 0D FD 11 20 65 64 6F 4D 20 53 20 21 6C 75 64 6F 6D 74 73 65 54 20 73 73 65 6C 65 72 69 77 20 52 45 42 4D 41
Nov 01 21:38:03 AMB 57 00 00 44 SND-NR Records: 2
--
CI Detail:	72 (EN 13757-3 Application Layer with long Transport Layer, SND-NR)
header:		long header
has errors:	False
access:		No access
config word:	05 30
mode:		5 (AES encryption with CBC; IV is not zero)
iv:		A2 05 44 00 00 57 0C 37 A3 A3 A3 A3 A3 A3 A3 A3
key:		CA FE BA BE 12 34 56 78 9A BC DE F0 CA FE BA BE
--
DIFs:	0E (Instantaneous value, 12 digit BCD)
VIFs:	13 (Volume l)
Value:	00 00 00 00 06 75
--
DIFs:	0D (Instantaneous value, variable length)
VIFs:	FD 11 (Second extension of VIF-codes)
Value:	41 4D 42 45 52 20 77 69 72 65 6C 65 73 73 20 54 65 73 74 6D 6F 64 75 6C 21 20 53 20 4D 6F 64 65
--
```

```
