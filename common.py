from Crypto.PublicKey import RSA
from hashlib import sha1
from requests import get
import dnslib
import socket
import os
import struct

class certloader:

    def __init__(self, cert_data):
        self.cert_data = cert_data

    # TODO: need to support more formats
    # Return RSA key files
    def importKey(self):
        try:
            return RSA.importKey(self.cert_data)
        except Exception as err:
            print ("Fatal error while loading certificate.")
            print (err)
            quit()

    def getSHA1(self):
        try:
            return sha1(self.cert_data.encode("UTF-8")).hexdigest()
        except Exception as err:
            print ("Cannot get SHA1 of the certificate.")
            print (err)
            quit()


def answer(dnsq, addr):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    answer = dnsq.reply()
    answer.header = dnslib.DNSHeader(id=dnsq.header.id,
                                     aa=1, qr=1, ra=1, rcode=3)
    answer.add_auth(
        dnslib.RR(
            "testing.arkc.org",
            dnslib.QTYPE.SOA,
            ttl=3600,
            rdata=dnslib.SOA(
                "freedom.arkc.org",
                "webmaster." + "freedom.arkc.org",
                (20150101, 3600, 3600, 3600, 3600)
            )
        )
    )
    answer.set_header_qa()
    packet = answer.pack()
    s.sendto(packet, addr)

def get_ip(debug_ip=None):  # TODO: Get local network interfaces ip
    if debug_ip:
        ip = debug_ip
    else:
        try:
            os.environ['NO_PROXY'] = 'api.ipify.org'
            ip = get('https://api.ipify.org').text
        except Exception as err:
            ip = "127.0.0.1"
    return struct.unpack("!L", socket.inet_aton(ip))[0]