from Crypto.PublicKey import RSA
from hashlib import sha1
import dnslib
import socket


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


def answer(dnsq, addr,reply):
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
                str(reply)
            )
        )
    )
    answer.set_header_qa()
    packet = answer.pack()
    s.sendto(packet, addr)
