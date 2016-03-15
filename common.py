from Crypto.PublicKey import RSA
from hashlib import sha1
import dnslib
import socket

import sqlite3


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


class certstorage:
    """ A sqlite client to check if fetch certificates, authenticate, and buffer"""

    def __init__(self, db_buffer_dict={}, sqlite_path=None):
        #certs[sha1(remote_cert_txt).hexdigest()] =[remote_cert, client[1]]
        self.db_buffer_dict = db_buffer_dict
        if sqlite_path is not None:
            self.db_conn = sqlite3.connect(sqlite_path)
            self.db_cursor = self.db_conn.cursor()

    def query(self, sha1_value):
        # Currently the DB is for appending only
        if sha1_value not in self.db_buffer_dict:
            t = (sha1_value,)
            self.db_cursor.execute('SELECT * FROM certs WHERE pub_sha1=?', t)
            rec = self.db_cursor.fetchone()
            if len(rec) != 1:
                return None
            else:
                key = RSA.importKey(rec[0][2])
                self.db_buffer_dict[sha1_value] = [key, rec[1]]
        return self.db_buffer_dict[sha1_value]

    def close(self):
        try:
            self.db_conn.close()
        except:
            pass


def int2base(num, base=36, numerals="0123456789abcdefghijklmnopqrstuvwxyz"):
    if num == 0:
        return "0"

    if num < 0:
        return '-' + int2base((-1) * num, base, numerals)

    if not 2 <= base <= len(numerals):
        raise ValueError('Base must be between 2-%d' % len(numerals))

    left_digits = num // base
    if left_digits == 0:
        return numerals[num % base]
    else:
        return int2base(left_digits, base, numerals) + numerals[num % base]
