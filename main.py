# -*- coding: utf8 -*-
import socket
import hashlib
import binascii
import ipaddress
import pyotp
import argparse
import json
import logging
import dnslib
from Crypto.PublicKey import RSA
from hashlib import sha1

MAX_SALT_BUFFER = 255
certs = dict()
recentsalt = []
DEFAULT_REMOTE_HOST = "0.0.0.0"
DEFAULT_REMOTE_PORT = 8000

def decode(data):
    msg = ''
    tipo = (ord(data[2]) >> 3) & 15  
    if tipo == 0:                   
      ini = 12
      lon = ord(data[ini])
      while lon != 0:
        msg += data[ini + 1:ini + lon + 1] + '.'
        ini += lon + 1
        lon = ord(data[ini])
    return msg

def decrypt_udp_msg(msg1, msg2, msg3, msg4, msg5):
        """Return (main_pw, client_sha1, number).

            The encrypted message should be
            (required_connection_number (HEX, 2 bytes) +
            used_remote_listening_port (HEX, 4 bytes) +
            sha1(cert_pub) ,
            pyotp.TOTP(time) , ## TODO: client identity must be checked
            main_pw,
            ip_in_number_form,
            salt
            Total length is 2 + 4 + 40 = 46, 16, 16, ?, 16
        """
        global recentsalt, certs, MAX_SALT_BUFFER
        assert len(msg1) == 46

        if msg5 in recentsalt:
            return (None, None, None, None, None)

        number_hex, port_hex, client_sha1 = msg1[:2], msg1[2:6], msg1[6:46]
        remote_ip = str(ipaddress.ip_address(int(msg4)))
        h = hashlib.sha256()
        h.update((certs[client_sha1][1] + msg4 + msg5).encode("UTF-8"))
        assert msg2 == pyotp.TOTP(h.hexdigest()).now()
        main_pw = binascii.unhexlify(msg3)
        number = int(number_hex, 16)
        remote_port = int(port_hex, 16)
        if len(recentsalt) >= MAX_SALT_BUFFER:
            recentsalt.pop(0)
        recentsalt.append(msg5)
        returnvalue=[main_pw,
                client_sha1,
                number,
                remote_port,
                remote_ip]
        return returnvalue
        
def process_msg(*msg):
    print(msg)
    #TODO: Assume the udptransmit server can load its own private and public key. Adapt the code in v0.1.1 to send a packet based on credentials of this server instead of the client. 
    pass

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('-c', '--config', dest="config", default='config.json')
    args = parser.parse_args()

    try:
        data_file = open(args.config)
        data = json.load(data_file)
        data_file.close()
    except Exception as err:
        logging.error("Fatal error while loading configuration file.\n" + str(err))
        quit()


    try:
        for client in data["clients"]:
            with open(client[0], "r") as f:
                remote_cert_txt = f.read()
                remote_cert = RSA.importKey(remote_cert_txt)
                certs[sha1(remote_cert_txt.encode("UTF-8")).hexdigest()] = [remote_cert, client[1]]
    except Exception as err:
        print ("Fatal error while loading client certificate.")
        print (err)
        quit()

    try:
        addr = (data['remote_host'], data['remote_port'])
    except Exception as err:
        print ('Fatal error while loading server address!')
        print (err)
        quit()
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(('', 53))
    while 1:
        msg, addr = s.recvfrom(2048)
        req = dnslib.DNSRecord.parse(msg)
        reqdomain = str(req.q.qname)
        query_data = reqdomain.split('.')
        s.sendto(process_msg(decrypt_udp_msg(query_data[0], query_data[1], query_data[2], query_data[3], query_data[4]), addr))
        # TODO: use logging to show logs about success and failures
