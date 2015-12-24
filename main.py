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
import os
from random import  choice
from Crypto.PublicKey import RSA
from hashlib import sha1




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
        h.update((certs[client_sha1][1] + msg4 + msg5).encode("UTF-8")) # Let's add the number_hex into the update string too, in client side and transmit side
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
        logging.info("Data decrypted, processing")
        return returnvalue
        
def process_msg(*msg):
    global clientlist,serverlist
    main_pw, client_sha1, number, tcp_port, remote_ip=msg[0],msg[1],msg[2],msg[3],msg[4]
    salt = os.urandom(16)
    ##TODO: use hashlib base64, since python2.7 doesn't allow byte string
    ##Change Format into multiple queries
    
    ##Need to encrypt something from the client, needed to establish connections, like main_pw,  with the remote server's cert
    ##Maybe design by you
    
    main_pw_hex="%X" % main_pw #Actually main_pw should be encrypted if you can
    required_hex = "%X" % min((number), 255)
    sign_hex = '%X' % localpri.sign(salt, None)[0] # better to sign the required numbers as well
    #Both items below should be in signature
    remote_ip_hex= "%X" % remote_ip
    remote_port_hex = '%X' % tcp_port
    if len(required_hex) == 1:
        required_hex = '0' + required_hex
    if len(sign_hex) == 510:
        sign_hex = '0' + sign_hex
    remote_port_hex = '0' * (4 - len(remote_port_hex)) + remote_port_hex
    if client_sha1 in clientlist:
        server=clientlist[client_sha1]
    else:
        server=choice(serverlist)[0]
        clientlist[client_sha1]=server
    return  salt + \
            bytes(main_pw_hex,"UTF-8") + \
            bytes(client_sha1,"UTF-8") + \
            bytes(required_hex, "UTF-8") + \
            bytes(remote_ip_hex,"UTF-8") + \
            bytes(remote_port_hex, "UTF-8") + \
            bytes(localpub_sha1, "UTF-8") + \
            bytes(sign_hex, "UTF-8") + \
            remotecert.encrypt(mainstr, None)[0]
    return server
if __name__ == "__main__":
    MAX_SALT_BUFFER = 255
    certs = dict()
    recentsalt = []
    serverlist=[]
    clientlist={}
    mainstr=os.urandom(16)
    DEFAULT_REMOTE_HOST = "0.0.0.0"
    DEFAULT_REMOTE_PORT = 8000
    parser = argparse.ArgumentParser()
    parser.add_argument('-c', '--config', dest="config", default='config.json')
    parser.add_argument("-v", dest="v", action="store_true", help="show detailed logs")
    args = parser.parse_args()

    try:
        data_file = open(args.config)
        data = json.load(data_file)
        data_file.close()
    except Exception as err:
        logging.error("Fatal error while loading configuration file.\n" + str(err))
        quit()

    #There should be many remote servers, so put it in 
    # (ip, host, remote public key) tuples and load it altogether.
    
    try:
        remotecert_data = open(data["remote_cert"], "r").read()
        remotecert = certloader(remotecert_data).importKey()
    except KeyError as e:
        logging.error(e.tostring() + "is not found in the config file. Quitting.")
        quit()
    except Exception as err:
        print ("Fatal error while loading remote host certificate.")
        print (err)
        quit()

    try:
        localpri_data = open(data["local_cert"], "r").read()
        localpri = certloader(localpri_data).importKey()
        localpri_sha1 = certloader(localpri_data).getSHA1()
        if not localpri.has_private():
            print("Fatal error, no private key included in local certificate.")
    except KeyError as e:
        logging.error(e.tostring() + "is not found in the config file. Quitting.")
        quit()
    except Exception as err:
        print ("Fatal error while loading local certificate.")
        print (err)
        quit()

    try:
        localpub_data = open(data["local_cert_pub"], "r").read()
        localpub_sha1 = certloader(localpub_data).getSHA1()
    except KeyError as e:
        logging.error(e.tostring() + "is not found in the config file. Quitting.")
        quit()
    except Exception as err:
        print ("Fatal error while calculating SHA1 digest.")
        print (err)
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
        for server in data["servers"]:
            server_pub_data=open(server[2],"r")
            server_pub=certloader(server_pub_data).importKey()
            serverlist.append(((server[0],server[1]),server_pub))
    except Exception as e:
        print("Fatal error while loading servers")
        print(e)
        quit()

    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(('', 53))
    if args.v:
        logging.basicConfig(level=logging.INFO)
    while 1:
        msg, addr = s.recvfrom(2048)
        if msg:
            logging.info("Received request from (%s, %d)" % (addr[0], addr[1]))
        try:
            req = dnslib.DNSRecord.parse(msg)
            reqdomain = str(req.q.qname)
            query_data = reqdomain.split('.')
            decrypted_msg=decrypt_udp_msg(query_data[0], query_data[1], query_data[2], query_data[3], query_data[4])
        except Exception as err:
            logging.info("Corrupted request") ##TODO: distinguish all kinds of errors, e.g. key error. What if decrypted_msg is not generated by error?
        processed_msg,randserver=process_msg(*decrypted_msg)
        s.sendto(processed_msg,randserver)
        # TODO: use logging to show logs about success and failures
