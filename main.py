# -*- coding: utf8 -*-
import socket
import hashlib
import binascii
import pyotp
import argparse
import json
import logging
import dnslib
import string
from random import choice
from Crypto.PublicKey import RSA
from hashlib import sha1

from common import certloader, answer


class CorruptedReq:
    pass


class ServerInfo:

    def __init__(self, pub, addr):
        self.pub = pub
        self.addr = addr


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
    remote_ip = msg4.decode("ASCII") + '=' * (7 - len(msg4))
    h = hashlib.sha256()
    # Let's add the number_hex into the update string too, in client side and
    # transmit side
    h.update(
        (certs[client_sha1][1] + msg4 + msg5 + number_hex).encode("UTF-8"))
    assert msg2 == pyotp.TOTP(h.hexdigest()).now()
    main_pw = binascii.unhexlify(msg3)
    number = int(number_hex, 16)
    remote_port = int(port_hex, 16)
    if len(recentsalt) >= MAX_SALT_BUFFER:
        recentsalt.pop(0)
    recentsalt.append(msg5)
    returnvalue = [main_pw,
                   client_sha1,
                   number,
                   remote_port,
                   remote_ip]
    return returnvalue


def process_msg(*msg):
    global clientlist, serverlist
    main_pw, client_sha1, number, tcp_port, remote_ip = msg[
        0], msg[1], msg[2], msg[3], msg[4]
    salt = (''.join(choice(string.ascii_letters) for _ in range(16)))\
        .encode('ASCII')

    if client_sha1 in clientlist:
        server = clientlist[client_sha1]
    else:
        server = choice(serverlist.keys())
        clientlist[client_sha1] = server
    # Actually main_pw should be encrypted if you can
    main_pw_enc = serverlist[server].pub.encrypt(
        main_pw, None)[0]
    required_hex = "%X" % min((number), 255)
    unsigned_str = salt + str(number) + remote_ip + str(tcp_port)
    sign_hex = '%X' % localpri.sign(unsigned_str.encode("UTF-8"), None)[0]
    remote_port_hex = '%X' % tcp_port
    if len(required_hex) == 1:
        required_hex = '0' + required_hex
    if len(sign_hex) == 510:
        sign_hex = '0' + sign_hex
    remote_port_hex = '0' * (4 - len(remote_port_hex)) + remote_port_hex
    return salt +\
        str(required_hex) +\
        str(remote_port_hex) +\
        str(client_sha1) +\
        str(sign_hex) +\
        main_pw_enc +\
        str(remote_ip), serverlist[server].addr
def tcp_punching(client,server):
    punching_addr=choice(punching_servers)
    while 1:
        msg,addr=s.recvfrom(512)
        req=dnslib.DNSRecord.parse(msg)
        if req.q.qtype==1:
            answer = req.reply()
            answer.header = dnslib.DNSHeader(id=req.header.id,
                                     aa=1, qr=1, ra=1, rcode=3)
            answer.add_auth(
                dnslib.RR(
                    "testing.arkc.org",
                    dnslib.QTYPE.SOA,
                    ttl=3600,
                    rdata=dnslib.SOA(
                        punching_addr[0],
                        "webmaster." + "freedom.arkc.org",
                        (20150101, 3600, 3600, 3600, 3600)
                    )
                )
            )
            answer.set_header_qa()
            packet = answer.pack()
            s.sendto(packet, addr)
        if req.q.qtype==16:
            answer = req.reply()
            answer.header = dnslib.DNSHeader(id=req.header.id,
                                     aa=1, qr=1, ra=1, rcode=3)
            answer.add_auth(
                dnslib.RR(
                    "testing.arkc.org",
                    dnslib.QTYPE.SOA,
                    ttl=3600,
                    rdata=dnslib.SOA(
                        "freedom.arkc.org",
                        "webmaster." + "freedom.arkc.org",
                        (20150101, punching_addr[1], 3600, 3600, 3600)
                    )
                )
            )
            answer.set_header_qa()
            packet = answer.pack()
            s.sendto(packet, addr)
            s.sendto(punching_addr,server)
            break


if __name__ == "__main__":
    MAX_SALT_BUFFER = 255
    certs = dict()
    recentsalt = []
    serverlist = {}  # TODO: be initiated, with ServerInfo class
    clientlist = {}
    punching_servers=[]
    punching_client={}
    DEFAULT_REMOTE_PORT = 8000
    parser = argparse.ArgumentParser()
    parser.add_argument('-c', '--config', dest="config", default='config.json')
    parser.add_argument(
        "-v", dest="v", action="store_true", help="show detailed logs")
    args = parser.parse_args()

    try:
        data_file = open(args.config)
        data = json.load(data_file)
        data_file.close()
    except Exception as err:
        logging.error(
            "Fatal error while loading configuration file.\n" + str(err))
        quit()

    try:
        for client in data["clients"]:
            with open(client[0], "r") as f:
                remote_cert_txt = f.read()
                remote_cert = RSA.importKey(remote_cert_txt)
                certs[sha1(remote_cert_txt).hexdigest()] =\
                     [remote_cert, client[1]]
    except KeyError as e:
        logging.error(
            e.tostring() + "is not found in the config file. Quitting.")
        quit()
    except Exception as err:
        print ("Fatal error while loading clients' certificate.")
        print (err)
        quit()

    try:
        for server in data["servers"]:
            with open(server[2], "r") as f:
                server_cert_txt = f.read()
                remote_cert = RSA.importKey(server_cert_txt)
                serverlist[sha1(server_cert_txt).hexdigest()] = \
                    ServerInfo(remote_cert, (server[0], server[1]))
    except KeyError as e:
        logging.error(
            e.tostring() + "is not found in the config file. Quitting.")
        quit()
    except Exception as err:
        print ("Fatal error while loading servers' certificate.")
        print (err)
        quit()

    try:
        localpri_data = open(data["local_cert"], "r").read()
        localpri = certloader(localpri_data).importKey()
        if not localpri.has_private():
            print("Fatal error, no private key included in local certificate.")
    except KeyError as e:
        logging.error(
            e.tostring() + "is not found in the config file. Quitting.")
        quit()
    except Exception as err:
        print ("Fatal error while loading local certificate.")
        print (err)
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
            if len(query_data) < 7:
                raise CorruptedReq
            decrypted_msg = decrypt_udp_msg(
                query_data[0], query_data[1], query_data[2], query_data[3], query_data[4])

        except CorruptedReq:
            logging.info("Corrupted request")
        # except AssertionError:
        #    logging.error("authentication failed or corrupted request")
        # except Exception as err:
        #    logging.error("unknown error: " + str(err))

        processed_msg, randserver = process_msg(*decrypted_msg)
        if not query_data[5]:
            tcp_punching(addr,randserver)
        else:
            answer(req, addr)
            punching_servers.append(addr)
        s.sendto(processed_msg, randserver)
        # TODO: use logging to show logs about success and failures
