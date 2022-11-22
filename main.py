#!/usr/bin/python
from __future__ import print_function
from pyrad import dictionary, packet, server
import six
import logging
import pymysql
#import poll
from pyrad.tools import *
from pyrad.packet import AuthPacket
import bcrypt
import hashlib

md5_constructor = hashlib.md5

logging.basicConfig(filename="pyrad.log", level="DEBUG",
                    format="%(asctime)s [%(levelname)-8s] %(message)s")
#poll.install()
def dump(obj):
   for attr in dir(obj):
       if hasattr( obj, attr ):
           print( "obj.%s = %s" % (attr, getattr(obj, attr)))

class FakeServer(server.Server):

    def HandleAuthPacket(self, pkt):
        pwd = pkt.PwDecrypt(pkt['User-Password'][0]).encode()
        uname = pkt['User-Name'][0]
        try: # trying to connect to the mysql database
            connection = pymysql.connect(
                host="localhost",
                port=3306,
                user="radius",
                password="radius2022",
                database="moodle",
                cursorclass=pymysql.cursors.DictCursor
            )
            #print("Connection success")
            try: # trying to make SQL request and execute it
                with connection.cursor() as cursor:
                    sql = ("SELECT * FROM `mdl_user` WHERE `username`=%s")
                    cursor.execute(sql, (uname))
                    result = cursor.fetchone()
                    if bcrypt.checkpw(pwd, result['password'].encode()):
                        # reply if password is OK
                        reply = self.CreateReplyPacket(pkt, **{
                            "Service-Type": "Framed-User",
                            "Framed-IP-Address": '192.168.0.1',
                            "Framed-IPv6-Prefix": "fc66::1/64"
                        })

                        reply.code = packet.AccessAccept
                    else:
                        # reply if password is bad
                        reply = self.CreateReplyPacket(pkt)
                        reply.code = packet.AccessReject
            finally:
                connection.close()

        except Exception as ex:
            print(ex)

        self.SendReplyPacket(pkt.fd, reply)

    def HandleAcctPacket(self, pkt):

        # print("Received an accounting request")
        # print("Attributes: ")
        # for attr in pkt.keys():
        #     print("%s: %s" % (attr, pkt[attr]))

        reply = self.CreateReplyPacket(pkt)
        self.SendReplyPacket(pkt.fd, reply)

    def HandleCoaPacket(self, pkt):

        # print("Received an coa request")
        # print("Attributes: ")
        # for attr in pkt.keys():
        #     print("%s: %s" % (attr, pkt[attr]))

        reply = self.CreateReplyPacket(pkt)
        self.SendReplyPacket(pkt.fd, reply)

    def HandleDisconnectPacket(self, pkt):

        # print("Received an disconnect request")
        # print("Attributes: ")
        # for attr in pkt.keys():
        #     print("%s: %s" % (attr, pkt[attr]))

        reply = self.CreateReplyPacket(pkt)
        # COA NAK
        reply.code = 45
        self.SendReplyPacket(pkt.fd, reply)

if __name__ == '__main__':

    # create server and read dictionary
    srv = FakeServer(dict=dictionary.Dictionary("dictionary"), coa_enabled=True)

    # add clients (address, secret, name)
    srv.hosts["0.0.0.0"] = server.RemoteHost("192.168.88.2", b'Kah3choteereethiejeimaeziecumi', "localhost")
    srv.BindToAddress("0.0.0.0")

    # start server
    srv.Run()
