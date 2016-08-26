#!/usr/bin/python3
import socketserver as ss
import datetime
from binascii import unhexlify
from ecdsa import VerifyingKey
import hashlib
import signal

PORT = 6002

PUBLIC_KEY = """
-----BEGIN PUBLIC KEY-----
MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEgTxPtDMGS8oOT3h6fLvYyUGq/BWeKiCB
sQPyD0+2vybIT/Xdl6hOqQd74zr4U2dkj+2q6+vwQ4DCB1X7HsFZ5JczfkO7HCdY
I7sGDvd9eUias/xPdSIL3gMbs26b0Ww0
-----END PUBLIC KEY-----
"""
vk = VerifyingKey.from_pem(PUBLIC_KEY.strip())

print(vk.to_string())

help_string = b"""
COMMANDS:
* read [file]
 - prints contents of file
* time
 - prints the current time
* help
 - prints this message
"""

class RequestHandler(ss.StreamRequestHandler):
    def run_command(self, msg):
        cmd, *args = msg.split()
        if cmd == b"read":
            try:
                with open(args[0], "rb") as f:
                    self.wfile.write(f.read())
            except:
                self.wfile.write("\n")
        elif cmd == b"time":
            self.wfile.write(datetime.datetime.strftime(datetime.datetime.now(), "%Y-%m-%d %H:%M:%S").encode("utf8"))
        elif cmd == b"help":
            self.wfile.write(help_string)
        else:
            self.wfile.write(b"bad command\n")
    
    def verify(self, msg, sig):
        try:
            return vk.verify(unhexlify(sig), msg, hashfunc=hashlib.sha256)
        except:
            return False

    def handle(self):
        signal.alarm(5)
        d = self.rfile.readline().strip()
        try:
            msg, sig = d.split(b":")
        except ValueError as e:
            self.wfile.write(b"bad command\n")
            return
        if not self.verify(msg, sig):
            self.wfile.write(b"bad signature\n")
            return

        self.run_command(msg)


class TCPServer(ss.ForkingMixIn, ss.TCPServer):
    pass


ss.TCPServer.allow_reuse_address = True
server = TCPServer(("0.0.0.0", PORT), RequestHandler)

print("Server listening on port %d" % PORT)
server.serve_forever()
