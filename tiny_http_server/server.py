#!/usr/bin/env python

# Simple ad-hoc http server for serving static pages in a directory, optionally 
# using basic auth for authentication.
# 
# Basic Auth is enabled if one or both of the --authfile or --auth options are provided.

# Create self-signed certificate for testing on localhost: see https://letsencrypt.org/docs/certificates-for-localhost/
# openssl req -x509 -out localhost.crt -keyout localhost.key -newkey rsa:2048 -nodes -sha256 -subj '/CN=localhost' -extensions EXT -config <( printf "[dn]\nCN=localhost\n[req]\ndistinguished_name = dn\n[EXT]\nsubjectAltName=DNS:localhost\nkeyUsage=digitalSignature\nextendedKeyUsage=serverAuth")


# Based on ideas from
# https://gist.github.com/lionelyoung/8cad668d4d30fa392842fa08d50d2bc6
# https://gist.github.com/fxsjy/5465353
# https://github.com/goya191/SimpleAuthServerSSL.py/blob/master/SimpleHttpsAuthServer.py

# check out https://stackoverflow.com/questions/30109449/what-does-sslerror-ssl-pem-lib-ssl-c2532-mean-using-the-python-ssl-libr
# !!https://github.com/tianhuil/SimpleHTTPAuthServer

# TODO: set auth header to None at first visit and also after some timeout:
# self.headers.replace_header('Authorization', None)

from functools import partial
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer, CGIHTTPRequestHandler
from http.server import test as server_test
import base64
import os
import ssl
import socketserver
import contextlib
import socket


class AuthHTTPRequestHandler(SimpleHTTPRequestHandler):
    """ Main class to present webpages and authentication. """

    def __init__(self, *args, **kwargs):
        self.users = kwargs.pop("users")
        super().__init__(*args, **kwargs)

    def do_HEAD(self):
        print("do_HEAD")
        self.send_response(200)
        self.send_header("Content-type", "text/html")
        self.end_headers()

    def do_AUTHHEAD(self):
        print("do_AUTHHEAD")
        self.send_response(401)
        self.send_header("WWW-Authenticate", 'Basic realm="Test"')
        self.send_header("Content-type", "text/html")
        self.end_headers()

    def do_GET(self):
        """ Present frontpage with user authentication. """
        print("do_GET", self.headers)
        if self.headers.get("Authorization") == None:
            print("do_GET: no authorization")
            self.do_NOTAUTH()
        elif self.headers.get("Authorization") is not None:
            auth = self.headers.get("Authorization")
            if not auth.startswith("Basic "):
                self.do_NOTAUTH()
                return
            auth = auth[6:]
            user, passwd = base64.b64decode(auth).decode("UTF-8").split(":")
            if self.users.get(user) == passwd:
                print("do_GET: correct Basic auth")
                SimpleHTTPRequestHandler.do_GET(self)
            else:
                self.do_NOTAUTH()
        else:
            print("do_GET: other stuff")
            self.do_NOTAUTH()

    def do_NOTAUTH(self):
        self.do_AUTHHEAD()
        self.wfile.write(self.headers.get("Authorization").encode())
        self.wfile.write(b"authentication problem")


def main():
    import argparse

    parser = argparse.ArgumentParser(
        description="Tiny HTTP server with optional basic authentication and https support.",
        epilog="See https://github.com/johann-petrak/python-tiny-http-server/blob/main/README.md"
    )
    parser.add_argument("--cgi", action="store_true", help="Run as CGI Server")
    parser.add_argument("--bind", "-b", metavar="ADDRESS", default="127.0.0.1",
                        help="Specify alternate bind address " "[default: 127.0.0.1]",
    )
    parser.add_argument("--directory", "-d", default=os.getcwd(),
                        help="Specify alternative directory " "[default: current directory]",
    )
    parser.add_argument("--port", default=8000, type=int,
                        help="Specify alternate port [default: 8000]",
    )
    parser.add_argument("--authfile", "-f",
                        help="If specified, a file with lines username:password")
    parser.add_argument("--auth", "-a", metavar="USERNAME:PASSWORD",
                        help="Add username:password to accepted authentication")
    parser.add_argument("--cert", "-c",
                        help="If specified, the cert-file to use, enables https")
    parser.add_argument("--key", "-k",
                        help="Key file, needed if --cert is specified")
    args = parser.parse_args()

    allusers = {}
    if args.auth:
        u, p = args.auth.split(":")
        allusers[u] = p
    if args.authfile:
        with open(args.authfile, "rt") as infp:
            for line in infp:
                line = line.rstrip("\n\r")
                u, p = line.split(":")
                allusers[u] = p

    class DualStackServer(ThreadingHTTPServer):
        def server_bind(self):
            # suppress exception when protocol is IPv4
            with contextlib.suppress(Exception):
                self.socket.setsockopt(
                    socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
            return super().server_bind()

    if args.cgi:
        handler_class = CGIHTTPRequestHandler
    elif len(allusers) == 0:
        handler_class = partial(SimpleHTTPRequestHandler,
                                directory=args.directory)
    else:
        handler_class = partial(
            AuthHTTPRequestHandler,
            users=allusers,
            directory=args.directory,
        )
    if args.cert:
        httpd = socketserver.TCPServer(("", args.port), handler_class)
        httpd.socket = ssl.wrap_socket (httpd.socket, certfile=args.cert, keyfile=args.key, server_side=True) 
        sa = httpd.socket.getsockname()
        print("Serving HTTP on", sa[0], "port", sa[1], "...")
        httpd.serve_forever()
    else:
        server_test(HandlerClass=handler_class, ServerClass=DualStackServer, port=args.port, bind=args.bind)


if __name__ == "__main__":
    main()
