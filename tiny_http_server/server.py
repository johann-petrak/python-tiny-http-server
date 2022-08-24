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
import sys
from logging import getLogger, basicConfig, DEBUG, INFO
from functools import partial
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer, CGIHTTPRequestHandler
import base64
import os
import ssl
import socketserver
import contextlib
import socket

DEFAULT_EXTENSIONS_UPDATES = {
    ".md": "text/plain",
}
class AuthHTTPRequestHandler(SimpleHTTPRequestHandler):
    """ Main class to present webpages and authentication. """

    def __init__(self, *args, **kwargs):
        self.users = kwargs.pop("users")
        self.logger = kwargs.pop("logger")
        self.global_var = kwargs.pop("global_var")
        self.logger.debug(f"RUNNING INIT!!!! self={self}")
        super().__init__(*args, **kwargs)
        self.extensions_map.update(DEFAULT_EXTENSIONS_UPDATES)
        self.logger.debug(f"extensions map is now: {self.extensions_map}")

    def do_HEAD(self):
        self.logger.debug("do_HEAD")
        self.send_response(200)
        self.end_headers()

    def do_AUTHHEAD(self):
        self.logger.debug("do_AUTHHEAD")
        self.send_response(401)
        self.send_header("WWW-Authenticate", 'Basic realm="Test"')
        self.end_headers()

    def do_GET(self):
        """ Present frontpage with user authentication. """
        ahdr = self.headers.get("Authorization")
        self.logger.debug(f"do_GET: first={self.global_var}, ahdr={ahdr},\nheaders={self.headers}")
        if self.global_var["first"] or self.headers.get("Authorization") == None:
            if self.global_var["first"]:
                self.global_var["first"] = False
                self.logger.debug(f"First time, setting to false")
            else:
                self.logger.debug("do_GET: no authorization")
            self.do_AUTHHEAD()
            self.logger.debug("After do_AUTHHEAD")
        elif self.headers.get("Authorization") is not None:
            auth = self.headers.get("Authorization")
            self.logger.debug(f"Got auth header: >>{auth}<<")
            if not auth.startswith("Basic "):
                self.do_AUTHHEAD()
                return
            auth = auth[6:]
            user, passwd = base64.b64decode(auth).decode("UTF-8").split(":")
            if self.users.get(user) == passwd:
                self.logger.debug("do_GET: correct Basic auth")
                SimpleHTTPRequestHandler.do_GET(self)
            else:
                self.logger.debug("do_GET: WRONG Basic auth")
                self.do_AUTHHEAD()
        else:
            self.logger.debug("do_GET: other stuff, this should never happen")
            raise Exception("This should not happen ...")


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
    parser.add_argument("--debug", action="store_true",
                        help="If specified output some debugging information")
    args = parser.parse_args()

    basicConfig(level=DEBUG if args.debug else INFO)
    logger = getLogger("tiny-http-server")
    allusers = {}
    if args.auth:
        u, p = args.auth.split(":")
        allusers[u] = p
    if args.authfile:
        with open(args.authfile, "rt") as infp:
            for line in infp:
                line = line.rstrip("\n\r")
                lineorig = line
                line = line.strip()
                if not line:
                    continue
                if line.startswith("#"):
                    continue
                if ":" in line:
                    u, p = line.split(":")
                else:
                    raise Exception(f"Odd line in {args.authfile}: >>{lineorig}<<")
                if u in allusers:
                    raise Exception(f"Duplicate entry in {args.authfile} for user {u}")
                allusers[u] = p

    class DualStackServer(ThreadingHTTPServer):
        def server_bind(self):
            # suppress exception when protocol is IPv4
            with contextlib.suppress(Exception):
                self.socket.setsockopt(
                    socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
            return super().server_bind()

    if args.cgi:
        logger.debug("Using CGIHTTPRequestHandler")
        handler_class = CGIHTTPRequestHandler
    elif len(allusers) == 0:
        logger.debug("Using SimpleHTTPRequestHandler")
        handler_class = partial(SimpleHTTPRequestHandler,
                                directory=args.directory)
    else:
        logger.debug("Using AuthHTTPRequestHandler")
        # NOTE: the handler_class gets re-allocated multiple times, so to find the very first
        # request after this script gets started, we use a hash as a global variable
        GLOBAL = dict(first=True)
        handler_class = partial(
            AuthHTTPRequestHandler,
            users=allusers,
            directory=args.directory,
            logger=logger,
            global_var=GLOBAL,
        )
    if args.cert:
        logger.debug("Wrapping handler for HTTPS")
        httpd = socketserver.TCPServer(("", args.port), handler_class)
        httpd.socket = ssl.wrap_socket(httpd.socket, certfile=args.cert, keyfile=args.key, server_side=True)
        sa = httpd.socket.getsockname()
        logger.info(f"Serving HTTPS on {sa[0]}, port {sa[1]} ...")
        httpd.serve_forever()
    else:
        infos = socket.getaddrinfo(args.bind, args.port, type=socket.SOCK_STREAM, flags=socket.AI_PASSIVE)
        family, type, proto, canonname, sockaddr = next(iter(infos))
        DualStackServer.address_family = family
        handler_class.protocol_version = "HTTP/1.0"
        with DualStackServer(sockaddr, handler_class) as httpd:
            host, port = httpd.socket.getsockname()[:2]
            url_host = f'[{host}]' if ':' in host else host
            logger.info(f"Serving HTTP on {host}, port {port} (http://{url_host}:{port}/) ...")
            try:
                httpd.serve_forever()
            except KeyboardInterrupt:
                logger.info("\nKeyboard interrupt received, exiting.")
                sys.exit(0)


if __name__ == "__main__":
    main()
