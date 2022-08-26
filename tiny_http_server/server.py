#!/usr/bin/env python

# Simple ad-hoc http server for serving static pages in a directory, optionally 
# using basic auth for authentication.
# 
# Basic Auth is enabled if one or both of the --authfile or --auth options are provided.

# Create self-signed certificate for testing on localhost: see https://letsencrypt.org/docs/certificates-for-localhost/
# openssl req -x509 -out localhost.crt -keyout localhost.key -newkey rsa:2048 -nodes -sha256 -subj '/CN=localhost' -extensions EXT -config <( printf "[dn]\nCN=localhost\n[req]\ndistinguished_name = dn\n[EXT]\nsubjectAltName=DNS:localhost\nkeyUsage=digitalSignature\nextendedKeyUsage=serverAuth")

import sys
import os
import io
import pathlib
import signal
from typing import Any
from logging import getLogger, basicConfig, DEBUG, INFO
from functools import partial
import html
import cgi
import urllib.parse
from http import HTTPStatus
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer, CGIHTTPRequestHandler
import base64
import ssl
import socketserver
import contextlib
import socket

DEFAULT_EXTENSIONS_UPDATES = {
    ".md": "text/plain",
}

UPLOAD_SNIPPET = """
<h2>File Upload</h2>
<form action="" method="POST" enctype="multipart/form-data">
<input name="files" type="file" multiple /> <input type="submit" />
</form>
<div id="task"></div>
<div id="status"></div>
<script>
document.getElementsByTagName('form')[0].addEventListener('submit', e => {
  e.preventDefault()
  const formData = new FormData(e.target)
  const filenames = formData.getAll('files').map(v => v.name).join(', ')
  const request = new XMLHttpRequest()
  request.open(e.target.method, e.target.action)
  request.timeout = 3600000  
  request.onreadystatechange = () => {
    if(request.readyState === XMLHttpRequest.DONE) {
      let message = `${request.status}: ${request.statusText}`
      if(request.status === 204) message = 'Success'
      if(request.status === 0) message = 'Connection failed'
      document.getElementById('status').textContent = message
    }
  }
  request.upload.onprogress = e => {
    document.getElementById("status").textContent = `${Math.round(100*e.loaded/e.total)}%`
  }
  request.send(formData)
  document.getElementById('task').textContent = `Uploading ${filenames}:`
  document.getElementById('status').textContent = '0%'
})
</script>
"""

class MySimpleHTTPRequestHandler(SimpleHTTPRequestHandler):

    def __init__(self, *args, **kwargs):
        self.logger = kwargs.pop("logger")
        self.enable_upload = kwargs.pop("enable_upload")
        self.enable_override = kwargs.pop("enable_override")
        super().__init__(*args, **kwargs)

    def log_message(self, format: str, *args: Any) -> None:
        if len(args) == 0:
            self.logger.info(format)
        else:
            self.logger.info(format % args)

    def list_directory(self, path):
        # NOTE: this gets called with the resolved file system path, the URL path is in self.path
        try:
            list = os.listdir(path)
        except OSError:
            self.send_error(HTTPStatus.NOT_FOUND, "Cannot list directory")
            return None
        list.sort(key=lambda a: a.lower())
        r = []
        try:
            displaypath = urllib.parse.unquote(self.path,
                                               errors='surrogatepass')
            self.logger.info(f"list_directory displaypath/surrogatepass {displaypath}")
        except UnicodeDecodeError:
            displaypath = urllib.parse.unquote(path)
            self.logger.info(f"list_directory displaypath/default {displaypath}")
        displaypath = html.escape(displaypath, quote=False)
        self.logger.debug(f"list_directory displaypath/escape {displaypath}")
        enc = sys.getfilesystemencoding()
        title = 'Directory listing for %s' % displaypath
        r.append('<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01//EN" '
                 '"http://www.w3.org/TR/html4/strict.dtd">')
        r.append('<html>\n<head>')
        r.append('<meta http-equiv="Content-Type" '
                 'content="text/html; charset=%s">' % enc)
        r.append('<title>%s</title>\n</head>' % title)
        r.append('<body>\n')
        if self.enable_upload:
            r.append(UPLOAD_SNIPPET)
        r.append('\n<h1>%s</h1>' % title)
        r.append('<hr>\n<ul>')
        for name in list:
            fullname = os.path.join(path, name)
            displayname = linkname = name
            # Append / for directories or @ for symbolic links
            if os.path.isdir(fullname):
                displayname = name + "/"
                linkname = name + "/"
            if os.path.islink(fullname):
                displayname = name + "@"
                # Note: a link to a directory displays with @ and links with /
            r.append('<li><a href="%s">%s</a></li>'
                     % (urllib.parse.quote(linkname,
                                           errors='surrogatepass'),
                        html.escape(displayname, quote=False)))
        r.append('</ul>\n<hr>\n</body>\n</html>\n')
        encoded = '\n'.join(r).encode(enc, 'surrogateescape')
        f = io.BytesIO()
        f.write(encoded)
        f.seek(0)
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-type", "text/html; charset=%s" % enc)
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        return f

    def receive_upload(self, path):
        # NOTE: this code has been copied/adapted from https://github.com/Densaugeo/uploadserver
        result = (HTTPStatus.INTERNAL_SERVER_ERROR, 'Server error')
        form = cgi.FieldStorage(fp=self.rfile,
                                headers=self.headers, environ={'REQUEST_METHOD': 'POST'})
        if 'files' not in form:
            return (HTTPStatus.BAD_REQUEST, 'Field "files" not found')
        fields = form['files']
        if not isinstance(fields, list):
            fields = [fields]
        for field in fields:
            if field.file and field.filename:
                filename = pathlib.Path(field.filename).name
                tofile = pathlib.Path(path) / filename
                if tofile.exists() and not self.enable_override:
                    self.logger.info(f"Upload of {filename} to {tofile} not allowed: file exists")
                    result = (HTTPStatus.BAD_REQUEST, f"File {filename} already exists and override disabled")
                    break
                with open(pathlib.Path(path) / filename, 'wb') as f:
                    f.write(field.file.read())
                    self.log_message('Upload of "{}" accepted'.format(filename))
                    result = (HTTPStatus.NO_CONTENT, None)
        return result

    def do_POST(self):
        # NOTE: this code has been copied/adapted from https://github.com/Densaugeo/uploadserver
        if not self.enable_upload:
            self.send_error(HTTPStatus.NOT_FOUND, 'Upload/POST not allowed')
        # check if the request comes from a directory path
        path = self.translate_path(self.path)
        if not os.path.isdir(path):
            self.send_error(HTTPStatus.NOT_FOUND, 'Upload/POST not allowed: not a directory')
        result = self.receive_upload(path)
        if result[0] < HTTPStatus.BAD_REQUEST:
            self.send_response(result[0], result[1])
            self.end_headers()
        else:
            self.send_error(result[0], result[1])


class AuthHTTPRequestHandler(MySimpleHTTPRequestHandler):
    """ Main class to present webpages and authentication. """

    def __init__(self, *args, **kwargs):
        self.users = kwargs.pop("users")
        self.global_var = kwargs.pop("global_var")
        super().__init__(*args, **kwargs)
        self.extensions_map.update(DEFAULT_EXTENSIONS_UPDATES)
        if self.global_var["first"]:
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
                self.logger.debug(f"Request path: {self.path}")
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
    parser.add_argument("--enable-upload", action="store_true",
                        help="If specified, allows file uploads")
    parser.add_argument("--enable-override", action="store_true",
                        help="If specified and --enable-upload, allows to override existing files")
    parser.add_argument("--debug", action="store_true",
                        help="If specified output some debugging information")
    args = parser.parse_args()

    basicConfig(level=DEBUG if args.debug else INFO)
    logger = getLogger("tiny-http-server")
    logger.debug(f"Logging mode DEBUG enabled")
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

    def mysignalhandler(sig, frame):
        logger.info(f"Program interrupted by signal {sig}, terminating with exit code 1 ...")
        sys.exit(1)

    # signal.signal(signal.SIGINT, mysignalhandler)
    signal.signal(signal.SIGHUP, mysignalhandler)

    if args.cgi:
        logger.debug("Using CGIHTTPRequestHandler")
        handler_class = CGIHTTPRequestHandler
    elif len(allusers) == 0:
        logger.debug("Using SimpleHTTPRequestHandler")
        handler_class = partial(MySimpleHTTPRequestHandler,
                                logger=logger,
                                enable_upload=args.enable_upload,
                                enable_override=args.enable_override,
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
            enable_upload=args.enable_upload,
            enable_override=args.enable_override,
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
                logger.info("Keyboard interrupt / INT signal received, exiting.")
                sys.exit(0)


if __name__ == "__main__":
    main()
