# python-tiny-http-server

[![PyPi version](https://img.shields.io/pypi/v/tiny-http-server.svg)](https://pypi.python.org/pypi/tiny-http-server/)
[![Python compatibility](https://img.shields.io/pypi/pyversions/tiny-http-server.svg)](https://pypi.python.org/pypi/tiny-http-server/)
[![Downloads](https://static.pepy.tech/personalized-badge/tiny-http-server?period=week&units=none&left_color=blue&right_color=yellow&left_text=Downloads/week)](https://pepy.tech/project/tiny-http-server)
[![PyPI - Downloads](https://img.shields.io/pypi/dm/tiny-http-server)](https://pypistats.org/packages/tiny-http-server)
[![License](https://img.shields.io/github/license/johann-petrak/python-tiny-http-server.svg)](LICENSE)



A simple ad-hoc HTTP server for serving static pages,
similar to `python -m http.server`.

This supports:
* Basic authentication, for one or more user:password pairs, which can be specified from the command line and/or be read in from a file.
* Support for HTTPS using a cert and key file
* Support to run as CGI server, but without basic auth / HTTPS for now
* Support for optionally uploading files, with or without the ability to override existing files

## Installation

`pip install -U tiny-http-server` 

## Usage

```
usage: tiny-http-server [-h] [--cgi] [--bind ADDRESS] [--directory DIRECTORY]
                        [--port PORT] [--authfile AUTHFILE]
                        [--auth USERNAME:PASSWORD] [--cert CERT] [--key KEY]

Tiny HTTP server with optional basic authentication and https support.

optional arguments:
  -h, --help            show this help message and exit
  --cgi                 Run as CGI Server
  --bind ADDRESS, -b ADDRESS
                        Specify alternate bind address [default: 127.0.0.1]
  --directory DIRECTORY, -d DIRECTORY
                        Specify alternative directory [default: current
                        directory]
  --port PORT           Specify alternate port [default: 8000]
  --authfile AUTHFILE, -f AUTHFILE
                        If specified, a file with lines username:password
  --auth USERNAME:PASSWORD, -a USERNAME:PASSWORD
                        Add username:password to accepted authentication
  --cert CERT, -c CERT  If specified, the cert-file to use, enables https
  --key KEY, -k KEY     Key file, needed if --cert is specified
  --enable-upload       If specified, allows file uploads
  --enable-override     If specified and --enable-upload, allows to override existing files
  --no-force-auth       If specified, do not force authentication after server
                        restart.
  --debug               If specified output some debugging information
```

Details:

* `--no-force-auth`: the default behaviour when using basic auth is that 
    after restarting the server, authentication is always enforced before the 
    first response. If this parameter is specified, the server will accept
    a connection if the browser provides the basich auth credentials from the
    previous server session.

Notes:

* CAUTION: do not use this program if security, safety or stability are important, this is just a very simply tiny 
  program for the convenience of providing a quick ad-hoc server to trusted users. 
* specifying the user/password on the command line is insecure if other users are on the same system. The `--authfile` option or use of environment variables is a better choice in that case.
* If `--enable-upload` is specified, all directory listing pages allow to upload files into the shown directory. 
  Replacing existing files is only allowed if `--enable-override` is specified in addition.
* CAUTION: `--enable-upload` may be dangerous, use with caution!
* the program uses a sinlge process and no threading, so if several clients use the server, one may have
  to wait for all others to complete or may get rejected.
* Uploading large files will load the whole file into memory which can completely bog down the machine this
  program runs on. Do not use the upload options if this could cause problems or if users may abuse this. 

## Using Basic Authentication

Whenever at least one user/password pair is added through 
either the `--auth` option or as line in the file specified
via `--authfile`, basic authentication is enabled. 
This can be combined with HTTPs (see below).

## Using HTTPS

This is experimental. It requires a cert and key file. 
This gets enabled whenever the `--cert` option is specified.

For testing this can be created for `localhost` using the command:
```bash
openssl req -x509 -out localhost.crt -keyout localhost.key -newkey rsa:2048 -nodes -sha256 -subj '/CN=localhost' -extensions EXT -config <( printf "[dn]\nCN=localhost\n[req]\ndistinguished_name = dn\n[EXT]\nsubjectAltName=DNS:localhost\nkeyUsage=digitalSignature\nextendedKeyUsage=serverAuth")
```

## Kudos

This software has been inspired and uses adapted code from the following sources:

* https://github.com/Densaugeo/uploadserver
* https://gist.github.com/lionelyoung/8cad668d4d30fa392842fa08d50d2bc6
* https://gist.github.com/fxsjy/5465353
* https://github.com/goya191/SimpleAuthServerSSL.py
* https://stackoverflow.com/questions/30109449/what-does-sslerror-ssl-pem-lib-ssl-c2532-mean-using-the-python-ssl-libr
* https://github.com/tianhuil/SimpleHTTPAuthServer
