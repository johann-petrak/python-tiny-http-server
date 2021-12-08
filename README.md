# python-tiny-http-server

[![PyPi version](https://img.shields.io/pypi/v/tiny-http-server.svg)](https://pypi.python.org/pypi/tiny-http-server/)
[![Python compatibility](https://img.shields.io/pypi/pyversions/tiny-http-server.svg)](https://pypi.python.org/pypi/tiny-http-server/)
[![Downloads](https://static.pepy.tech/personalized-badge/tiny-http-server?period=week&units=none&left_color=blue&right_color=yellow&left_text=Downloads/week)](https://pepy.tech/project/tiny-http-server)
[![PyPI - Downloads](https://img.shields.io/pypi/dm/tiny-http-server)](https://pypistats.org/packages/tiny-http-server)
[![License](https://img.shields.io/github/license/GateNLP/python-tiny-http-server.svg)](LICENSE)
[![Updates](https://pyup.io/repos/github/GateNLP/python-gatenlp/shield.svg)](https://pyup.io/repos/github/GateNLP/python-tiny-http-server/)
[![Python 3](https://pyup.io/repos/github/GateNLP/python-tiny-http-server/python-3-shield.svg)](https://pyup.io/repos/github/GateNLP/python-tiny-http-server/)


A simple ad-hoc HTTP server for serving static pages,
similar to `python -m http.server`.

This supports:
* Basic authentication, for one or more user:password pairs, which can be specified from the command line and/or be read in from a file.
* Support for HTTPS using a cert and key file
* Support to run as CGI server, but without basic auth / HTTPS for now

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
```
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

