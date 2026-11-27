# SPDX-License-Identifier: AGPL-3.0-or-later
"""Opt-in HTTPS transport; no credential discovery, logging, redirects or retries."""
import json
import ssl
from urllib.parse import urlsplit
from urllib.request import Request, build_opener, HTTPSHandler, HTTPRedirectHandler, ProxyHandler
from urllib.error import HTTPError
from state import Conflict


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class Transport:
    def __init__(self, origin, authorization, *, cafile=None, timeout=15, max_bytes=4*1024*1024):
        url = urlsplit(origin)
        if (url.scheme != 'https' or not url.hostname or url.username or url.password or url.path not in ('','/')
                or url.query or url.fragment or not authorization or '\r' in authorization or '\n' in authorization):
            raise ValueError('explicit HTTPS origin and authorization required')
        if not 1 <= timeout <= 60 or not 1024 <= max_bytes <= 16*1024*1024:
            raise ValueError('invalid transport budget')
        self.origin, self.authorization = origin.rstrip('/'), authorization
        self.timeout, self.max_bytes = timeout, max_bytes
        self.opener = build_opener(ProxyHandler({}), NoRedirect(), HTTPSHandler(context=ssl.create_default_context(cafile=cafile)))

    def request(self, method, path, body=None):
        if method not in ('GET','POST','PUT','DELETE') or not path.startswith('/') or path.startswith('//') or any(c in path for c in ('\r','\n','#','\\')):
            raise ValueError('invalid request')
        data = None if body is None else json.dumps(body,allow_nan=False).encode()
        if data is not None and len(data)>self.max_bytes:
            raise ValueError('request budget exceeded')
        request = Request(self.origin+path, data=data, method=method,
                          headers={'Authorization':self.authorization,'Content-Type':'application/json','Accept':'application/json'})
        try:
            with self.opener.open(request,timeout=self.timeout) as response:
                raw=response.read(self.max_bytes+1)
        except HTTPError as exc:
            if exc.code==409:
                raise Conflict('Indexer version/create conflict') from None
            raise RuntimeError(f'Indexer HTTP {exc.code}') from None
        if len(raw)>self.max_bytes:
            raise RuntimeError('response budget exceeded')
        result=json.loads(raw)
        if not isinstance(result,dict):
            raise RuntimeError('unexpected response shape')
        return result
