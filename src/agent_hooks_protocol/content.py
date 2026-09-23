"""Normative synchronous raw-octet upload binding, independent of event auth."""
import hashlib
import os
import socket
from http.client import HTTPConnection
from urllib.parse import urlsplit
from urllib.request import Request, build_opener, HTTPRedirectHandler
from urllib.error import HTTPError

class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, *_args, **_kwargs):
        return None

from .runtime import ProtocolError


def upload(config, data, *, loopback=False, _declared=None):
    if not isinstance(data, bytes):
        raise ProtocolError('Upload requires bytes')
    from .interop import validate_descriptor
    from .runtime import Validator
    validator = Validator()
    config = {'maxBytes': 4 * 1024 * 1024, 'timeoutMs': 30000, **config}
    validator.validate('content-upload', config)
    url = urlsplit(config['endpoint'])
    if url.scheme != 'https' and not (loopback and url.scheme == 'http' and url.hostname in ('127.0.0.1', '::1', 'localhost')):
        raise ProtocolError('Upload requires HTTPS')
    if not url.hostname or url.username or url.password or url.fragment or any(c in config['endpoint'] for c in '\r\n'):
        raise ProtocolError('Invalid upload endpoint')
    if len(data) > config.get('maxBytes', 4 * 1024 * 1024):
        raise ProtocolError('Upload exceeds configured limit')
    timeout = config.get('timeoutMs', 30000) / 1000
    digest = hashlib.sha256(data).hexdigest()
    headers = {'Content-Type': 'application/octet-stream', 'Content-Length': str(len(data)),
               'AHP-Content-SHA256': digest}
    if config.get('auth'):
        auth = config['auth']
        if auth['type'] != 'bearer' or not os.environ.get(auth['tokenEnv']):
            raise ProtocolError('Upload bearer token unavailable')
        headers['Authorization'] = 'Bearer ' + os.environ[auth['tokenEnv']]
    if any('\r' in v or '\n' in v for v in headers.values()):
        raise ProtocolError('Invalid upload framing')
    if _declared:
        # Negative fixture framing is sent to the receiver, never credited locally.
        if not loopback or url.scheme != 'http' or url.hostname not in ('127.0.0.1', 'localhost', '::1'):
            raise ProtocolError('Malformed fixture uploads require loopback HTTP')
        headers['Content-Length'] = str(_declared.get('size', len(data)))
        headers['AHP-Content-SHA256'] = _declared.get('sha256', digest)
        if any(not isinstance(v, str) or '\r' in v or '\n' in v for v in headers.values()):
            raise ProtocolError('Invalid upload framing')
        connection = HTTPConnection(url.hostname, url.port, timeout=timeout)
        try:
            path = (url.path or '/') + ('?' + url.query if url.query else '')
            connection.request('POST', path, body=data, headers=headers)
            if int(headers['Content-Length']) != len(data):
                connection.sock.shutdown(socket.SHUT_WR)
            response = connection.getresponse()
            status = response.status
            descriptor = validate_descriptor(response, data, validator) if status == 201 else None
        finally:
            connection.close()
        return status, descriptor
    try:
        response = build_opener(NoRedirect()).open(Request(config['endpoint'], data=data, headers=headers, method='POST'), timeout=timeout)
    except HTTPError as error:
        response = error
    with response:
        status = response.code
        descriptor = validate_descriptor(response, data, validator) if status == 201 else None
    return status, descriptor


def receive(store, headers, data, authorize, *, limit=4 * 1024 * 1024):
    """Authorize(credentials) returns (201/401/403, receiver-defined scope)."""
    from .interop import validate_upload_framing
    try:
        if int(headers.get('Content-Length', '0')) > limit:
            return 413, None
        validate_upload_framing(headers, data)
        status, scope = authorize(headers.get('Authorization'))
        if status != 201 or scope is None:
            return (status if status != 201 else 403), None
        return store.upload({'scope': scope, 'size': len(data),
                             'sha256': headers['AHP-Content-SHA256'], 'data': data})
    except (ProtocolError, ValueError, UnicodeError):
        return 400, None
