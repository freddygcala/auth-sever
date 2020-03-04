from http.server import BaseHTTPRequestHandler
from urllib import parse
import base64 
from hashlib import md5, sha256, sha512
import os
import time
import re

from routes.main import routes


class BaseHandler(BaseHTTPRequestHandler):

    def do_HEAD(self):
        return

    def do_POST(self):
        return

    def do_GET(self):
        handler = self.route_request()
        self.response(handler)

    def response(self, handler):
        self.send_response(handler.status_code)
        for header,value in handler.get_response_headers():
            self.send_header(header, value)
        self.end_headers()
        self.wfile.write(handler.get_content())

    def route_request(self):
        if self.path == '/':
            return RequestHandler()
        elif self.path == '/basic':
            return BasicAuthHandler(self.headers.get('Authorization'))
        elif self.path == '/digest':
            return DigestAuthHandler(self)
        else:
            return NotFoundHandler()


class RequestHandler():
    
    def __init__(self):
        self.headers = {}
        self.status_code = 200
        self.add_response_header('Content-Type', 'text/plain; charset=utf-8')
        self.content = 'Test auth server'

    def get_content(self):
        return bytes(self.content, 'UTF-8')

    def get_response_headers(self):
        return self.headers.items()

    def add_response_header(self, header, value):
        self.headers[header] = value


class BasicAuthHandler(RequestHandler):
    
    def __init__(self, auth_header):
        super().__init__()
        user = 'admin'
        pswd = 'pass'
        if auth_header == 'Basic {}'.format(self.get_basic_key(user,pswd)):
            self.status_code = 200
            self.content = 'Basic Auth OK'
        else:
            self.status_code = 401
            self.add_response_header('WWW-Authenticate', 'Basic realm="Auth Server"')
            self.content = 'Basic Auth Login'

    def get_basic_key(self, username, password):
        return str(base64.b64encode(bytes('{}:{}'.format(username, password), 'utf-8')).decode('ascii'))


class DigestAuthHandler(RequestHandler):
    
    def __init__(self, request):
        super().__init__()
        authorization = request.headers.get('Authorization')
        qop = 'auth'
        algorithm = 'MD5'
        
        if not authorization:
            self.status_code = 401
            digest_challenge = self.get_digest_challenge(qop, request.path, algorithm)
            self.add_response_header('WWW-Authenticate', 'Digest {}'.format(digest_challenge))
            self.content = 'Please Login'
        elif not self.check_digest_credentials(request):
            self.status_code = 401
            digest_challenge = self.get_digest_challenge(qop, request.path, algorithm)
            self.add_response_header('WWW-Authenticate', 'Digest {}'.format(digest_challenge))
            self.content = 'Incorrect Authorization'
        else:
            self.status_code = 200
            self.content = 'Digest Auth OK'

    def get_digest_challenge(self, qop, path, algorithm):
        """Create digest challenge 
        """
        realm = 'digest@authserver.test'
        nonce = self.H(b':'.join([str(time.time()).encode('utf-8'), path.encode('utf-8'), os.urandom(10)]), algorithm)
        opaque = self.H(os.urandom(10), algorithm)
        digest_challenge = 'realm="{}", nonce={}, opaque={}, stale=FALSE, algorithm={}, qop={}'.format(
            realm,
            nonce,
            opaque,
            algorithm,
            qop,
        )
        return digest_challenge

    def parse_header(self, header):
        reg = re.compile('(\w+)[:=][\s"]?([^",]+)?')
        header_dict = dict(reg.findall(header))
        header_dict['type'] = header.split(' ')[0]
        return header_dict

    def check_digest_credentials(self, request):
        """Check header credentials
        """
        auth_header = request.headers.get('Authorization')
        uri = request.path
        method = 'GET' # Only GET method for now
        user = 'admin'
        passwd = 'pass'
        
        credentials = self.parse_header(auth_header)
        response_hash = self.create_digest_response(credentials, passwd, dict(uri=uri, body='', method=method))

        if credentials['type'].lower() == 'digest' and credentials['response'] == response_hash:
            return True
            
        return False

    def create_digest_response(self, credentials, password, request):
        """Create digest auth response
        If the qop directive's value is "auth" or "auth-int", then compute the response as follows:
            response = MD5(HA1:nonce:nonceCount:cnonce:qop:HA2)
        If the qop directive is unspecified, then compute the response as follows:
            response = MD5(HA1:nonce:HA2)
        """
        algorithm = credentials['algorithm']
        ha1_hash = self.HA1(credentials['realm'], credentials['username'], password, algorithm)
        ha2_hash = self.HA2(request, credentials, algorithm)
        qop = credentials['qop']
        nonce = credentials['nonce']
        if qop is None:
            response = self.H(b':'.join([ha1_hash.encode('utf-8'), nonce.encode('utf-8'), ha2_hash.encode('utf-8')]), algorithm)
        elif qop == 'auth' or qop == 'auth-int':
            for k in 'nonce', 'nc', 'cnonce', 'qop':
                if k not in credentials:
                    raise ValueError('{} required for response H'.format(k))
            response = self.H(b':'.join([
                ha1_hash.encode('utf-8'),
                nonce.encode('utf-8'),
                credentials['nc'].encode('utf-8'),
                credentials['cnonce'].encode('utf-8'),
                qop.encode('utf-8'),
                ha2_hash.encode('utf-8')
            ]), algorithm)
        else:
            raise ValueError
        
        return response


    def HA1(self, realm, username, password, algorithm):
        """Create HA1 hash
        HA1 = MD5(username:realm:password)
        """
        data = b':'.join([username.encode('utf-8'), realm.encode('utf-8'), password.encode('utf-8')])
        return self.H(data, algorithm)

    def HA2(self, request, credentials, algorithm):
        """Create HA2 hash
        If the qop directive's value is "auth" or is unspecified, then HA2 is
            HA2 = MD5(method:digestURI)
        If the qop directive's value is "auth-int", then HA2 is
            HA2 = MD5(method:digestURI:MD5(entityBody))
        """
        qop = credentials['qop']
        if qop == 'auth' or qop is None :
            A2 = b':'.join([request['method'].encode('utf-8'), request['uri'].encode('utf-8')])
            return self.H(A2, algorithm)
        elif qop == 'auth-int':
            A2 = b':'.join([request['method'].encode('utf-8'), request['uri'].encode('utf-8'), self.H(request['body'], algorithm).encode('utf-8')])
            return self.H(A2, algorithm)
        else:
            raise ValueError

    def H(self, data, algorithm):
        if algorithm == 'sha-256':
            return sha256(data).hexdigest()
        elif algorithm == 'sha-512':
            return sha512(data).hexdigest()
        else:
            return md5(data).hexdigest()


class NotFoundHandler(RequestHandler):
    
    def __init__(self):
        super().__init__()
        self.status_code = 404
        self.content = 'Not Found'
