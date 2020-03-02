from http.server import BaseHTTPRequestHandler
from urllib import parse
import base64 

from routes.main import routes


class BaseHandler(BaseHTTPRequestHandler):

    def do_HEAD(self):
        return

    def do_POST(self):
        return

    def do_GET(self):
        handler = self.route_request(self.path)
        self.response(handler)

    def response(self, handler):
        self.send_response(handler.status_code)
        for header,value in handler.get_response_headers():
            self.send_header(header, value)
        self.end_headers()
        self.wfile.write(handler.get_contents())

    def route_request(self, path):
        if path == '/':
            return RequestHandler()
        elif path == '/basic':
            return BasicAuthHandler(self.headers.get('Authorization'))
        else:
            return NotFoundHandler()


class RequestHandler():
    
    def __init__(self):
        self.headers = {}
        self.status_code = 200
        self.add_response_header('Content-Type', 'text/plain; charset=utf-8')
        self.contents = 'Test auth server'

    def get_contents(self):
        return bytes(self.contents, 'UTF-8')

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
            self.contents = 'Basic Auth OK'
        else:
            self.status_code = 401
            self.add_response_header('WWW-Authenticate', 'Basic realm="Auth Server"')
            self.contents = 'Login'

    def get_basic_key(self, username, password):
        return str(base64.b64encode(bytes('{}:{}'.format(username, password), 'utf-8')).decode('ascii'))


class NotFoundHandler(RequestHandler):
    
    def __init__(self):
        super().__init__()
        self.status_code = 404
        self.contents = 'Not Found'
