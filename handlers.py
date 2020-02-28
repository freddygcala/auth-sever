from http.server import BaseHTTPRequestHandler
from urllib import parse

from routes.main import routes

def _get_request_info(req):
    parsed_path = parse.urlparse(req.path)
    message_parts = [
        'CLIENT VALUES:',
        'client_address={} ({})'.format(
            req.client_address,
            req.address_string()),
        'command={}'.format(req.command),
        'path={}'.format(req.path),
        'real path={}'.format(parsed_path.path),
        'query={}'.format(parsed_path.query),
        'request_version={}'.format(req.request_version),
        '',
        'SERVER VALUES:',
        'server_version={}'.format(req.server_version),
        'sys_version={}'.format(req.sys_version),
        'protocol_version={}'.format(req.protocol_version),
        '',
        'HEADERS RECEIVED:',
    ]
    for name, value in sorted(req.headers.items()):
        message_parts.append(
            '{}={}'.format(name, value.rstrip())
        )
    message_parts.append('')
    message = '\r\n'.join(message_parts)
    return message

class BaseHandler(BaseHTTPRequestHandler):

    def do_HEAD(self):
        return

    def do_POST(self):
        return

    def do_GET(self):
        if self.path in routes:
            content = routes[self.path]
        else:
            content = None
        self.respond(content)

    def handle_http(self, status, content_type):
        self.send_response(status)
        self.send_header('Content-Type', content_type)
        self.end_headers()

    def respond(self, message=None):
        status = 200 if message else 404
        message = message or _get_request_info(self)

        self.handle_http(status, 'text/plain; charset=utf-8')
        self.wfile.write(message.encode('utf-8'))

