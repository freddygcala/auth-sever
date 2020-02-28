
from handlers import BaseHandler

HOST_NAME = 'localhost'
PORT_NUMBER = 8080


if __name__ == "__main__":
    from http.server import HTTPServer
    server = HTTPServer((HOST_NAME, PORT_NUMBER), BaseHandler)
    print('Server started - http://{}:{}'.format(HOST_NAME, PORT_NUMBER))
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    server.server_close()
    print('Server stopped - http://{}:{}'.format(HOST_NAME, PORT_NUMBER))



