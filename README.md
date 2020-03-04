
Web server to test different authentication schemes

Authentication schemes (to be) implemented:

- [x] [Basic](#basic-and-digest)
- [x] [Digest](#basic-and-digest)
- [ ] NTLM _*_
- [ ] OAuth2

This is a link to view all the RFC about HTTP Authentication Schemes: [https://www.iana.org/assignments/http-authschemes/http-authschemes.xhtml](https://www.iana.org/assignments/http-authschemes/http-authschemes.xhtml). To keep in mind:

>_*_ NTLM authentication scheme violates both HTTP semantics (being >connection-oriented) and syntax (use of syntax incompatible with the WWW-Authenticate and Authorization header field syntax)

## Basic and Digest

The basic and digest authentication are based on [RFC2617](https://tools.ietf.org/html/rfc2617) (HTTP Authentication: Basic and Digest Access Authentication)

### Test Basic auth

*Testing using `requests` library:

```python
import requests
from requests.auth import HTTPBasicAuth
url_basic = 'http://localhost:8080/basic'
response_basic = requests.get(url_basic, auth=HTTPBasicAuth('admin', 'pass'))
print(response_basic.status_code)
print(response_basic.text)
```

### Test Digest auth

```python
import requests
from requests.auth import HTTPDigestAuth
url_basic = 'http://localhost:8080/digest'
response_digest = requests.get(url_basic, auth=HTTPDigestAuth('admin', 'pass'))
print(response_digest.status_code)
print(response_digest.text)
```
