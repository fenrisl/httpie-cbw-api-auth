"""
CyberWatch ApiAuth HMAC-SHA256 auth plugin for HTTPie.
"""
import hmac
import base64
import hashlib
import datetime

from httpie.plugins import AuthPlugin

try:
    from urllib.parse import urlparse
except ImportError:
    from urlparse import urlparse

__version__ = '0.0.2'
__author__ = 'CyberWatch SAS'
__licence__ = 'MIT'


class CbwApiAuth:
    def __init__(self, access_id, secret_key):
        self.access_id = access_id
        self.secret_key = secret_key

    def __call__(self, r):
        method = r.method.upper()

        content_type = r.headers.get('content-type')
        if content_type:
            content_type = content_type.decode()
        else:
            content_type = ''

        content_md5 = r.headers.get('content-md5')
        if content_md5:
            content_md5 = content_md5.decode()
        else:
            content_md5 = ''

        httpdate = r.headers.get('date')
        if not httpdate:
            now = datetime.datetime.utcnow()
            httpdate = now.strftime('%a, %d %b %Y %H:%M:%S GMT')
            r.headers['Date'] = httpdate

        url = urlparse(r.url)
        path = url.path
        if url.query:
            path = path + '?' + url.query

        canonical = ','.join([method,
                              content_type,
                              content_md5,
                              path,
                              httpdate])

        signature = (base64.b64encode(hmac.new(self.secret_key.encode('utf-8'), canonical.encode('utf-8'), hashlib.sha256).digest())).decode()

        r.headers['Authorization'] = 'CyberWatch APIAuth-HMAC-SHA256 %s:%s' % (
                                      self.access_id,
                                      signature)

        return r


class CbwApiAuthPlugin(AuthPlugin):

    name = 'CyberWatch ApiAuth auth'
    auth_type = 'cbw-api-auth'
    description = 'Sign requests using the CyberWatch ApiAuth HMAC-SHA256 authentication method'

    def get_auth(self, username=None, password=None):
        return CbwApiAuth(username, password)
