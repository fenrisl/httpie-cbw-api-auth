"""
CyberWatch ApiAuth HMAC-SHA256 auth plugin for HTTPie.
"""
import hmac
import base64
import hashlib
import datetime

from httpie.plugins import AuthPlugin

try:
    import urlparse
except ImportError:
    import urllib.parse

__version__ = '0.0.2'
__author__ = 'CyberWatch SAS'
__licence__ = 'MIT'


class CbwApiAuth:
    def __init__(self, access_id, secret_key):
        self.access_id = access_id
        self.secret_key = secret_key.encode('ascii')

    def __call__(self, r):
        method = r.method.upper()

        content_type = r.headers.get('content-type')
        if not content_type:
            content_type = ''

        content_md5 = r.headers.get('content-md5')
        if not content_md5:
            content_md5 = ''

        httpdate = r.headers.get('date')
        if not httpdate:
            now = datetime.datetime.utcnow()
            httpdate = now.strftime('%a, %d %b %Y %H:%M:%S GMT')
            r.headers['Date'] = httpdate

        url = urlparse.urlparse(r.url)
        path = url.path
        if url.query:
            path = path + '?' + url.query

        canonical = ','.join([method,
                              content_type,
                              content_md5,
                              path,
                              httpdate])

        digest = hmac.new(self.secret_key, canonical, hashlib.sha256).digest()

        signature = base64.encodestring(digest).rstrip()

        r.headers['Authorization'] = 'CyberWatch APIAuth-HMAC-SHA256 %s:%s' % (
                                      self.access_id,
                                      signature)

        return r


class CbwApiAuthPlugin(AuthPlugin):

    name = 'CyberWatch ApiAuth auth'
    auth_type = 'cbw-api-auth'
    description = 'Sign requests using the CyberWatch ApiAuth HMAC-SHA256 authentication method'

    def get_auth(self, access_id, secret_key):
        return CbwApiAuth(access_id, secret_key)
