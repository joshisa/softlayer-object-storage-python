"""
    Connection Module

    See COPYING for license information
"""
from urllib.parse import urlencode
from object_storage import errors
from object_storage.transport import BaseAuthentication, \
    BaseAuthenticatedConnection, Response
import httplib2
import os
from base64 import b64encode

from object_storage.utils import json

import logging
logger = logging.getLogger(__name__)


class AuthenticatedConnection(BaseAuthenticatedConnection):
    """
        Connection that will authenticate if it isn't already
        and retry once if an auth error is returned.
    """
    def __init__(self, auth, debug=False, **kwargs):
        if debug:
            httplib2.debuglevel = 4
        self.token = None
        self.storage_url = None
        self.http = httplib2.Http()
        self.http.disable_ssl_certificate_validation = True
        self.auth = auth
        if not self.auth.authenticated:
            self.auth.authenticate()
        self._authenticate()

    def make_request(self, method, url=None, headers=None, formatter=None,
                     params=None, data=None, *args, **kwargs):
        """ Makes a request """
        headers = headers or {}
        headers.update(self.get_headers())

        if params:
            url = "%s?%s" % (url, urlencode(params))

        def _make_request(headers):
            logger.debug("%s %s %s" % (method, url, headers))
            res, content = self.http.request(url, method,
                                             headers=headers,
                                             body=data)
            response = Response()
            response.headers = res
            response.status_code = int(res.status)
            response.content = content
            return response

        response = _make_request(headers)

        if response.status_code == 401:
            self.auth.authenticate()
            self._authenticate()
            headers.update(self.auth_headers)
            response = _make_request(headers)

        response.raise_for_status()

        if formatter:
            return formatter(response)
        return response


class Authentication(BaseAuthentication):
    """
        Authentication class.
    """
    def __init__(self, username, api_key, auth_token=None,
                 bluemix=False, *args, **kwargs):
        super(Authentication, self).__init__(*args, **kwargs)
        self.username = username
        self.api_key = api_key
        self.auth_token = auth_token
        if os.getenv('VCAP_SERVICES'):
            self.bluemix = True
            # Find the bluemix app name to use as the SL objectstore user
            VCAP_APPLICATION = os.getenv('VCAP_APPLICATION')
            decoded_application = json.loads(VCAP_APPLICATION)
            self.bluemixappname = decoded_application['name']
        if self.auth_token:
            self.authenticated = True

    @property
    def auth_headers(self):
        return {'X-Auth-Token': self.auth_token}

    def authenticate(self):
        """ Does authentication """
        headers = {'X-Storage-User': self.username,
                   'X-Storage-Pass': self.api_key,
                   'Content-Length': '0'}
        http = httplib2.Http()
        http.disable_ssl_certificate_validation = True
        if self.bluemix:
            userAndPass = b64encode(bytes(self.username + ':' +
                                    self.api_key,
                                    'utf-8')).decode("ISO-8859-1")
            bluemix_headers = {'Authorization': 'Basic %s' % userAndPass}
            res, content = http.request(self.auth_url + '/' +
                                        self.bluemixappname,
                                        'GET', headers=bluemix_headers)
        else:
            res, content = http.request(self.auth_url, 'GET', headers=headers)

        response = Response()
        response.headers = res
        response.status_code = int(res.status)
        response.content = content

        if response.status_code == 401:
            raise errors.AuthenticationError('Invalid Credentials')
        response.raise_for_status()
        if not self.bluemix:
            try:
                storage_options = json.loads(response.content)['storage']
            except ValueError:
                raise errors.StorageURLNotFound("Could not parse "
                                                "services JSON.")
            self.storage_url = self.get_storage_url(storage_options)

        self.auth_token = response.headers['x-auth-token']
        if not self.storage_url:
            self.storage_url = response.headers['x-storage-url']
        if not self.auth_token or not self.storage_url:
            raise errors.AuthenticationError('Invalid Authentication Response')
