import os
import xml.sax
import boto.web_identity_provider
from boto.provider import Provider
from boto.resultset import ResultSet
from boto.connection import connection
from boto.compat import six
from boto.exception import BotoServerError

class AWSAuthConnection(connection):

    def __init__(self, host, aws_access_key_id=None,
                 aws_secret_access_key=None,
                 is_secure=True, port=None, proxy=None, proxy_port=None,
                 proxy_user=None, proxy_pass=None, debug=0,
                 https_connection_factory=None, path='/',
                 provider='aws', security_token=None,
                 suppress_consec_slashes=True,
                 validate_certs=True, profile_name=None):


        web_identity_file='AWS_WEB_IDENTITY_TOKEN_FILE'

        if web_identity_file in os.environ:
            if isinstance(provider,Provider):
                provider=boto.web_identity_provider.web_identity_credential_provider(provider.name,profile_name)
            else:
                provider=boto.web_identity_provider.web_identity_credential_provider(provider,profile_name)

        super(AWSAuthConnection,self).__init__(host, aws_access_key_id,
                 aws_secret_access_key,
                 is_secure, port, proxy, proxy_port,
                 proxy_user, proxy_pass, debug,
                 https_connection_factory, path,
                 provider, security_token,
                 suppress_consec_slashes,
                 validate_certs, profile_name)

    def aws_access_key_id(self):
        return self.provider.access_key
    aws_access_key_id = property(aws_access_key_id)
    gs_access_key_id = aws_access_key_id
    access_key = aws_access_key_id

    def aws_secret_access_key(self):
        return self.provider.secret_key
    aws_secret_access_key = property(aws_secret_access_key)
    gs_secret_access_key = aws_secret_access_key
    secret_key = aws_secret_access_key

class AWSQueryConnection(AWSAuthConnection):

    APIVersion = ''
    ResponseError = BotoServerError

    def __init__(self, aws_access_key_id=None, aws_secret_access_key=None,
                 is_secure=True, port=None, proxy=None, proxy_port=None,
                 proxy_user=None, proxy_pass=None, host=None, debug=0,
                 https_connection_factory=None, path='/', security_token=None,
                 validate_certs=True, profile_name=None, provider='aws'):
        super(AWSQueryConnection, self).__init__(
            host, aws_access_key_id,
            aws_secret_access_key,
            is_secure, port, proxy,
            proxy_port, proxy_user, proxy_pass,
            debug, https_connection_factory, path,
            security_token=security_token,
            validate_certs=validate_certs,
            profile_name=profile_name,
            provider=provider)

    def _required_auth_capability(self):
        return []

    def get_utf8_value(self, value):
        return boto.utils.get_utf8_value(value)


    def build_list_params(self, params, items, label):
        if isinstance(items, six.string_types):
            items = [items]
        for i in range(1, len(items) + 1):
            params['%s.%d' % (label, i)] = items[i - 1]

    def build_complex_list_params(self, params, items, label, names):
        """Serialize a list of structures.

        For example::

            items = [('foo', 'bar', 'baz'), ('foo2', 'bar2', 'baz2')]
            label = 'ParamName.member'
            names = ('One', 'Two', 'Three')
            self.build_complex_list_params(params, items, label, names)

        would result in the params dict being updated with these params::

            ParamName.member.1.One = foo
            ParamName.member.1.Two = bar
            ParamName.member.1.Three = baz

            ParamName.member.2.One = foo2
            ParamName.member.2.Two = bar2
            ParamName.member.2.Three = baz2

        :type params: dict
        :param params: The params dict.  The complex list params
            will be added to this dict.

        :type items: list of tuples
        :param items: The list to serialize.

        :type label: string
        :param label: The prefix to apply to the parameter.

        :type names: tuple of strings
        :param names: The names associated with each tuple element.

        """
        for i, item in enumerate(items, 1):
            current_prefix = '%s.%s' % (label, i)
            for key, value in zip(names, item):
                full_key = '%s.%s' % (current_prefix, key)
                params[full_key] = value

    # generics

    def get_list(self, action, params, markers, path='/',
                 parent=None, verb='GET'):
        if not parent:
            parent = self
        response = self.make_request(action, params, path, verb)
        body = response.read()
        boto.log.debug(body)
        if not body:
            boto.log.error('Null body %s' % body)
            raise self.ResponseError(response.status, response.reason, body)
        elif response.status == 200:
            rs = ResultSet(markers)
            h = boto.handler.XmlHandler(rs, parent)
            if isinstance(body, six.text_type):
                body = body.encode('utf-8')
            xml.sax.parseString(body, h)
            return rs
        else:
            boto.log.error('%s %s' % (response.status, response.reason))
            boto.log.error('%s' % body)
            raise self.ResponseError(response.status, response.reason, body)

    def get_object(self, action, params, cls, path='/',
                   parent=None, verb='GET'):
        if not parent:
            parent = self
        response = self.make_request(action, params, path, verb)
        body = response.read()
        boto.log.debug(body)
        if not body:
            boto.log.error('Null body %s' % body)
            raise self.ResponseError(response.status, response.reason, body)
        elif response.status == 200:
            obj = cls(parent)
            h = boto.handler.XmlHandler(obj, parent)
            if isinstance(body, six.text_type):
                body = body.encode('utf-8')
            xml.sax.parseString(body, h)
            return obj
        else:
            boto.log.error('%s %s' % (response.status, response.reason))
            boto.log.error('%s' % body)
            raise self.ResponseError(response.status, response.reason, body)

    def get_status(self, action, params, path='/', parent=None, verb='GET',
                   override_num_retries=None, override_timeout=None):
        if not parent:
            parent = self
        response = self.make_request(action, params, path, verb,
            override_num_retries=override_num_retries,
            override_timeout=override_timeout)
        body = response.read()
        boto.log.debug(body)
        if not body:
            boto.log.error('Null body %s' % body)
            raise self.ResponseError(response.status, response.reason, body)
        elif response.status == 200:
            rs = ResultSet()
            h = boto.handler.XmlHandler(rs, parent)
            xml.sax.parseString(body, h)
            return rs.status
        else:
            boto.log.error('%s %s' % (response.status, response.reason))
            boto.log.error('%s' % body)
            raise self.ResponseError(response.status, response.reason, body)

    def make_request(self, action, params=None, path='/', verb='GET',
            override_num_retries=None, override_timeout=None, async_timeout=None):
        http_request = self.build_base_http_request(verb, path, None,
                                                    params, {}, '',
                                                    self.host)
        if action:
            http_request.params['Action'] = action
        if self.APIVersion:
            http_request.params['Version'] = self.APIVersion
        return self._mexe(http_request,
            override_num_retries=override_num_retries,
            override_timeout=override_timeout,
            async_timeout=async_timeout)

    def get_object(self, action, params, cls, path='/',
                   parent=None, verb='GET',override_num_retries=None,
                   override_timeout=None, async_timeout=None):
        if not parent:
            parent = self
        response = self.make_request(action, params, path, verb,
            override_num_retries=override_num_retries,
            override_timeout=override_timeout,
            async_timeout=async_timeout)
        body = response.read()
        boto.log.debug(body)
        if not body:
            boto.log.error('Null body %s' % body)
            raise self.ResponseError(response.status, response.reason, body)
        elif response.status == 200:
            obj = cls(parent)
            h = boto.handler.XmlHandler(obj, parent)
            if isinstance(body, six.text_type):
                body = body.encode('utf-8')
            xml.sax.parseString(body, h)
            return obj
        else:
            boto.log.error('%s %s' % (response.status, response.reason))
            boto.log.error('%s' % body)
            raise self.ResponseError(response.status, response.reason, body)