# Copyright (c) 2011 Mitch Garnaat http://garnaat.org/
# Copyright (c) 2011, Eucalyptus Systems, Inc.
#
# Permission is hereby granted, free of charge, to any person obtaining a
# copy of this software and associated documentation files (the
# "Software"), to deal in the Software without restriction, including
# without limitation the rights to use, copy, modify, merge, publish, dis-
# tribute, sublicense, and/or sell copies of the Software, and to permit
# persons to whom the Software is furnished to do so, subject to the fol-
# lowing conditions:
#
# The above copyright notice and this permission notice shall be included
# in all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
# OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABIL-
# ITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT
# SHALL THE AUTHOR BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
# WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
# IN THE SOFTWARE.

"""
File containing classes used in AssumeRoleWithWebIdentity, including credential objects, refreshable credentials and credntial provider.
Content of this file is backported from botocore, which is used by boto3.

https://github.com/boto/botocore/blob/08d0e5995284656895f5c8a0bddd8c386a8483c4/botocore/credentials.py#L353
"""

import time
import os
import datetime
import threading
from dateutil.tz import tzlocal
from dateutil.parser import parse
from collections import namedtuple
from copy import deepcopy
from hashlib import sha1

import boto.utils
import boto
from boto import config
from boto.compat import json
from boto.exception import CredentialRetrievalError,InvalidConfigError


ReadOnlyCredentials = namedtuple('ReadOnlyCredentials',
                                 ['access_key', 'secret_key', 'token'])

class FileWebIdentityTokenLoader(object):
    def __init__(self, web_identity_token_path, _open=open):
        self._web_identity_token_path = web_identity_token_path
        self._open = _open

    def __call__(self):
        with self._open(self._web_identity_token_path) as token_file:
            return token_file.read()


class Credentials(object):
    """
    :ivar access_key: The AccessKeyID.
    :ivar secret_key: The SecretAccessKey.
    :ivar session_token: The session token that must be passed with
                         requests to use the temporary credentials
    :ivar expiration: The timestamp for when the credentials will expire
    """

    def __init__(self, parent=None, access_key=None, secret_key=None):
        self.parent = parent
        self.access_key = access_key
        self.secret_key = secret_key
        self.session_token = None
        self.expiration = None
        self.request_id = None

        self._normalize()

    def __getitem__(self, item):
        if not isinstance(item,str):
            raise TypeError('Index must be a string, not {}'.format(type(item)))
        item = item.lower()
        return getattr(self,item)

    @classmethod
    def from_json(cls, json_doc):
        """
        Create and return a new Session Token based on the contents
        of a JSON document.

        :type json_doc: str
        :param json_doc: A string containing a JSON document with a
            previously saved Credentials object.
        """
        d = json.loads(json_doc)
        token = cls()
        token.__dict__.update(d)
        return token

    @classmethod
    def load(cls, file_path):
        """
        Create and return a new Session Token based on the contents
        of a previously saved JSON-format file.

        :type file_path: str
        :param file_path: The fully qualified path to the JSON-format
            file containing the previously saved Session Token information.
        """
        fp = open(file_path)
        json_doc = fp.read()
        fp.close()
        return cls.from_json(json_doc)

    def startElement(self, name, attrs, connection):
        return None

    def endElement(self, name, value, connection):
        if name == 'AccessKeyId':
            self.access_key = value
        elif name == 'SecretAccessKey':
            self.secret_key = value
        elif name == 'SessionToken':
            self.session_token = value
        elif name == 'Expiration':
            self.expiration = value
        elif name == 'RequestId':
            self.request_id = value
        else:
            pass

    def to_dict(self):
        """
        Return a Python dict containing the important information
        about this Session Token.
        """
        return {'access_key': self.access_key,
                'secret_key': self.secret_key,
                'session_token': self.session_token,
                'expiration': self.expiration,
                'request_id': self.request_id}

    def save(self, file_path):
        """
        Persist a Session Token to a file in JSON format.

        :type path: str
        :param path: The fully qualified path to the file where the
            the Session Token data should be written.  Any previous
            data in the file will be overwritten.  To help protect
            the credentials contained in the file, the permissions
            of the file will be set to readable/writable by owner only.
        """
        fp = open(file_path, 'w')
        json.dump(self.to_dict(), fp)
        fp.close()
        os.chmod(file_path, 0o600)

    def is_expired(self, time_offset_seconds=0):
        """
        Checks to see if the Session Token is expired or not.  By default
        it will check to see if the Session Token is expired as of the
        moment the method is called.  However, you can supply an
        optional parameter which is the number of seconds of offset
        into the future for the check.  For example, if you supply
        a value of 5, this method will return a True if the Session
        Token will be expired 5 seconds from this moment.

        :type time_offset_seconds: int
        :param time_offset_seconds: The number of seconds into the future
            to test the Session Token for expiration.
        """
        now = datetime.datetime.utcnow()
        if time_offset_seconds:
            now = now + datetime.timedelta(seconds=time_offset_seconds)
        ts = boto.utils.parse_ts(self.expiration)
        delta = ts - now
        return delta.total_seconds() <= 0

    def _normalize(self):
        # Keys would sometimes (accidentally) contain non-ascii characters.
        # It would cause a confusing UnicodeDecodeError in Python 2.
        # We explicitly convert them into unicode to avoid such error.
        #
        # Eventually the service will decide whether to accept the credential.
        # This also complies with the behavior in Python 3.
        if self.access_key is not None:
            self.access_key = boto.compat.ensure_unicode(self.access_key)
        if self.secret_key is not None:
            self.secret_key = boto.compat.ensure_unicode(self.secret_key)

    def get_frozen_credentials(self):
        return ReadOnlyCredentials(self.access_key,
                                   self.secret_key,
                                   self.token)

def _local_now():
    return datetime.datetime.now(tzlocal())

def total_seconds(delta):
    """
    Returns the total seconds in a ``datetime.timedelta``.

    This used to be a compat shim for 2.6 but is now just an alias.

    :param delta: The timedelta object
    :type delta: ``datetime.timedelta``
    """
    return delta.total_seconds()

def _serialize_if_needed(value, iso=False):
    if isinstance(value, datetime.datetime):
        if iso:
            return value.isoformat()
        return value.strftime('%Y-%m-%dT%H:%M:%S%Z')
    return value

def _parse_if_needed(value):
    if isinstance(value, datetime.datetime):
        return value
    return parse(value)

class RefreshableCredentials(Credentials):
    """
    Holds the credentials needed to authenticate requests. In addition, it
    knows how to refresh itself.

    :ivar access_key: The access key part of the credentials.
    :ivar secret_key: The secret key part of the credentials.
    :ivar token: The security token, valid only for session credentials.
    :ivar method: A string which identifies where the credentials
        were found.
    """
    # The time at which we'll attempt to refresh, but not
    # block if someone else is refreshing.
    _advisory_refresh_timeout = 10 * 60
    # The time at which all threads will block waiting for
    # refreshed credentials.
    _mandatory_refresh_timeout = 15 * 60

    def __init__(self, access_key, secret_key, token,
                 expiry_time, refresh_using, method,
                 time_fetcher=_local_now):
        self._refresh_using = refresh_using
        self._access_key = access_key
        self._secret_key = secret_key
        self._token = token
        self._expiry_time = expiry_time
        self._time_fetcher = time_fetcher
        self._refresh_lock = threading.Lock()
        self.method = method
        self._frozen_credentials = ReadOnlyCredentials(
            access_key, secret_key, token)
        self._normalize()

    def _normalize(self):
        pass

    @classmethod
    def create_from_metadata(cls, metadata, refresh_using, method):
        instance = cls(
            access_key=metadata['access_key'],
            secret_key=metadata['secret_key'],
            token=metadata['token'],
            expiry_time=cls._expiry_datetime(metadata['expiry_time']),
            method=method,
            refresh_using=refresh_using
        )
        return instance

    @property
    def access_key(self):
        """Warning: Using this property can lead to race conditions if you
        access another property subsequently along the refresh boundary.
        Please use get_frozen_credentials instead.
        """
        self._refresh()
        return self._access_key

    @access_key.setter
    def access_key(self, value):
        self._access_key = value

    @property
    def secret_key(self):
        """Warning: Using this property can lead to race conditions if you
        access another property subsequently along the refresh boundary.
        Please use get_frozen_credentials instead.
        """
        self._refresh()
        return self._secret_key

    @secret_key.setter
    def secret_key(self, value):
        self._secret_key = value

    @property
    def token(self):
        """Warning: Using this property can lead to race conditions if you
        access another property subsequently along the refresh boundary.
        Please use get_frozen_credentials instead.
        """
        self._refresh()
        return self._token

    @token.setter
    def token(self, value):
        self._token = value

    def _seconds_remaining(self):
        delta = self._expiry_time - self._time_fetcher()
        return total_seconds(delta)

    def refresh_needed(self, refresh_in=None):
        """Check if a refresh is needed.

        A refresh is needed if the expiry time associated
        with the temporary credentials is less than the
        provided ``refresh_in``.  If ``time_delta`` is not
        provided, ``self.advisory_refresh_needed`` will be used.

        For example, if your temporary credentials expire
        in 10 minutes and the provided ``refresh_in`` is
        ``15 * 60``, then this function will return ``True``.

        :type refresh_in: int
        :param refresh_in: The number of seconds before the
            credentials expire in which refresh attempts should
            be made.

        :return: True if refresh needed, False otherwise.

        """
        if self._expiry_time is None:
            # No expiration, so assume we don't need to refresh.
            return False

        if refresh_in is None:
            refresh_in = self._advisory_refresh_timeout
        # The credentials should be refreshed if they're going to expire
        # in less than 5 minutes.
        if self._seconds_remaining() >= refresh_in:
            # There's enough time left. Don't refresh.
            return False

        return True

    def _is_expired(self):
        # Checks if the current credentials are expired.
        return self.refresh_needed(refresh_in=0)

    def _refresh(self):
        # In the common case where we don't need a refresh, we
        # can immediately exit and not require acquiring the
        # refresh lock.
        if not self.refresh_needed(self._advisory_refresh_timeout):
            return

        # acquire() doesn't accept kwargs, but False is indicating
        # that we should not block if we can't acquire the lock.
        # If we aren't able to acquire the lock, we'll trigger
        # the else clause.
        if self._refresh_lock.acquire(False):
            try:
                if not self.refresh_needed(self._advisory_refresh_timeout):
                    return
                is_mandatory_refresh = self.refresh_needed(
                    self._mandatory_refresh_timeout)
                self._protected_refresh(is_mandatory=is_mandatory_refresh)
                return
            finally:
                self._refresh_lock.release()
        elif self.refresh_needed(self._mandatory_refresh_timeout):
            # If we're within the mandatory refresh window,
            # we must block until we get refreshed credentials.
            with self._refresh_lock:
                if not self.refresh_needed(self._mandatory_refresh_timeout):
                    return
                self._protected_refresh(is_mandatory=True)

    def _protected_refresh(self, is_mandatory):
        # precondition: this method should only be called if you've acquired
        # the self._refresh_lock.
        try:
            metadata = self._refresh_using()
        except Exception as e:
            period_name = 'mandatory' if is_mandatory else 'advisory'
            if is_mandatory:
                # If this is a mandatory refresh, then
                # all errors that occur when we attempt to refresh
                # credentials are propagated back to the user.
                raise
            # Otherwise we'll just return.
            # The end result will be that we'll use the current
            # set of temporary credentials we have.
            return
        self._set_from_data(metadata)
        self._frozen_credentials = ReadOnlyCredentials(
            self._access_key, self._secret_key, self._token)
        if self._is_expired():
            # We successfully refreshed credentials but for whatever
            # reason, our refreshing function returned credentials
            # that are still expired.  In this scenario, the only
            # thing we can do is let the user know and raise
            # an exception.
            msg = ("Credentials were refreshed, but the "
                   "refreshed credentials are still expired.")
            raise RuntimeError(msg)

    @staticmethod
    def _expiry_datetime(time_str):
        return parse(time_str)

    def _set_from_data(self, data):
        expected_keys = ['access_key', 'secret_key', 'token', 'expiry_time']
        if not data:
            missing_keys = expected_keys
        else:
            missing_keys = [k for k in expected_keys if k not in data]

        if missing_keys:
            message = "Credential refresh failed, response did not contain: %s"
            raise CredentialRetrievalError(
                provider=self.method,
                message=message % ', '.join(missing_keys),
            )

        self.access_key = data['access_key']
        self.secret_key = data['secret_key']
        self.token = data['token']
        self._expiry_time = parse(data['expiry_time'])
        boto.log.debug("Retrieved credentials will expire at: %s",
                     self._expiry_time)
        self._normalize()

    def get_frozen_credentials(self):
        """Return immutable credentials.

        The ``access_key``, ``secret_key``, and ``token`` properties
        on this class will always check and refresh credentials if
        needed before returning the particular credentials.

        This has an edge case where you can get inconsistent
        credentials.  Imagine this:

            # Current creds are "t1"
            tmp.access_key  ---> expired? no, so return t1.access_key
            # ---- time is now expired, creds need refreshing to "t2" ----
            tmp.secret_key  ---> expired? yes, refresh and return t2.secret_key

        This means we're using the access key from t1 with the secret key
        from t2.  To fix this issue, you can request a frozen credential object
        which is guaranteed not to change.

        The frozen credentials returned from this method should be used
        immediately and then discarded.  The typical usage pattern would
        be::

            creds = RefreshableCredentials(...)
            some_code = SomeSignerObject()
            # I'm about to sign the request.
            # The frozen credentials are only used for the
            # duration of generate_presigned_url and will be
            # immediately thrown away.
            request = some_code.sign_some_request(
                with_credentials=creds.get_frozen_credentials())
            print("Signed request:", request)

        """
        self._refresh()
        return self._frozen_credentials


class DeferredRefreshableCredentials(RefreshableCredentials):
    """Refreshable credentials that don't require initial credentials.

    refresh_using will be called upon first access.
    """
    def __init__(self, refresh_using, method, time_fetcher=_local_now):
        self._refresh_using = refresh_using
        self._access_key = None
        self._secret_key = None
        self._token = None
        self._expiry_time = None
        self._time_fetcher = time_fetcher
        self._refresh_lock = threading.Lock()
        self.method = method
        self._frozen_credentials = None

    def refresh_needed(self, refresh_in=None):
        if self._frozen_credentials is None:
            return True
        return super(DeferredRefreshableCredentials, self).refresh_needed(
            refresh_in
        )


class CachedCredentialFetcher(object):
    DEFAULT_EXPIRY_WINDOW_SECONDS = 60 * 15

    def __init__(self, cache=None, expiry_window_seconds=None):
        if cache is None:
            cache = {}
        self._cache = cache
        self._cache_key = self._create_cache_key()
        if expiry_window_seconds is None:
            expiry_window_seconds = self.DEFAULT_EXPIRY_WINDOW_SECONDS
        self._expiry_window_seconds = expiry_window_seconds

    def _create_cache_key(self):
        raise NotImplementedError('_create_cache_key()')

    def _make_file_safe(self, filename):
        # Replace :, path sep, and / to make it the string filename safe.
        filename = filename.replace(':', '_').replace(os.path.sep, '_')
        return filename.replace('/', '_')

    def _get_credentials(self):
        raise NotImplementedError('_get_credentials()')

    def fetch_credentials(self):
        return self._get_cached_credentials()

    def _get_cached_credentials(self):
        """Get up-to-date credentials.

        This will check the cache for up-to-date credentials, calling assume
        role if none are available.
        """
        response = self._load_from_cache()
        if response is None:
            response = self._get_credentials()
            self._write_to_cache(response)
        else:
            boto.log.debug("Credentials for role retrieved from cache.")

        if isinstance(response,AssumedRole):
            creds=response.credentials.to_dict()
        else:
            creds = response['Credentials']

        expiration = _serialize_if_needed(creds['expiration'], iso=True)
        return {
            'access_key': creds['access_key'],
            'secret_key': creds['secret_key'],
            'token': creds['session_token'],
            'expiry_time': expiration,
        }

    def _load_from_cache(self):
        if self._cache_key in self._cache:
            creds = deepcopy(self._cache[self._cache_key])
            if not self._is_expired(creds):
                return creds
            else:
                boto.log.debug(
                    "Credentials were found in cache, but they are expired."
                )
        return None

    def _write_to_cache(self, response):
        self._cache[self._cache_key] = deepcopy(response)

    def _is_expired(self, credentials):
        """Check if credentials are expired."""
        end_time = _parse_if_needed(credentials['Credentials']['expiration'])
        seconds = total_seconds(end_time - _local_now())
        return seconds < self._expiry_window_seconds


class BaseAssumeRoleCredentialFetcher(CachedCredentialFetcher):
    def __init__(self, connection_class, role_arn, extra_args=None,
                 cache=None, expiry_window_seconds=None):
        self._connction_class = connection_class
        self._role_arn = role_arn

        if extra_args is None:
            self._assume_kwargs = {}
        else:
            self._assume_kwargs = deepcopy(extra_args)
        self._assume_kwargs['RoleArn'] = self._role_arn

        self._role_session_name = self._assume_kwargs.get('RoleSessionName')
        self._using_default_session_name = False
        if not self._role_session_name:
            self._generate_assume_role_name()

        super(BaseAssumeRoleCredentialFetcher, self).__init__(
            cache, expiry_window_seconds
        )

    def _generate_assume_role_name(self):
        self._role_session_name = 'botocore-session-%s' % (int(time.time()))
        self._assume_kwargs['RoleSessionName'] = self._role_session_name
        self._using_default_session_name = True

    def _create_cache_key(self):
        """Create a predictable cache key for the current configuration.

        The cache key is intended to be compatible with file names.
        """
        args = deepcopy(self._assume_kwargs)

        # The role session name gets randomly generated, so we don't want it
        # in the hash.
        if self._using_default_session_name:
            del args['RoleSessionName']

        if 'Policy' in args:
            # To have a predictable hash, the keys of the policy must be
            # sorted, so we have to load it here to make sure it gets sorted
            # later on.
            args['Policy'] = json.loads(args['Policy'])

        args = json.dumps(args, sort_keys=True)
        argument_hash = sha1(args.encode('utf-8')).hexdigest()
        return self._make_file_safe(argument_hash)

class AssumeRoleWithWebIdentityCredentialFetcher(
        BaseAssumeRoleCredentialFetcher
):
    def __init__(self, connection_class, web_identity_token_loader, role_arn,
                 extra_args=None, cache=None, expiry_window_seconds=None):
        """
        :type connection_class: callable
        :param connection_class: A callable that creates a client taking
            arguments like connection_class(**kwargs)

        :type web_identity_token_loader: callable
        :param web_identity_token_loader: A callable that takes no arguments
        and returns a web identity token str.

        :type role_arn: str
        :param role_arn: The ARN of the role to be assumed.

        :type extra_args: dict
        :param extra_args: Any additional arguments to add to the assume
            role request using the format of the botocore operation.
            Possible keys include, but may not be limited to,
            DurationSeconds, Policy, SerialNumber, ExternalId and
            RoleSessionName.

        :type cache: dict
        :param cache: An object that supports ``__getitem__``,
            ``__setitem__``, and ``__contains__``.  An example of this is
            the ``JSONFileCache`` class in aws-cli.

        :type expiry_window_seconds: int
        :param expiry_window_seconds: The amount of time, in seconds,
        """
        self._web_identity_token_loader = web_identity_token_loader

        super(AssumeRoleWithWebIdentityCredentialFetcher, self).__init__(
            connection_class, role_arn, extra_args=extra_args,
            cache=cache, expiry_window_seconds=expiry_window_seconds
        )

    def _get_credentials(self):
        """Get credentials by calling assume role."""
        kwargs = self._assume_web_identity_role_kwargs()
        # Assume role with web identity does not require credentials other than
        # the token, explicitly configure the client to not sign requests.

        connection=self._connction_class()
        return connection.assume_role_with_web_identity(**kwargs)

    def _assume_role_kwargs(self):
        """Get the arguments for assume role based on current configuration."""
        assume_role_kwargs = deepcopy(self._assume_kwargs)
        identity_token = self._web_identity_token_loader()
        assume_role_kwargs['WebIdentityToken'] = identity_token

        return assume_role_kwargs

    def _assume_web_identity_role_kwargs(self):
        return {
            'web_identity_token':self._web_identity_token_loader(),
            'role_arn':self._role_arn,
            'role_session_name': self._role_session_name

        }

class AssumeRoleWithWebIdentityProvider(object):
    METHOD = 'assume-role-with-web-identity'
    CANONICAL_NAME = None
    _CONFIG_TO_ENV_VAR = {
        'web_identity_token_file': 'AWS_WEB_IDENTITY_TOKEN_FILE',
        'role_session_name': 'AWS_ROLE_SESSION_NAME',
        'role_arn': 'AWS_ROLE_ARN',
    }

    def __init__(
            self,
            connection,
            profile_name,
            cache=None,
            load_config=None,
            disable_env_vars=False,
            token_loader_cls=None,
    ):
        self.cache = cache
        self._connection = connection
        self._load_config = load_config
        self._profile_name = profile_name
        self._profile_config = None
        self._disable_env_vars = disable_env_vars
        if token_loader_cls is None:
            token_loader_cls = FileWebIdentityTokenLoader
        self._token_loader_cls = token_loader_cls

    def load(self):
        return self._assume_role_with_web_identity()


    def _get_profile_config(self, key):
        if self._profile_config is None and self._load_config is not None:
            print type(self._load_config)
            loaded_config = self._load_config()
            profiles = loaded_config.get('profiles', {})
            self._profile_config = profiles.get(self._profile_name, {})
        return self._profile_config.get(key) if self._profile_config else None

    def _get_env_config(self, key):
        if self._disable_env_vars:
            return None
        env_key = self._CONFIG_TO_ENV_VAR.get(key)
        if env_key and env_key in os.environ:
            return os.environ[env_key]
        return None

    def _get_config(self, key):
        env_value = self._get_env_config(key)
        if env_value is not None:
            return env_value
        return self._get_profile_config(key)


    def _assume_role_with_web_identity(self):
        token_path = self._get_config('web_identity_token_file')
        if not token_path:
            return None
        token_loader = self._token_loader_cls(token_path)

        role_arn = self._get_config('role_arn')
        if not role_arn:
            error_msg = (
                'The provided profile or the current environment is '
                'configured to assume role with web identity but has no '
                'role ARN configured. Ensure that the profile has the role_arn'
                'configuration set or the AWS_ROLE_ARN env var is set.'
            )
            raise InvalidConfigError(message=error_msg)

        extra_args = {}
        role_session_name = self._get_config('role_session_name')
        if role_session_name is not None:
            extra_args['RoleSessionName'] = role_session_name

        fetcher = AssumeRoleWithWebIdentityCredentialFetcher(
            connection_class=self._connection,
            web_identity_token_loader=token_loader,
            role_arn=role_arn,
            extra_args=extra_args,
            cache=self.cache,
        )
        # The initial credentials are empty and the expiration time is set
        # to now so that we can delay the call to assume role until it is
        # strictly needed.
        return DeferredRefreshableCredentials(
            method=self.METHOD,
            refresh_using=fetcher.fetch_credentials,
        )


class User(object):
    """
    :ivar arn: The arn of the user assuming the role.
    :ivar assume_role_id: The identifier of the assumed role.
    """
    def __init__(self, arn=None, assume_role_id=None):
        self.arn = arn
        self.assume_role_id = assume_role_id

    def startElement(self, name, attrs, connection):
        pass

    def endElement(self, name, value, connection):
        if name == 'Arn':
            self.arn = value
        elif name == 'AssumedRoleId':
            self.assume_role_id = value


class AssumedRole(object):
    """
    :ivar user: The assumed role user.
    :ivar credentials: A Credentials object containing the credentials.
    """
    def __init__(self, connection=None, credentials=None, user=None):
        self._connection = connection
        self.credentials = credentials
        self.user = user

    def startElement(self, name, attrs, connection):
        if name == 'Credentials':
            self.credentials = Credentials()
            return self.credentials
        elif name == 'AssumedRoleUser':
            self.user = User()
            return self.user

    def endElement(self, name, value, connection):
        pass

    def __deepcopy__(self, memodict={}):
        return AssumedRole(self._connection,deepcopy(self.credentials,memodict),deepcopy(self.user,memodict))

    def __getitem__(self, item):
        if not isinstance(item,str):
            raise TypeError('Index must be a string, not {}'.format(type(item)))
        item = item.lower()
        return getattr(self,item)