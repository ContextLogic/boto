import unittest
import mock

import boto.credentials as credentials
from datetime import datetime, timedelta
from dateutil.tz import tzlocal
from boto.exception import CredentialRetrievalError,InvalidConfigError

class STSCredentialsTest(unittest.TestCase):
    sts = True

    def setUp(self):
        super(STSCredentialsTest, self).setUp()
        self.creds = credentials.Credentials()

    def test_to_dict(self):
        # This would fail miserably if ``Credentials.request_id`` hadn't been
        # explicitly set (no default).
        # Default.
        self.assertEqual(self.creds.to_dict(), {
            'access_key': None,
            'expiration': None,
            'request_id': None,
            'secret_key': None,
            'session_token': None
        })

        # Override.
        creds = credentials.Credentials()
        creds.access_key = 'something'
        creds.secret_key = 'crypto'
        creds.session_token = 'this'
        creds.expiration = 'way'
        creds.request_id = 'comes'
        self.assertEqual(creds.to_dict(), {
            'access_key': 'something',
            'expiration': 'way',
            'request_id': 'comes',
            'secret_key': 'crypto',
            'session_token': 'this'
        })

class BaseEnvVar(unittest.TestCase):
    def setUp(self):
        # Automatically patches out os.environ for you
        # and gives you a self.environ attribute that simulates
        # the environment.  Also will automatically restore state
        # for you in tearDown()
        self.environ = {}
        self.environ_patch = mock.patch('os.environ', self.environ)
        self.environ_patch.start()

    def tearDown(self):
        self.environ_patch.stop()

class TestCredentials(BaseEnvVar):
    def _ensure_credential_is_normalized_as_unicode(self, access, secret):
        c = credentials.Credentials(access_key=access, secret_key=secret)
        self.assertTrue(isinstance(c.access_key, type(u'u')))
        self.assertTrue(isinstance(c.secret_key, type(u'u')))

    def test_detect_nonascii_character(self):
        self._ensure_credential_is_normalized_as_unicode(
            'foo\xe2\x80\x99', 'bar\xe2\x80\x99')

    def test_unicode_input(self):
        self._ensure_credential_is_normalized_as_unicode(
            u'foo', u'bar')


class TestRefreshableCredentials(TestCredentials):
    def setUp(self):
        super(TestRefreshableCredentials, self).setUp()
        self.refresher = mock.Mock()
        self.future_time = datetime.now(tzlocal()) + timedelta(hours=24)
        self.expiry_time = \
            datetime.now(tzlocal()) - timedelta(minutes=30)
        self.metadata = {
            'access_key': 'NEW-ACCESS',
            'secret_key': 'NEW-SECRET',
            'token': 'NEW-TOKEN',
            'expiry_time': self.future_time.isoformat(),
            'role_name': 'rolename',
        }
        self.refresher.return_value = self.metadata
        self.mock_time = mock.Mock()
        self.creds = credentials.RefreshableCredentials(
            'ORIGINAL-ACCESS', 'ORIGINAL-SECRET', 'ORIGINAL-TOKEN',
            self.expiry_time, self.refresher, 'iam-role',
            time_fetcher=self.mock_time
        )

    def test_refresh_needed(self):
        # The expiry time was set for 30 minutes ago, so if we
        # say the current time is utcnow(), then we should need
        # a refresh.
        self.mock_time.return_value = datetime.now(tzlocal())
        self.assertTrue(self.creds.refresh_needed())
        # We should refresh creds, if we try to access "access_key"
        # or any of the cred vars.
        self.assertEqual(self.creds.access_key, 'NEW-ACCESS')
        self.assertEqual(self.creds.secret_key, 'NEW-SECRET')
        self.assertEqual(self.creds.token, 'NEW-TOKEN')

    def test_no_expiration(self):
        creds = credentials.RefreshableCredentials(
            'ORIGINAL-ACCESS', 'ORIGINAL-SECRET', 'ORIGINAL-TOKEN',
            None, self.refresher, 'iam-role', time_fetcher=self.mock_time
        )
        self.assertFalse(creds.refresh_needed())

    def test_no_refresh_needed(self):
        # The expiry time was 30 minutes ago, let's say it's an hour
        # ago currently.  That would mean we don't need a refresh.
        self.mock_time.return_value = (
            datetime.now(tzlocal()) - timedelta(minutes=60))
        self.assertTrue(not self.creds.refresh_needed())

        self.assertEqual(self.creds.access_key, 'ORIGINAL-ACCESS')
        self.assertEqual(self.creds.secret_key, 'ORIGINAL-SECRET')
        self.assertEqual(self.creds.token, 'ORIGINAL-TOKEN')

    def test_get_credentials_set(self):
        # We need to return a consistent set of credentials to use during the
        # signing process.
        self.mock_time.return_value = (
            datetime.now(tzlocal()) - timedelta(minutes=60))
        self.assertTrue(not self.creds.refresh_needed())
        credential_set = self.creds.get_frozen_credentials()
        self.assertEqual(credential_set.access_key, 'ORIGINAL-ACCESS')
        self.assertEqual(credential_set.secret_key, 'ORIGINAL-SECRET')
        self.assertEqual(credential_set.token, 'ORIGINAL-TOKEN')

    def test_refresh_returns_empty_dict(self):
        self.refresher.return_value = {}
        self.mock_time.return_value = datetime.now(tzlocal())
        self.assertTrue(self.creds.refresh_needed())

        with self.assertRaises(CredentialRetrievalError):
            self.creds.access_key

    def test_refresh_returns_none(self):
        self.refresher.return_value = None
        self.mock_time.return_value = datetime.now(tzlocal())
        self.assertTrue(self.creds.refresh_needed())

        with self.assertRaises(CredentialRetrievalError):
            self.creds.access_key

    def test_refresh_returns_partial_credentials(self):
        self.refresher.return_value = {'access_key': 'akid'}
        self.mock_time.return_value = datetime.now(tzlocal())
        self.assertTrue(self.creds.refresh_needed())

        with self.assertRaises(CredentialRetrievalError):
            self.creds.access_key


class TestDeferredRefreshableCredentials(unittest.TestCase):
    def setUp(self):
        self.refresher = mock.Mock()
        self.future_time = datetime.now(tzlocal()) + timedelta(hours=24)
        self.metadata = {
            'access_key': 'NEW-ACCESS',
            'secret_key': 'NEW-SECRET',
            'token': 'NEW-TOKEN',
            'expiry_time': self.future_time.isoformat(),
            'role_name': 'rolename',
        }
        self.refresher.return_value = self.metadata
        self.mock_time = mock.Mock()
        self.mock_time.return_value = datetime.now(tzlocal())

    def test_refresh_using_called_on_first_access(self):
        creds = credentials.DeferredRefreshableCredentials(
            self.refresher, 'iam-role', self.mock_time
        )

        # The credentials haven't been accessed, so there should be no calls.
        self.refresher.assert_not_called()

        # Now that the object has been accessed, it should have called the
        # refresher
        creds.get_frozen_credentials()
        self.assertEqual(self.refresher.call_count, 1)

    def test_refresh_only_called_once(self):
        creds = credentials.DeferredRefreshableCredentials(
            self.refresher, 'iam-role', self.mock_time
        )

        for _ in range(5):
            creds.get_frozen_credentials()

        # The credentials were accessed several times in a row, but only
        # should call refresh once.
        self.assertEqual(self.refresher.call_count, 1)


class TestAssumeRoleWithWebIdentityCredentialFetcher(BaseEnvVar):
    def setUp(self):
        super(TestAssumeRoleWithWebIdentityCredentialFetcher, self).setUp()
        self.role_arn = 'myrole'

    def load_token(self):
        return 'totally.a.token'

    def some_future_time(self):
        timeobj = datetime.now(tzlocal())
        return timeobj + timedelta(hours=24)

    def create_client_creator(self, with_response):
        # Create a mock sts client that returns a specific response
        # for assume_role.
        connection = mock.Mock()
        if isinstance(with_response, list):
            connection.assume_role_with_web_identity.side_effect = with_response
        else:
            connection.assume_role_with_web_identity.return_value = with_response
        return mock.Mock(return_value=connection)

    def get_expected_creds_from_response(self, response):
        expiration = response['Credentials']['expiration']
        if isinstance(expiration, datetime):
            expiration = expiration.isoformat()
        return {
            'access_key': response['Credentials']['access_key'],
            'secret_key': response['Credentials']['secret_key'],
            'token': response['Credentials']['session_token'],
            'expiry_time': expiration
        }

    def test_no_cache(self):
        response = {
            'Credentials': {
                'access_key': 'foo',
                'secret_key': 'bar',
                'session_token': 'baz',
                'expiration': self.some_future_time().isoformat()
            },
        }
        client_creator = self.create_client_creator(with_response=response)
        refresher = credentials.AssumeRoleWithWebIdentityCredentialFetcher(
            client_creator, self.load_token, self.role_arn
        )
        expected_response = self.get_expected_creds_from_response(response)
        response = refresher.fetch_credentials()

        self.assertEqual(response, expected_response)

    def test_retrieves_from_cache(self):
        date_in_future = datetime.utcnow() + timedelta(seconds=1000)
        utc_timestamp = date_in_future.isoformat() + 'Z'
        cache_key = (
            '793d6e2f27667ab2da104824407e486bfec24a47'
        )
        cache = {
            cache_key: {
                'Credentials': {
                    'access_key': 'foo-cached',
                    'secret_key': 'bar-cached',
                    'session_token': 'baz-cached',
                    'expiration': utc_timestamp,
                }
            }
        }
        client_creator = mock.Mock()
        refresher = credentials.AssumeRoleWithWebIdentityCredentialFetcher(
            client_creator, self.load_token, self.role_arn, cache=cache
        )
        expected_response = self.get_expected_creds_from_response(
            cache[cache_key]
        )
        response = refresher.fetch_credentials()

        self.assertEqual(response, expected_response)
        client_creator.assert_not_called()

    def test_assume_role_in_cache_but_expired(self):
        response = {
            'Credentials': {
                'access_key': 'foo',
                'secret_key': 'bar',
                'session_token': 'baz',
                'expiration': self.some_future_time().isoformat(),
            },
        }
        client_creator = self.create_client_creator(with_response=response)
        cache = {
            'development--myrole': {
                'Credentials': {
                    'access_key': 'foo-cached',
                    'secret_key': 'bar-cached',
                    'session_token': 'baz-cached',
                    'expiration': datetime.now(tzlocal()),
                }
            }
        }

        refresher = credentials.AssumeRoleWithWebIdentityCredentialFetcher(
            client_creator, self.load_token, self.role_arn, cache=cache
        )
        expected = self.get_expected_creds_from_response(response)
        response = refresher.fetch_credentials()

        self.assertEqual(response, expected)

class TestAssumeRoleWithWebIdentityCredentialProvider(unittest.TestCase):
    def setUp(self):
        self.profile_name = 'some-profile'
        self.config = {
            'role_arn': 'arn:aws:iam::123:role/role-name',
            'web_identity_token_file': '/some/path/token.jwt'
        }

    def create_client_creator(self, with_response):
        # Create a mock sts client that returns a specific response
        # for assume_role.
        client = mock.Mock()
        if isinstance(with_response, list):
            client.assume_role_with_web_identity.side_effect = with_response
        else:
            client.assume_role_with_web_identity.return_value = with_response
        return mock.Mock(return_value=client)

    def some_future_time(self):
        timeobj = datetime.now(tzlocal())
        return timeobj + timedelta(hours=24)

    def _mock_loader_cls(self, token=''):
        mock_loader = mock.Mock(spec=credentials.FileWebIdentityTokenLoader)
        mock_loader.return_value = token
        mock_cls = mock.Mock()
        mock_cls.return_value = mock_loader
        return mock_cls

    def _load_config(self):
        return {
            'profiles': {
                self.profile_name: self.config,
            }
        }

    def test_assume_role_with_no_cache(self):
        response = {
            'Credentials': {
                'access_key': 'foo',
                'secret_key': 'bar',
                'session_token': 'baz',
                'expiration': self.some_future_time().isoformat()
            },
        }
        client_creator = self.create_client_creator(with_response=response)
        mock_loader_cls = self._mock_loader_cls('totally.a.token')
        provider = credentials.AssumeRoleWithWebIdentityProvider(
            load_config=self._load_config,
            connection=client_creator,
            cache={},
            profile_name=self.profile_name,
            token_loader_cls=mock_loader_cls,
        )

        creds = provider.load()

        self.assertEqual(creds.access_key, 'foo')
        self.assertEqual(creds.secret_key, 'bar')
        self.assertEqual(creds.token, 'baz')
        mock_loader_cls.assert_called_with('/some/path/token.jwt')

    def test_assume_role_retrieves_from_cache(self):
        date_in_future = datetime.utcnow() + timedelta(seconds=1000)
        utc_timestamp = date_in_future.isoformat() + 'Z'

        cache_key = (
            'c29461feeacfbed43017d20612606ff76abc073d'
        )
        cache = {
            cache_key: {
                'Credentials': {
                    'access_key': 'foo-cached',
                    'secret_key': 'bar-cached',
                    'session_token': 'baz-cached',
                    'expiration': utc_timestamp,
                }
            }
        }
        mock_loader_cls = self._mock_loader_cls('totally.a.token')
        client_creator = mock.Mock()
        provider = credentials.AssumeRoleWithWebIdentityProvider(
            connection=client_creator,
            load_config=self._load_config,
            cache=cache,
            profile_name=self.profile_name,
            token_loader_cls=mock_loader_cls,
        )

        creds = provider.load()

        self.assertEqual(creds.access_key, 'foo-cached')
        self.assertEqual(creds.secret_key, 'bar-cached')
        self.assertEqual(creds.token, 'baz-cached')
        client_creator.assert_not_called()

    def test_assume_role_in_cache_but_expired(self):
        expired_creds = datetime.now(tzlocal())
        valid_creds = expired_creds + timedelta(hours=1)
        response = {
            'Credentials': {
                'access_key': 'foo',
                'secret_key': 'bar',
                'session_token': 'baz',
                'expiration': valid_creds,
            },
        }
        cache = {
            'development--myrole': {
                'Credentials': {
                    'access_key': 'foo-cached',
                    'secret_key': 'bar-cached',
                    'session_token': 'baz-cached',
                    'expiration': expired_creds,
                }
            }
        }
        client_creator = self.create_client_creator(with_response=response)
        mock_loader_cls = self._mock_loader_cls('totally.a.token')
        provider = credentials.AssumeRoleWithWebIdentityProvider(
            load_config=self._load_config,
            connection=client_creator,
            cache=cache,
            profile_name=self.profile_name,
            token_loader_cls=mock_loader_cls,
        )

        creds = provider.load()

        self.assertEqual(creds.access_key, 'foo')
        self.assertEqual(creds.secret_key, 'bar')
        self.assertEqual(creds.token, 'baz')
        mock_loader_cls.assert_called_with('/some/path/token.jwt')

    def test_role_session_name_provided(self):
        self.config['role_session_name'] = 'myname'
        response = {
            'Credentials': {
                'access_key': 'foo',
                'secret_key': 'bar',
                'session_token': 'baz',
                'expiration': self.some_future_time().isoformat(),
            },
        }
        client_creator = self.create_client_creator(with_response=response)
        mock_loader_cls = self._mock_loader_cls('totally.a.token')
        provider = credentials.AssumeRoleWithWebIdentityProvider(
            load_config=self._load_config,
            connection=client_creator,
            cache={},
            profile_name=self.profile_name,
            token_loader_cls=mock_loader_cls,
        )
        # The credentials won't actually be assumed until they're requested.
        provider.load().get_frozen_credentials()

        client = client_creator.return_value
        client.assume_role_with_web_identity.assert_called_with(
            role_arn='arn:aws:iam::123:role/role-name',
            role_session_name='myname',
            web_identity_token='totally.a.token'
        )

    def test_role_arn_not_set(self):
        del self.config['role_arn']
        client_creator = self.create_client_creator(with_response={})
        provider = credentials.AssumeRoleWithWebIdentityProvider(
            load_config=self._load_config,
            connection=client_creator,
            cache={},
            profile_name=self.profile_name,
        )
        # If the role arn isn't set but the token path is raise an error
        with self.assertRaises(InvalidConfigError):
            provider.load()
