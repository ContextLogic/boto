import os
import boto
from datetime import datetime

from boto.compat import expanduser
from boto.pyami.config import Config
from boto import config
from boto.provider import Provider,ProfileNotFoundError


class CredentialProvider(Provider):
    def __init__(self, name, access_key=None, secret_key=None,
                 security_token=None, profile_name=None,anon=False):

        super(CredentialProvider,self).__init__(name,access_key=access_key,secret_key=secret_key,
                                                security_token=security_token,profile_name=profile_name,anon=anon)

        # Load shared credentials file if it exists
        shared_path = os.path.join(expanduser('~'), '.' + name, 'credentials')
        self.shared_credentials = Config(do_load=False)
        if os.path.isfile(shared_path):
            self.shared_credentials.load_from_path(shared_path)

        self.get_credentials(access_key, secret_key, security_token, profile_name)

    def get_access_key(self):

        if self._credentials_need_refresh():
            self._populate_keys_from_metadata_server()
        return self._access_key

    def set_access_key(self, value):
        self._access_key = value

    access_key = property(get_access_key, set_access_key)

    def get_secret_key(self):
        if self._credentials_need_refresh():
            self._populate_keys_from_metadata_server()
        return self._secret_key

    def set_secret_key(self, value):
        self._secret_key = value

    secret_key = property(get_secret_key, set_secret_key)

    def get_security_token(self):
        if self._credentials_need_refresh():
            self._populate_keys_from_metadata_server()
        return self._security_token

    def set_security_token(self, value):
        self._security_token = value

    security_token = property(get_security_token, set_security_token)

    def _credentials_need_refresh(self):
        if self._credential_expiry_time is None:
            return False
        else:
            # The credentials should be refreshed if they're going to expire
            # in less than 5 minutes.
            delta = self._credential_expiry_time - datetime.utcnow()
            # python2.6 does not have timedelta.total_seconds() so we have
            # to calculate this ourselves.  This is straight from the
            # datetime docs.
            seconds_left = (
                (delta.microseconds + (delta.seconds + delta.days * 24 * 3600)
                 * 10 ** 6) / 10 ** 6)
            if seconds_left < (5 * 60):
                boto.log.debug("Credentials need to be refreshed.")
                return True
            else:
                return False

    def get_credentials(self, access_key=None, secret_key=None,
                        security_token=None, profile_name=None):
        access_key_name, secret_key_name, security_token_name, \
            profile_name_name = self.CredentialMap[self.name]

        # Load profile from shared environment variable if it was not
        # already passed in and the environment variable exists
        if profile_name is None and profile_name_name is not None and \
           profile_name_name.upper() in os.environ:
            profile_name = os.environ[profile_name_name.upper()]

        shared = self.shared_credentials

        if access_key is not None:
            self.access_key = access_key
            boto.log.debug("Using access key provided by client.")
        elif access_key_name.upper() in os.environ:
            self.access_key = os.environ[access_key_name.upper()]
            boto.log.debug("Using access key found in environment variable.")
        elif profile_name is not None:
            if shared.has_option(profile_name, access_key_name):
                self.access_key = shared.get(profile_name, access_key_name)
                boto.log.debug("Using access key found in shared credential "
                               "file for profile %s." % profile_name)
            elif config.has_option("profile %s" % profile_name,
                                   access_key_name):
                self.access_key = config.get("profile %s" % profile_name,
                                             access_key_name)
                boto.log.debug("Using access key found in config file: "
                               "profile %s." % profile_name)
            else:
                raise ProfileNotFoundError('Profile "%s" not found!' %
                                           profile_name)
        elif shared.has_option('default', access_key_name):
            self.access_key = shared.get('default', access_key_name)
            boto.log.debug("Using access key found in shared credential file.")
        elif config.has_option('Credentials', access_key_name):
            self.access_key = config.get('Credentials', access_key_name)
            boto.log.debug("Using access key found in config file.")

        if secret_key is not None:
            self.secret_key = secret_key
            boto.log.debug("Using secret key provided by client.")
        elif secret_key_name.upper() in os.environ:
            self.secret_key = os.environ[secret_key_name.upper()]
            boto.log.debug("Using secret key found in environment variable.")
        elif profile_name is not None:
            if shared.has_option(profile_name, secret_key_name):
                self.secret_key = shared.get(profile_name, secret_key_name)
                boto.log.debug("Using secret key found in shared credential "
                               "file for profile %s." % profile_name)
            elif config.has_option("profile %s" % profile_name, secret_key_name):
                self.secret_key = config.get("profile %s" % profile_name,
                                             secret_key_name)
                boto.log.debug("Using secret key found in config file: "
                               "profile %s." % profile_name)
            else:
                raise ProfileNotFoundError('Profile "%s" not found!' %
                                           profile_name)
        elif shared.has_option('default', secret_key_name):
            self.secret_key = shared.get('default', secret_key_name)
            boto.log.debug("Using secret key found in shared credential file.")
        elif config.has_option('Credentials', secret_key_name):
            self.secret_key = config.get('Credentials', secret_key_name)
            boto.log.debug("Using secret key found in config file.")
        elif config.has_option('Credentials', 'keyring'):
            keyring_name = config.get('Credentials', 'keyring')
            try:
                import keyring
            except ImportError:
                boto.log.error("The keyring module could not be imported. "
                               "For keyring support, install the keyring "
                               "module.")
                raise
            self.secret_key = keyring.get_password(
                keyring_name, self.access_key)
            boto.log.debug("Using secret key found in keyring.")

        if security_token is not None:
            self.security_token = security_token
            boto.log.debug("Using security token provided by client.")
        elif ((security_token_name is not None) and
              (access_key is None) and (secret_key is None)):
            # Only provide a token from the environment/config if the
            # caller did not specify a key and secret.  Otherwise an
            # environment/config token could be paired with a
            # different set of credentials provided by the caller
            if security_token_name.upper() in os.environ:
                self.security_token = os.environ[security_token_name.upper()]
                boto.log.debug("Using security token found in environment"
                               " variable.")
            elif shared.has_option(profile_name or 'default',
                                   security_token_name):
                self.security_token = shared.get(profile_name or 'default',
                                                 security_token_name)
                boto.log.debug("Using security token found in shared "
                               "credential file.")
            elif profile_name is not None:
                if config.has_option("profile %s" % profile_name,
                                     security_token_name):
                    boto.log.debug("config has option")
                    self.security_token = config.get("profile %s" % profile_name,
                                                     security_token_name)
                    boto.log.debug("Using security token found in config file: "
                                   "profile %s." % profile_name)
            elif config.has_option('Credentials', security_token_name):
                self.security_token = config.get('Credentials',
                                                 security_token_name)
                boto.log.debug("Using security token found in config file.")

        if ((self._access_key is None or self._secret_key is None) and
                self.MetadataServiceSupport[self.name]):
            self._populate_keys_from_metadata_server()
        self._secret_key = self._convert_key_to_str(self._secret_key)

    def _populate_keys_from_metadata_server(self):
        # get_instance_metadata is imported here because of a circular
        # dependency.
        boto.log.debug("Retrieving credentials from metadata server.")
        from boto.utils import get_instance_metadata
        timeout = config.getfloat('Boto', 'metadata_service_timeout', 1.0)
        attempts = config.getint('Boto', 'metadata_service_num_attempts', 1)
        # The num_retries arg is actually the total number of attempts made,
        # so the config options is named *_num_attempts to make this more
        # clear to users.
        metadata = get_instance_metadata(
            timeout=timeout, num_retries=attempts,
            data='meta-data/iam/security-credentials/')
        if metadata:
            # I'm assuming there's only one role on the instance profile.
            security = list(metadata.values())[0]
            self._access_key = security['AccessKeyId']
            self._secret_key = self._convert_key_to_str(security['SecretAccessKey'])
            self._security_token = security['Token']
            expires_at = security['Expiration']
            self._credential_expiry_time = datetime.strptime(
                expires_at, "%Y-%m-%dT%H:%M:%SZ")
            boto.log.debug("Retrieved credentials will expire in %s at: %s",
                           self._credential_expiry_time - datetime.now(), expires_at)