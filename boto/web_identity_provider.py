import boto.anon_connection
from boto.credentials import AssumeRoleWithWebIdentityProvider
from boto.provider import Provider

class web_identity_credential_provider(Provider):
    def __init__(self, name, profile_name):
        super(web_identity_credential_provider,self).__init__(name, profile_name=profile_name)
        self.access_key = None,
        self.secret_key = None,
        self.security_token = None,
        self._expiry_time = None
        connection = boto.anon_connection.AnonSTSConnection
        self._credentials = AssumeRoleWithWebIdentityProvider(connection, profile_name).load()


    def get_access_key(self):
        return self._credentials.get_frozen_credentials().access_key


    def set_access_key(self, value):
        self._access_key = value

    access_key = property(get_access_key, set_access_key)

    def get_secret_key(self):
        return self._credentials.get_frozen_credentials().secret_key

    def set_secret_key(self, value):
        self._secret_key = value

    secret_key = property(get_secret_key, set_secret_key)

    def get_security_token(self):
        return self._credentials.get_frozen_credentials().token

    def set_security_token(self, value):
        self._security_token = value

    security_token = property(get_security_token, set_security_token)

