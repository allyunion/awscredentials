"""Python library defining credential classes

Example of usage:
import awscredentials
credential = awscredentials.AWSCredentials()
credential.get_credentials_from_profile()
mfa = awscredentials.AWSMFASessionCredentials(credential, '<Full ARN of MFA token>')
mfa.get_credentials_from_sts()
ar = awscredentials.AWSAssumeRoleCredentials(mfa,
                                    '<Full ARN of the Role>',
                                    '<Profile name>')
ar.get_credentials_from_sts()
"""

# Standard Libraries
import configparser
import datetime
import json
import os
import os.path

# Third party libraries
import boto3

AWS_CREDENTIALS_FILE = os.path.expanduser('~/.aws/credentials')
AWS_CONFIG_FILE = os.path.expanduser('~/.aws/config')

# Pylint ignores
#pylint: disable=arguments-differ

class AWSCredentials(object):
    """Defines basic functions around getting AWS Credentials"""
    def __init__(self, profile='default', access='', secret=''):
        """
        Takes in AWSCredentials(profile='', access='', secret='')
        Example:
        creds = AWSCredentials(profile='default')
        creds = AWSCredentials(access='<AWS Access Key>', secret='<AWS Secret Key>')
        """
        self.aws_profile = profile
        self.aws_access_key = access
        self.aws_secret_key = secret

    def __getitem__(self, items):
        """Function that treats object like a dictionary,
        returns a few selected items only."""
        if items == 'aws_profile':
            return self.aws_profile
        elif items == 'aws_access_key':
            return self.aws_access_key
        elif items == 'aws_secret_key':
            return self.aws_secret_key
        else:
            raise KeyError("No such item '{}' in object".format(items))

    def __repr__(self):
        """Function represent the object"""
        return ("{{'aws_profile': '{}', 'aws_access_key': '{}',"
                " 'aws_secret_key': '{}'}}").format(
                    self.aws_profile,
                    self.aws_access_key,
                    self.aws_secret_key)

    def __str__(self):
        """Will only output access key and secret key"""
        return ("AWS_ACCESS_KEY='{}'\n"
                "AWS_SECRET_KEY='{}'").format(
                    self.aws_access_key,
                    self.aws_secret_key)

    def set_profile_from_env(self):
        """Set the profile from AWS_PROFILE environmental variable"""
        if 'AWS_PROFILE' in os.environ:
            self.aws_profile = os.environ['AWS_PROFILE']
            return True
        return False

    def set_credentials_from_env(self):
        """Set the AWS_ACCESS_KEY and AWS_SECRET_KEY from environmental
        variables"""
        if 'AWS_ACCESS_KEY' in os.environ:
            self.aws_access_key = os.environ['AWS_ACCESS_KEY']
        else:
            raise KeyError("AWS_ACCESS_KEY not set in environment variables!")

        if 'AWS_SECRET_KEY' in os.environ:
            self.aws_secret_key = os.environ['AWS_SECRET_KEY']
        else:
            raise KeyError("AWS_SECRET_KEY not set in environment variables!")

    def get_credentials_from_profile(self):
        """Set the credentials from the AWS credentials file given the set
        profile defined"""
        config = configparser.ConfigParser()
        if os.path.exists(AWS_CREDENTIALS_FILE):
            config.read(AWS_CREDENTIALS_FILE)
            if self.aws_profile in config.sections():
                self.aws_access_key = config.get(self.aws_profile,
                                                 'aws_access_key_id')
                self.aws_secret_key = config.get(self.aws_profile,
                                                 'aws_secret_access_key')
            else:
                raise IOError(("'{}' section not defined in credentials "
                               "file '{}'!").format(self.aws_profile, AWS_CREDENTIALS_FILE))
        else:
            raise FileNotFoundError("'{}' not found".format(
                AWS_CREDENTIALS_FILE))

    def get_credentials(self):
        """Returns the credentials as a dict"""
        return {'aws_access_key': self.aws_access_key,
                'aws_secret_key': self.aws_secret_key}

class AWSSessionCredentials(object):
    """Base class for AWS Session Credentials"""
    def __init__(self, credentials):
        """
        Define base init class, will need to be overwritten by subclasses
        """
        self.aws_credentials = credentials
        self.aws_access_key = ''
        self.aws_secret_key = ''
        self.aws_session_token = ''
        self.aws_session_data = {}
        self.aws_session_json = ''

    def __getitem__(self, items):
        """Function that treats object like a dictionary,
        returns a few selected items only."""
        if items == 'aws_access_key':
            return self.aws_access_key
        elif items == 'aws_secret_key':
            return self.aws_secret_key
        elif items == 'aws_session_token':
            return self.aws_session_token
        elif items == 'aws_profile':
            return '{}-session'.format(self.aws_credentials['aws_profile'])
        else:
            raise KeyError("No such item '{}' in object".format(items))

    def __repr__(self):
        """Function represent the object"""
        return json.dumps({
            'aws_credentials': self.aws_credentials.__repr__(),
            'aws_access_key': self.aws_access_key,
            'aws_secret_key': self.aws_secret_key,
            'aws_session_token': self.aws_session_token,
            'aws_session_data': self.aws_session_data,
            'aws_session_json': self.aws_session_json}, indent=4)

    def __str__(self):
        """Will only output access, secret and session token"""
        return ("AWS_ACCESS_KEY='{}'\n"
                "AWS_SECRET_KEY='{}'\n"
                "AWS_SESSION_TOKEN='{}'").format(
                    self.aws_access_key,
                    self.aws_secret_key,
                    self.aws_session_token)

    @staticmethod
    def convert_dt_to_str(dtobject):
        """Converts a datetime object into UTC and in a string formatted
        'YYYY-MM-ddTH:M:SZ'"""
        return dtobject.astimezone(datetime.timezone.utc).strftime(
            '%Y-%m-%dT%H:%M:%SZ')

    @staticmethod
    def convert_str_to_dt(dstr):
        """Converts a dstr string object formatted '%Y-%m-%dT%H:%M:%SZ'
        into a datetime object"""
        return datetime.datetime.strptime(dstr, '%Y-%m-%dT%H:%M:%SZ')

    def _save_session_token_as_string(self, data):
        """Converts the results from the get_session_token into a string
        and store it in self.aws_session_json"""
        dconvert = data['Credentials']['Expiration']
        data['Credentials']['Expiration'] = self.convert_dt_to_str(dconvert)
        self.aws_session_json = json.dumps(data)

    def validate_session(self, session_token=False):
        """This function returns True if the session is valid, false otherwise"""
        if session_token:
            if self.aws_access_key != '' and self.aws_secret_key != '' and \
                self.aws_session_token != '':
                sts_client = boto3.client(
                    service_name='sts',
                    aws_access_key_id=self.aws_access_key,
                    aws_secret_access_key=self.aws_secret_key)
                try:
                    sts_client.get_caller_identity()
                    return True
                except boto3.exceptions.botocore.client.ClientError as error:
                    if 'InvalidClientTokenId' in str(error):
                        return False
                    else:
                        raise
        else:
            if self.aws_access_key != '' and self.aws_secret_key != '':
                sts_client = boto3.client(
                    service_name='sts',
                    aws_access_key_id=self.aws_access_key,
                    aws_secret_access_key=self.aws_secret_key)
                try:
                    sts_client.get_caller_identity()
                    return True
                except boto3.exceptions.botocore.client.ClientError as error:
                    if 'InvalidClientTokenId' in str(error):
                        return False
                    else:
                        raise
                except:
                    raise
        return False

    def get_credentials_from_profile(self, profile, renew=False):
        """Get the MFA credentials from the AWS credentials file
        and if renew is set to True, if the credentials expired,
        get new ones from the Security Token Service."""
        if os.path.exists(AWS_CREDENTIALS_FILE):
            config = configparser.ConfigParser()
            config.read(AWS_CREDENTIALS_FILE)
            if profile in config.sections():
                self.aws_access_key = config.get(profile,
                                                 'aws_access_key_id')
                self.aws_secret_key = config.get(profile,
                                                 'aws_secret_access_key')
                self.aws_session_token = config.get(profile,
                                                    'aws_session_token')
                if not self.validate_session():
                    self.aws_access_key = ''
                    self.aws_secret_key = ''
                    self.aws_session_token = ''

                    if renew:
                        self.get_credentials_from_sts()
            else:
                raise IOError(("'{}' section not defined in credentials "
                               "file '{}'!").format(profile, AWS_CREDENTIALS_FILE))
        else:
            raise FileNotFoundError("'{}' not found".format(
                AWS_CREDENTIALS_FILE))

    def get_credentials_from_sts(self):
        """Get the MFA credentials from the AWS Security Token Service
        Downstream classes will need to re-implement this class"""
        return self.aws_access_key != '' and self.aws_secret_key != ''

    def get_credentials_from_cache(self, filename):
        """Read the MFA session from a cached file"""
        try:
            with open(filename) as filein:
                self.aws_session_json = filein.read()
                data = json.loads(self.aws_session_json)
                expiration = self.convert_str_to_dt(
                    data['Credentials']['Expiration'])
                if datetime.datetime.now() >= expiration:
                    print("WARN: cached credentials have expired!")
                    self.aws_access_key = ''
                    self.aws_secret_key = ''
                    self.aws_session_token = ''
                    self.aws_session_data = {}
                    self.aws_session_json = ''
                    return False
                else:
                    data['Credentials']['Expiration'] = expiration
                    self.aws_session_data = data
                    self.aws_access_key = data['Credentials']['AccessKeyId']
                    self.aws_secret_key = data['Credentials']['SecretAccessKey']
                    self.aws_session_token = data['Credentials']['SessionToken']
            return True
        except FileNotFoundError:
            return False

    def write_session_to_cache(self, filename):
        """Write the MFA session into a cached file"""
        if self.aws_session_json != '':
            with open(filename, 'w') as fout:
                fout.write(self.aws_session_json)
            return True
        return False

    def write_session_to_credfile(self, profile):
        """Write the session into the AWS credential file"""
        if self.aws_access_key != '' and self.aws_secret_key != '' and \
            self.aws_session_token != '':
            if os.path.exists(AWS_CREDENTIALS_FILE):
                config = configparser.ConfigParser()
                config.read(AWS_CREDENTIALS_FILE)
                if profile not in config.sections():
                    config[profile] = {}

                # Overwrite even if it exists,
                # assume in memory credentials are valid
                config[profile]['aws_access_key_id'] = self.aws_access_key
                config[profile]['aws_secret_access_key'] = self.aws_secret_key
                config[profile]['aws_session_token'] = self.aws_session_token
                with open(AWS_CREDENTIALS_FILE, 'w') as credsfile:
                    config.write(credsfile)
            else:
                with open(AWS_CREDENTIALS_FILE, 'w') as fout:
                    fout.write('[{}]\n'.format(
                        profile))
                    fout.write('aws_access_key_id = {}\n'.format(
                        self.aws_access_key))
                    fout.write('aws_secret_access_key = {}\n'.format(
                        self.aws_secret_key))
                    fout.write('aws_session_token = {}\n'.format(
                        self.aws_session_token))
            return True
        return False

    @staticmethod
    def _write_section_to_awsconfig(new_profile, source_profile,
                                    role_arn='', mfa_serial='',
                                    region=''):
        """Write a profile section into the AWS credential file"""
        if new_profile != 'default' and 'profile ' not in new_profile:
            new_profile = 'profile {}'.format(new_profile)
        if os.path.exists(AWS_CONFIG_FILE):
            config = configparser.ConfigParser()
            config.read(AWS_CONFIG_FILE)
            if new_profile not in config.sections():
                config[new_profile] = {}

            config[new_profile]['source_profile'] = source_profile
            if role_arn:
                config[new_profile]['role_arn'] = role_arn
            if mfa_serial:
                config[new_profile]['mfa_serial'] = mfa_serial
            if region:
                config[new_profile]['region'] = region
            with open(AWS_CONFIG_FILE, 'w') as confout:
                config.write(confout)
        else:
            with open(AWS_CONFIG_FILE, 'w') as fout:
                fout.write('[{}]\n'.format(new_profile))
                fout.write('source_profile = {}'.format(source_profile))
                if role_arn:
                    fout.write('role_arn = {}'.format(role_arn))
                if mfa_serial:
                    fout.write('mfa_serial = {}'.format(mfa_serial))
                if region:
                    fout.write('region = {}'.format(region))


class AWSMFASessionCredentials(AWSSessionCredentials):
    """Defines functionality in setting/getting MFA session credentials
    from a set of AWSCredentials"""
    def __init__(self, credentials, mfa_token, region=''):
        """
        Gets the temporary MFA authorized credentials
        """
        if not isinstance(credentials, (AWSCredentials, AWSSessionCredentials)):
            raise TypeError("credentials passed is not of type "
                            "AWSCredentials or AWSSessionCredentials")
        super().__init__(credentials)
        if 'arn:aws:iam::' not in mfa_token:
            raise ValueError("Invalid input given for mfa_token: '{}'".format(
                mfa_token))
        self.aws_mfa_token = mfa_token
        self.region = region
        self.cached_filename = os.path.expanduser(
            '~/.aws/cli/cache/{}-mfa.json'.format(
                self.aws_credentials['aws_profile']))

    def __getitem__(self, items):
        """Function that treats object like a dictionary,
        returns a few selected items only."""
        if items == 'aws_mfa_token':
            return self.aws_mfa_token
        elif items == 'aws_access_key':
            return self.aws_access_key
        elif items == 'aws_secret_key':
            return self.aws_secret_key
        elif items == 'aws_session_token':
            return self.aws_session_token
        elif items == 'aws_profile':
            return '{}-mfa'.format(self.aws_credentials['aws_profile'])
        else:
            raise KeyError("No such item '{}' in object".format(items))

    def __repr__(self):
        """Function represent the object"""
        aws_session_data = self.aws_session_data.copy()
        if self.aws_session_data:
            if isinstance(aws_session_data['Credentials']['Expiration'],
                          datetime.datetime):
                aws_session_data['Credentials']['Expiration'] = \
                    self.convert_dt_to_str(
                        aws_session_data['Credentials']['Expiration'])
        return json.dumps({
            'aws_credentials': self.aws_credentials.__repr__(),
            'aws_mfa_token': self.aws_mfa_token,
            'aws_access_key': self.aws_access_key,
            'aws_secret_key': self.aws_secret_key,
            'aws_session_token': self.aws_session_token,
            'aws_session_data': aws_session_data,
            'aws_session_json': self.aws_session_json,
            'aws_cached_filename': self.cached_filename}, indent=4)

    def get_credentials_from_sts(self, token_code=''):
        """Get the MFA credentials from the AWS Security Token Service"""
        sts_client = boto3.client(
            service_name='sts',
            aws_access_key_id=self.aws_credentials['aws_access_key'],
            aws_secret_access_key=self.aws_credentials['aws_secret_key'])

        if token_code == '':
            token_code = input('Enter MFA Token Code: ')

        self.aws_session_data = sts_client.get_session_token(
            DurationSeconds=10800, # 3 hours
            SerialNumber=self.aws_mfa_token,
            TokenCode=token_code)

        self._save_session_token_as_string(self.aws_session_data.copy())

        self.aws_access_key = self.aws_session_data['Credentials'][
            'AccessKeyId']
        self.aws_secret_key = self.aws_session_data['Credentials'][
            'SecretAccessKey']
        self.aws_session_token = self.aws_session_data['Credentials'][
            'SessionToken']

    def get_credentials_from_cache(self):
        """Read the MFA session from a cached file"""
        return super(AWSMFASessionCredentials, self).get_credentials_from_cache(
            self.cached_filename)

    def write_mfa_session_to_cache(self):
        """Write the MFA session into a cached file"""
        return self.write_session_to_cache(self.cached_filename)

    def write_mfa_session_to_credfile(self):
        """Write the MFA session into the AWS configuration files"""
        return self.write_session_to_credfile(
            self.aws_credentials['aws_profile'] + '-mfa')

    def write_mfa_section_to_awsconfig(self):
        """Write a profile section into the AWS credential file"""
        self._write_section_to_awsconfig(
            new_profile=self.aws_credentials['aws_profile'] + '-mfa',
            source_profile=self.aws_credentials['aws_profile'],
            mfa_serial=self.aws_mfa_token,
            region=self.region)

class AWSAssumeRoleCredentials(AWSSessionCredentials):
    """A class wrapper around assume role by using either
    AWSCredentials or AWSMFASessionCredentials"""
    def __init__(self, credentials, role_arn, profile_name, region=''):
        """
        Gets the temporary MFA authorized credentials
        """
        if not isinstance(credentials, (AWSCredentials,
                                        AWSSessionCredentials,
                                        AWSMFASessionCredentials)):
            raise TypeError("credentials passed is not of type "
                            "AWSCredentials or AWSSessionCredentials or "
                            "AWSMFASessionCredentials")
        super().__init__(credentials)
        if 'arn:aws:iam::' not in role_arn and 'role' not in role_arn:
            raise ValueError("Invalid input given for role_arn: '{}'".format(
                role_arn))
        self.profile_name = profile_name
        self.role_arn = role_arn
        self.region = region
        self.cached_filename = os.path.expanduser(
            '~/.aws/cli/cache/{}--{}.json'.format(
                profile_name, role_arn.replace(':', '_').replace('/', '-')))

    def __getitem__(self, items):
        """Function that treats object like a dictionary,
        returns a few selected items only."""
        if items == 'aws_access_key':
            return self.aws_access_key
        elif items == 'aws_secret_key':
            return self.aws_secret_key
        elif items == 'aws_session_token':
            return self.aws_session_token
        else:
            raise KeyError("No such item '{}' in object".format(items))

    def __repr__(self):
        """Function represent the object"""
        return json.dumps({
            'aws_credentials': self.aws_credentials.__repr__(),
            'aws_access_key': self.aws_access_key,
            'aws_secret_key': self.aws_secret_key,
            'aws_session_token': self.aws_session_token,
            'aws_session_data': json.dumps(self.aws_session_data, indent=4),
            'aws_session_json': self.aws_session_json,
            'aws_cached_filename': self.cached_filename}, indent=4)

    def get_credentials_from_sts(self):
        """Get the assume role credentials from the AWS Security Token Service"""
        sts_client = boto3.client(
            service_name='sts',
            aws_access_key_id=self.aws_credentials['aws_access_key'],
            aws_secret_access_key=self.aws_credentials['aws_secret_key'],
            aws_session_token=self.aws_credentials['aws_session_token'])

        self.aws_session_data = sts_client.assume_role(
            RoleArn=self.role_arn,
            RoleSessionName=self.profile_name)

        self._save_session_token_as_string(self.aws_session_data.copy())

        self.aws_access_key = self.aws_session_data['Credentials'][
            'AccessKeyId']
        self.aws_secret_key = self.aws_session_data['Credentials'][
            'SecretAccessKey']
        self.aws_session_token = self.aws_session_data['Credentials'][
            'SessionToken']

    def get_credentials_from_cache(self):
        """Read the MFA session from a cached file"""
        return super(AWSAssumeRoleCredentials, self).get_credentials_from_cache(
            self.cached_filename)

    def write_ar_session_to_cache(self):
        """Write the assume role session into a cached file"""
        return self.write_session_to_cache(self.cached_filename)

    def write_ar_session_to_credfile(self):
        """Write the assume role session into the AWS configuration files"""
        return self.write_session_to_credfile(
            self.profile_name)

    def write_ar_section_to_awsconfig(self):
        """Write a profile section into the AWS credential file"""
        self._write_section_to_awsconfig(
            new_profile=self.profile_name,
            source_profile=self.aws_credentials['aws_profile'],
            role_arn=self.role_arn,
            region=self.region)

    def get_session(self, region='us-west-2'):
        """Returns a boto3 session with the default of 'region'"""
        if self.aws_access_key and self.aws_secret_key \
            and self.aws_session_token:
            return boto3.session.Session(
                aws_access_key_id=self.aws_access_key,
                aws_secret_access_key=self.aws_secret_key,
                aws_session_token=self.aws_session_token,
                region_name=region)
