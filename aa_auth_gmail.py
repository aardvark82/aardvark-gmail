from __future__ import print_function

import aa_credentials
import aa_flask_cache
import aa_globals
import aa_loggers
import httplib2
from flask import session
from googleapiclient import discovery
import oauth2client
########### Settings import for different environments ##########
from settings.settings import *

if isProduction():
    from settings.settings_prod import *
elif isStaging():
    from settings.settings_staging import *
elif isStagingNew():
    from settings.settings_staging_static import *
else:
    isDevelopment()
    from settings.settings_dev import *
###################################################################

cache = aa_flask_cache.getCacheObject()

log = aa_loggers.logging.getLogger(__name__)
######################################################################
######################  PUBLIC METHODS  ##############################
######################################################################


class AuthGoogle():

    def testAuthCredentials(self):
        http, service = self.get_or_refresh_token('plus')
        if service:
            person = service.people().get(userId='me').execute()
            name = person['displayName']
            print('testAuthCredentials - name = ' + name)

        http, service = self.get_or_refresh_token('gmail')
        if service:
            results = service.users().getProfile(userId='me').execute()
            email = results["emailAddress"]
            print('testAuthCredentials - email = ' + email)

        http, service = self.get_or_refresh_token('admin')
        if service:
            results = service.users().list(customer='my_customer', maxResults=500,
                                           orderBy='email').execute()
            users = results.get('users', [])

            if not users:
                print('testAuthCredentials - No users in the domain.')
            else:
                print('testAuthCredentials - Users:')
                for user in users:
                    print('{0} ({1})'.format(user['primaryEmail'],
                                             user['name']['fullName']))

    def AuthRefreshCredentialsIfNeeded(self, credentials, g_service, http):
        if credentials.access_token_expired:
            credentials.refresh(httplib2.Http())
            if isinstance(credentials, oauth2client.client.OAuth2Credentials):
                session['credentials'] = credentials.to_json()

        service = None

        # list of ALL available API's
        # https://developers.google.com/api-client-library/python/apis/

        # knowledge graph API https://developers.google.com/api-client-library/python/apis/kgsearch/v1
        # google + APi https://developers.google.com/+/web/api/rest/
        # gmail API https://developers.google.com/api-client-library/python/apis/gmail/v1

        # cache discover = False gets rids of annoying console Log errors
        if g_service == 'people':
            service = discovery.build(serviceName='people', version='v1', credentials=credentials,
                                      http=http, cache_discovery=False)

        if g_service == 'gmail':
            service = discovery.build(serviceName='gmail', version='v1', credentials=credentials,
                                      cache_discovery=False)

        if g_service == 'admin':
            service = discovery.build(serviceName='admin', version='directory_v1', credentials=credentials,
                                      cache_discovery=False)

        return credentials, service

    def get_or_refresh_token(self, g_service):
        ''' if http is not None, we just refreshed it '''
        http = None
        service = None
        credentials = aa_credentials.loadAPIAuthGoogleCredentialsFromFlaskSession()
        # if not credentials: @ may 2019 doesn't make sense
        # http = credentials.authorize(httplib2.Http())
        # now = datetime.datetime.utcnow()
        # print('Access token expires in ' + str(credentials.token_expiry - now))
        if not credentials:
            credentials = aa_credentials.get_provider_token_from_db(provider='google')

        if credentials:
            try:
                credentials, service = self.AuthRefreshCredentialsIfNeeded(credentials, g_service, http=http)

            except oauth2client.client.HttpAccessTokenRefreshError as e:
                log.warning(e)

        return http, service

    def AuthRetrieveUserScopes(self):
        ''' returns list (array) of scopes, transforms from set to array for serialization'''
        scopes = None
        credentials = aa_credentials.loadAPIAuthGoogleCredentialsFromFlaskSession()
        if credentials:
            scopes = list(credentials.scopes)

        return scopes

    @cache.memoize(timeout=30)
    def AuthGetUserEmail(self):
        """
        Gets valid name_first, Name_lst using the People API
        Jan 2019 - Google + API deprecated - switched to people API instead
        - see https://developers.google.com/+/mobile/android/api-deprecation
        uses the People API
        SETUP https://developers.google.com/people/v1/getting-started
        DOCUMENTATION https://developers.google.com/people/v1/read-people !! JAN 2019 !!
        ERROR - missing get(resourceName='people/me', personFields='names,emailAddresses') instead of get('people/me'...
        SAMPLE https://developers.google.com/people/quickstart/python
        '''
        """
        email = None

        try:

            http, people_service = self.get_or_refresh_token('people')
            if (people_service):
                profile = people_service.people().get(resourceName='people/me',
                                                      personFields='names,emailAddresses').execute()
                if (profile.get('emailAddresses')):
                    for email_addr in profile.get('emailAddresses'):  # detect primary address
                        if email_addr.get('metadata'):
                            if email_addr.get('metadata').get('primary') is True:
                                email = email_addr.get('value')
                                break
                else:
                    print("Error - AuthGetUserEmail  email not found")

            # # the Legacy gmail way # requires addtl suerinfo permissions
            # http, service = self.AuthGetCredentials('gmail')
            # email = 'undefined'
            # if (service):
            #     request = service.users().getProfile(userId='me')
            #     results = request.execute()
            #     email = results["emailAddress"]

        except Exception as exc:
            print("Exception - AuthGetUserEmail  Exception code:", exc)

        return email

    @cache.memoize(timeout=30)
    def AuthGetUserName(self):
        """
        Gets valid name_first, Name_lst using the People API
        Jan 2019 - Google + API deprecated - switched to people API instead
        - see https://developers.google.com/+/mobile/android/api-deprecation
        uses the Google People API

        PEOPLE API FIELDS: https://developers.google.com/people/api/rest/v1/people/get
        """
        if aa_globals.aaIsDemo():
            return "AntEater", "Demo"

        name = None
        name_first = name
        name_last = name

        try:
            # get email
            http, people_service = self.get_or_refresh_token('people')
            if (people_service):
                profile = people_service.people().get(resourceName='people/me',
                                                      personFields='names,emailAddresses').execute()
                if (profile.get('names')):
                    for name_lst in profile.get('names'):  # detect primary address
                        if name_lst.get('metadata'):
                            if name_lst.get('metadata').get('primary') is True:
                                name_first = name_lst.get('givenName')
                                name_last = name_lst.get('familyName')
                                break
                else:
                    name_first = name
                    name_last = name

        except Exception as exc:
            print("Exception - AuthGetUserName  Exception code:", exc)

        return name_first, name_last

    def AuthGetContactsForUser(self):  # TODO contacts
        ''' users the People API https://developers.google.com/people/v1/read-people'''
        ''' TODO unused for now - created for future use '''
        connections = None
        try:
            # get email
            http, people_service = self.get_or_refresh_token('people')
            if (people_service):
                connections = people_service.people().connections().list('people/me',
                                                                         personFields='names,emailAddresses')
            else:
                print("Error - AuthGetContactsForUser  People API not authorized")

        except Exception as exc:
            print("Exception - AuthGetContactsForUser  Exception code:", exc)

        return connections

    @cache.memoize(timeout=30)
    def AuthGetCurrentProfilePictureForUser(self):
        ''' previously used Google plus API - deprecated Jan 2019
         now uses Google People API '''
        if aa_globals.aaIsDemo():
            return MAINLOGO_REMOTE

        url = None
        try:
            # get email
            http, people_service = self.get_or_refresh_token('people')
            if (people_service):
                profile = people_service.people().get(resourceName='people/me', personFields='photos').execute()
                if (profile.get('photos')):
                    for url_lst in profile.get('photos'):  # detect primary address
                        if url_lst.get('metadata'):
                            if url_lst.get('metadata').get('primary') is True:
                                url = url_lst.get('url')
                                break
                else:
                    url = None

            else:
                print('ERROR - AuthGetCurrentProfilePictureForUserAPI not authorized')

        except Exception as exc:
            print("Exception - AuthGetCurrentProfilePictureForUser  Exception code:", exc)

        return url

    # Sample JSON response for user list
    # {'kind': 'admin#directory#user', 'id': '115590473097591392320',
    #  'etag': '"cCp_kEtRu66enfbKyanZyrFQNAw/IvDoKFnl4EXX94XRp_jUcGm1Sg8"',
    #  'primaryEmail': 'admin@exodusvisa.com',
    #  'name': {'givenName': 'Admin', 'familyName': 'Domain', 'fullName': 'Admin Domain'}, 'isAdmin': True,
    #  'isDelegatedAdmin': False, 'lastLoginTime': '2017-12-13T07:40:56.000Z',
    #  'creationTime': '2017-12-09T03:29:46.000Z', 'agreedToTerms': True, 'suspended': False,
    #  'changePasswordAtNextLogin': False, 'ipWhitelisted': False,
    #  'emails': [{'address': 'admin@exodusvisa.com', 'primary': True}],
    #  'externalIds': [{'value': '', 'type': 'organization'}], 'organizations': [
    #     {'title': '', 'primary': True, 'customType': '', 'department': '', 'description': '',
    #      'costCenter': ''}], 'customerId': 'C04itfrdi', 'orgUnitPath': '/', 'isMailboxSetup': True,
    #  'isEnrolledIn2Sv': True, 'isEnforcedIn2Sv': False, 'includeInGlobalAddressList': True}

    def AuthGetUsersAdminsJsonFromAPI(self):

        http, service = self.get_or_refresh_token('admin')
        users = None

        if service:
            results = service.users().list(customer='my_customer', maxResults=500,
                                           orderBy='email').execute()
            users = results.get('users', [])

        return users

    @cache.memoize(timeout=30)
    def AuthGetAllUsersAndAdmins(self):

        users = self.AuthGetUsersAdminsJsonFromAPI()

        res = []
        for user in users:
            if user['isAdmin'] == 'true':
                role = 'admin'
            else:
                role = 'user'

            res.append({'id': user['id'],
                        'name': user['name']['fullName'],
                        'first_name': user['name']['givenName'],
                        'last_name': user['name']['familyName'],
                        'email': user['primaryEmail'],
                        'team': (user.get('organizations')[0].get('department') if user.get(
                            'organizations') else "Not defined"),
                        'role': role})

        return res

    @cache.memoize(timeout=30)
    def AuthGetAllAdmins(self):

        users = self.AuthGetUsersAdminsJsonFromAPI()

        res = []
        for user in users:
            if (user['isAdmin']):
                role = 'admin'
                res.append({'id': user['id'],
                            'name': user['name']['fullName'],
                            'first_name': user['name']['givenName'],
                            'last_name': user['name']['familyName'],
                            'email': user['primaryEmail'],
                            'team': (user.get('organizations')[0].get('department') if user.get(
                                'organizations') else "Not defined"),
                            'role': role})

            return res

    @cache.memoize(timeout=30)
    def AuthGetAllUsers(self):
        users = self.AuthGetUsersAdminsJsonFromAPI()

        res = []
        for user in users:
            if (not user['isAdmin']):
                role = 'user'
                res.append({'id': user['id'],
                            'name': user['name']['fullName'],
                            'first_name': user['name']['givenName'],
                            'last_name': user['name']['familyName'],
                            'email': user['primaryEmail'],
                            'team': (user.get('organizations')[0].get('department') if user.get(
                                'organizations') else "Not defined"),
                            'role': role})

        return res

    @cache.memoize(timeout=30)
    def AuthIsUserAdmin(self, email):
        ''' Check if account is G Suite admin'''
        users = self.AuthGetUsersAdminsJsonFromAPI()

        res = False
        for user in users:
            if user['primaryEmail'] == email:
                res = user['isAdmin']

        return res
