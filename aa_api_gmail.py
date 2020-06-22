# Ignore code verification added on 2020-02-12 by: Seraphin
# Reason: legacy file, too much work to make it compliant
# flake8: noqa

from __future__ import print_function

import aa_organizations
import aa_users
from flask import session

import time
import dateutil.parser as parser
from datetime import datetime
import datetime

import aa_db

import aa_api_data
import aa_auth_gmail

import aa_globals

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

import aa_loggers

log = aa_loggers.logging.getLogger(__name__)
###################################################################

import aa_helper_methods

import aa_flask_cache
import aa_dataclasses

cache = aa_flask_cache.getCacheObject()

###################################################################

from sentry_sdk import capture_message

NUM_EMAIL_PER_API_BATCH_REQUEST = 100  # needs to be 100 - From https://developers.google.com/gmail/api/guides/batch
# You're limited to 100 calls in a single batch request. If you need to make more calls than that, use multiple batch requests.


NUM_EMAIL_DEBUG_LIMIT = 100  # needs to be > 2x
NUM_EMAIL_FREE_LIMIT = 25000  # needs to be > 2x
NUM_EMAIL_UNLIMITED_LIMIT = 50000  # needs to be > 2x

CACHE_API_GMAIL_SHORT = 5
CACHE_API_GMAIL_STANDARD = 60
CACHE_API_GMAIL_TIMEOUT = 3600 * 24 * 7

######################################################################
######################  PUBLIC METHODS  ##############################
######################################################################

import redis_lock


class ApiGmail(aa_api_data.ApiData):

    def __init__(self):
        _GLOBAL_emails_dic[cacheKey()] = []
        _GLOBAL_contacts_dic[cacheKey()] = []

    def APIgetDataSourceType(self):
        return 'gmail'

    def APIgetLabelNamesForLabelIds(self, label_ids):
        ''' returns a string joined with & '''

        if (label_ids == "All" or not label_ids):
            return "All"

        label_list = aa_globals.getUserCacheValueForKey('labels_dic')  # from gmail API

        if label_list and label_ids:
            labels_id_arr = label_ids.split()
            labels_names = []
            result = ''
            if labels_id_arr:
                for label_id in labels_id_arr:  ## compare each label id to the master list from Google API to retrieve name
                    for label_dict in label_list:
                        if isinstance(label_dict, str):
                            if (label_dict == label_id):
                                labels_names.append(label_dict)
                        else:
                            if (label_dict['id'] == label_id):
                                labels_names.append(label_dict['name'])

            if (label_ids == "aa_sample"):
                return 'JSON SAMPLE DATA'

            return ' & '.join(labels_names)
        else:
            return ''

    def APIgetAllEmails(self):
        ''' convenience method - default to 1 week '''
        date_1 = aa_globals.todayLocalUser() - datetime.timedelta(days=7)
        date_2 = aa_globals.todayLocalUser()

        return self.APIgetAllEmailsForLabelIdAndDatesAndFilter(labelIds='INBOX',
                                                               date_first=date_1.strftime("%Y-%m-%d"),
                                                               date_last=date_2.strftime("%Y-%m-%d"),
                                                               filter_topic="")

    @cache.memoize(timeout=CACHE_API_GMAIL_STANDARD)
    def APIgetAllEmailsForLabelIdAndDatesAndFilterForUser(self, labelIds, date_first, date_last, filter_topic='',
                                                          disable_cache=None, user=None, metadata_limit=0):

        """
        Computes full list for label then calls parseEmail on each email
        RESULT = messages is a tuple email, contacts
        date_first is included
        date_last is included - so we always add 1 day / use end of day for time filtering

        We use a rolling random chunk iteration so that multiple processes complete this faster - e.g. we prepare 13 api chunks, and iterate over the 13 in order 7,4,1,3,5,2,6,8,9,11 etc...
        """
        if True:

            formatted_labels = labelIds.split()
            if (len(formatted_labels) == 1 and formatted_labels[0] == 'ALL_DATA'):
                formatted_labels[0] = ''


            aa_globals.setUserCacheValueForKey("ui_progress_value", 0)
            aa_globals.setUserCacheValueForKey("ui_progress_msg", "Loading conversations...")

            metadata_limit = 0
            # check if custom metadata param (e.g. used by refreshemails)
            if date_first == 'metadata':
                metadata_limit = int(date_last)

            if session.get(
                    'google_scopes_granted') == 'metadata' and metadata_limit == 0:  # 1. metadata permissions, Gmail API query paramter is disabled - use max query indicator
                # 2. we didn't get a request to explicitly fetch xxx number of emails (uses the metadata value for date_first param

                metadata_limit = aa_globals.getUserCacheValueForKey('query_emails')
                if not metadata_limit or int(metadata_limit) < 100:
                    metadata_limit = 100
                    aa_globals.setUserCacheValueForKey('query_emails', '100')



            seconds_first = None
            seconds_last = None


            if not date_first == 'metadata':
                            ## add 1 day to date_last - google needs 'before' + 1 day
                datefirst_from_str = parser.parse(
                    date_first)  # from https://stackoverflow.com/questions/466345/converting-string-into-datetime

                datelast_from_str = parser.parse(
                    date_last)  # from https://stackoverflow.com/questions/466345/converting-string-into-datetime
                datelast_from_str = datelast_from_str + datetime.timedelta(
                    days=1)  # adding 1 day to capture all events until midnight next day - e.g. date_last is always INCLUDED

                # Convert local datetime to UTC timestamp (for google API call)
                # from https://stackoverflow.com/questions/8777753/converting-datetime-date-to-utc-timestamp-in-python
                # !!! date cannot be a UTC object!! must be a locall time object
                import time
                seconds_first = time.mktime(datefirst_from_str.timetuple())
                seconds_last = time.mktime(datelast_from_str.timetuple())

                thisepoch = int(time.time())
                print('API Gmail seconds_first ' + str(seconds_first) + ' seconds_last ' + str(
                    seconds_last) + ' epoch ' + str(thisepoch) + ' seconds_first-epoch ' + str(
                    seconds_first - thisepoch) + ' seconds_last- epoch ' + str(seconds_last - thisepoch))
                print('API Gmail:  (seconds_first-epoch HOURS): ' + str(
                    (seconds_first - thisepoch) / 3600) + ' -- (seconds_last - epoch HOURS) ' + str(
                    (seconds_last - thisepoch) / 3600))


            ##### STEP 1 Computes LIST OF all IDs email from pagination . ########
            email_ids = getListOfEmailsForLabelIdAndDatesAndFilterAndMetaDataLimit(formatted_labels, seconds_first,
                                                                                    seconds_last,
                                                                                    filter_topic, metadata_limit)
            print('getListOfEmailsForLabelIdAndDatesAndFilterAndMetaDataLimit email_list', str(len(email_ids)))

            def chunks(lst, n):
                """Yield successive n-sized chunks from lst."""
                for i in range(0, len(lst), n):
                    yield lst[i:i + n]

            messages_emails = aa_globals.get_emails_for_ids(subset_list=list(chunks(email_ids, 25)))


            try:
                aa_globals.setUserCacheValueForKey("ui_progress_value", 100)
                aa_globals.setUserCacheValueForKey("ui_progress_msg", "")

            except Exception as e:
                print(
                    'Exception APIgetAllEmailsForLabelIdAndDatesAndFilterForUser - no results for messages_emails, messages_contacts',
                    e)

        return messages_emails


    def APIgetAllEmailsForLabelIdAndDatesAndFilter(self, labelIds, date_first, date_last, filter_topic='',
                                                   disable_cache=None):
        return self.APIgetAllEmailsForLabelIdAndDatesAndFilterForUser(labelIds, date_first, date_last,
                                                                      filter_topic=filter_topic,
                                                                      disable_cache=disable_cache,
                                                                      user=aa_users.get_current_user_email())

    def APIgetLabels(self):
        ''' Gmail API returns names for labels but query necessitates to split with -
         Example: id : Label_5, name = Wanderung BC --> query needs Wanderung-BC"
         '''
        API_labels = _getLabelsDictionaryFromGmailAPI()

        res = []
        if API_labels:
            for label in API_labels:
                new_result = {}
                new_result['message_id'] = label.get('id')
                new_result['name'] = label.get('name')
                new_result['id'] = label.get('name').replace(" ", "-")
                new_result['messagesTotal'] = label.get('messagesTotal')
                res.append(new_result)

        return res




###################################################################
#####################  STATIC HELPER METHODS  ###########################
###################################################################


_GLOBAL_emails_dic = {}  # results, global variable, used because of Batch update
_GLOBAL_contacts_dic = {}  # results, global variable, used because of Batch update
_GLOBAL_api_responses = {}


def _dbg_GLOBAL_api_responses():
    return _GLOBAL_api_responses


def _dbg_GLOBAL_api_responses_user_count():
    return str(len(_GLOBAL_api_responses))


def _dbg_GLOBAL_api_responses_total_count():
    api_response_count = 0
    for key in (_GLOBAL_api_responses):
        api_response_count = api_response_count + len(_GLOBAL_api_responses[key])

    return str(api_response_count)


def list_digest(gmail_ids):  ##hash a list of strings
    import hashlib, struct
    hash = hashlib.sha256()
    for id in gmail_ids:
        s = id.get('id')
        hash.update(struct.pack("I", len(s)))
        hash.update(s.encode())
    return hash.hexdigest()


def cacheKey():
    return aa_globals.getCacheUserKey() + '_gmail'


def authorizeUserCredentialsGmailAPI():
    auth_service = aa_auth_gmail.AuthGoogle()
    http, service = auth_service.get_or_refresh_token('gmail')
    return http, service



def _getLabelsDictionaryFromGmailAPI():
    """Shows basic usage of the Gmail API.

    Creates a Gmail API service object and outputs a list of label names
    of the user's Gmail account.
    """

    if session.get('google_scopes_granted') == 'read':

        _labels_list_of_dics = aa_globals.getUserCacheValueForKey('labels_dic')

        if not _labels_list_of_dics:
            _labels_list_of_dics = []

        if (len(_labels_list_of_dics) > 0):  # use cache
            print("API Gmail using Cache for getLabels()")
        else:  # send API request to refresh
            http, service = authorizeUserCredentialsGmailAPI()

            if (service):
                try:
                    request = service.users().labels().list(userId='me')
                    results = request.execute()  # !! results returns an object CONTAINING a dic, not a dic! Inspect in debugger

                except Exception as exc:
                    print(
                        "API Gmail httpRequest ERROR - service.users().labels().list in getLabels. Error:", exc)
                    return '-1'
                all_labels = results.get('labels', [])
                sorted_labels = sorted(all_labels, key=lambda k: k['name'])
                _labels_list_of_dics = sorted_labels

                if not _labels_list_of_dics:
                    print('API Gmail No labels found.')
                else:
                    # save to cache
                    aa_globals.setUserCacheValueForKey('labels_dic', _labels_list_of_dics)
                    print('API Gmail getLabels() Labels count: ' + str(len(_labels_list_of_dics)))
                    batch = service.new_batch_http_request()

                    for label in _labels_list_of_dics:
                        # get number of emails for label
                        # Synchronous, non-batch way


                        # Synchronous, Batch way
                        request = service.users().labels().get(userId='me', id=label['id'])
                        batch.add(request, callback=parseEmailCountForLabelRequest)

                        try:
                            batch.execute(http=http)

                        except Exception as exc:
                            print("httpRequest ERROR - service.users().labels().get in getLabels. Error:", exc)

            else:
                print("API Gmail APIgetLabels() ApiGmail Error - Could not initialize Http object - check credentials")

    _labels_list_of_dics = aa_globals.getUserCacheValueForKey('labels_dic')

    return _labels_list_of_dics


@cache.memoize(timeout=CACHE_API_GMAIL_STANDARD)  # cached with user id
def getListOfEmailsForLabelIdAndDatesAndFilterAndMetaDataLimitForUser(formatted_labels, seconds_first, seconds_last,
                                                                      filter_topic, metadata_limit=0, user=None):
    """
       Creates a Gmail API service object and retrieves a list of all email ids for that label
       ''' if meta_data limit is set and meta data API permission - use this instead of query
       ''' if formatted_labels & seconds defined, and we have read permissions (query enabled in gmail API) then use that instead
       """
    http, service = authorizeUserCredentialsGmailAPI()
    data_messages = []

    if seconds_first and seconds_last:
        if aa_helper_methods.RepresentsFloat(seconds_first):
            seconds_first = int(seconds_first)

        if aa_helper_methods.RepresentsFloat(seconds_last):
            seconds_last = int(seconds_last)

    if service:
        # List email() - initial request - list page 1
        dbg = len(formatted_labels)
        # Filtering through q= query From https://developers.google.com/gmail/api/guides/filtering

        if session.get(
                'google_scopes_granted') == 'read' or session.get(
            'google_scopes_granted') == 'admin':  # metadata permissions, Gmail API query paramter is disabled - use max query indicator

            # use SECONDS not dates!!!
            # From https://developers.google.com/gmail/api/guides/filtering
            # All dates used in the search query are interpretted as midnight on that date in the PST timezone. To specify accurate dates for other timezones pass the value in seconds instead:
            query = 'after:' + str(seconds_first) + ' ' + 'before:' + str(seconds_last)

            if len(filter_topic) > 0:
                query = '"' + filter_topic + '"' + ' ' + query

            if len(formatted_labels) > 0 and len(formatted_labels[0]) > 0 and not formatted_labels[
                                                                                      0] == 'None':  # use label
                # format labels properly for query: https://stackoverflow.com/questions/2050637/appending-the-same-string-to-a-list-of-strings-in-python
                in_list = ['in:' + label for label in formatted_labels]
                # https://www.decalage.info/en/python/print_list
                labels = ' '.join(in_list)
                labels = '{' + labels + '}'  # OR operator gmail - from https://support.google.com/mail/answer/7190?hl=en

                labels = labels + ' AND NOT in:DRAFTS'  # for general
                labels = labels + ' AND NOT in:SPAM'

                query = labels + ' ' + query
        else:
            query = 'metadata-query-unused'

        if session.get(
                'google_scopes_granted') == 'metadata':  # metadata permissions, Gmail API query paramter is disabled - use max query indicator
            print("API Gmail metadatalimit = " + str(metadata_limit))
            user_id = 'me'
            request = service.users().messages().list(userId=user_id,
                                                      maxResults=metadata_limit)

        else:  # read all permissions, Gmail API query parameter is enabled
            print("**** API Gmail Query ***** = " + query)
            user_id = 'me'
            request = service.users().messages().list(userId=user_id,
                                                      maxResults=NUM_EMAIL_PER_API_BATCH_REQUEST,
                                                      q=query)

        api_results = []

        try:
            api_results = request.execute()

        except Exception as exc:
            print("API Gmail Error executing http request service.users().messages().list in getAllEmails with label",
                  formatted_labels, "Exception code:", exc)
            pass

        page_nbr = 0
        resultSizeEstimate = 0

        if 'messages' in api_results:
            data_messages.extend(api_results['messages'])
            page_nbr = 1

        if 'resultSizeEstimate' in api_results:
            resultSizeEstimate = api_results['resultSizeEstimate']

            print("API Gmail resultSizeEstimate with query - ", query, "resultSizeEstimate: ",
                  resultSizeEstimate)

        msg_count = 0
        while (('nextPageToken' in api_results)):
            try:
                page_token = api_results['nextPageToken']

                if session.get('google_scopes_granted') == 'metadata':
                    user_id = 'me'
                    request = service.users().messages().list(userId=user_id,
                                                              pageToken=page_token,
                                                              maxResults=metadata_limit)
                else:
                    user_id = 'me'
                    request = service.users().messages().list(userId=user_id,
                                                              pageToken=page_token,
                                                              q=query)

                api_results = request.execute()

                if api_results and ('messages' in api_results):  # end of calls - empty response
                    msg_count = msg_count + len(api_results['messages'])

                    if session.get('google_scopes_granted') == 'metadata':
                        progress = 100 * ((msg_count) / int(metadata_limit))
                        aa_globals.setUserCacheValueForKey("ui_progress_value", progress)
                        aa_globals.setUserCacheValueForKey("ui_progress_msg", "Loading conversations...")

                        if (msg_count >= int(
                                metadata_limit)):  # metadata goes on and on and on so we need to stop it when we have the right amount of emails
                            break

                    ##gmail readonly - check against user email limit (plan) and use Query
                    data_messages.extend(api_results['messages'])

                page_nbr = page_nbr + 1
                print(str(page_nbr), " of ", str(resultSizeEstimate))
            except Exception as e:
                print("API Gmail Exception in ", str(page_nbr), " of ", str(resultSizeEstimate))

        print("API Gmail Total messages With Pagination: ", str(len(data_messages)), "with permissions:",
              session.get('google_scopes_granted'), " for query:",
              query)

    else:
        print("API Gmail Error: getListOfEmailsForLabelIdAndDates - could not get http object")

    # let's make sure this is sorted and deterministic - let's sort this so that the result is always deterministic
    data_messages = sorted(data_messages, key=lambda k: k['id'])

    return data_messages


# non-cached, need user param
def getListOfEmailsForLabelIdAndDatesAndFilterAndMetaDataLimit(formatted_labels, seconds_first, seconds_last,
                                                               filter_topic, metadata_limit=0):
    return getListOfEmailsForLabelIdAndDatesAndFilterAndMetaDataLimitForUser(formatted_labels, seconds_first,
                                                                             seconds_last,
                                                                             filter_topic, metadata_limit,
                                                                             user=aa_users.get_current_user_id())


number_of_api_request_errors = 0

from aa_sqlalchemy import db, ApiCache
import cbor


@cache.memoize(timeout=CACHE_API_GMAIL_STANDARD)
def get_emails_from_gmail_ids(msg_list):
    """
    Creates a Gmail API service object and retrieves each header for each emails for that list of ids
    ''' we cache API requests to our DB for faster refresh as athe content of a msg id will never change '''
    """

    ''' we have 3(4!) cache levels
    1. We hit our legacy cache (insights_email) currently disabled - can store post-processed emails
    2. We hit our API reponse cache and emulate an API hit 
    3. We hit Gmail API
    For each fo these we have memoize cache enabled at some levels...'''
    key = cacheKey()
    http, service = authorizeUserCredentialsGmailAPI()

    global _GLOBAL_api_responses
    _GLOBAL_api_responses[key] = []

    global _GLOBAL_emails_dic
    _GLOBAL_emails_dic[key] = []
    global _GLOBAL_contacts_dic
    _GLOBAL_contacts_dic[key] = []

    global number_of_api_request_errors  # record errors
    number_of_api_request_errors = 0

    if (service):
        # use global final_list to compute results after batch

        msg_counter = -1

        if True:  # avoid too many concurrent requests per user GMAIL API error

            batch = service.new_batch_http_request()

            for mssg in msg_list:
                msg_counter = msg_counter + 1

                m_id = mssg['id']  # get id of individual message

                result_json = None


                if result_json:  # coming from DB Cache
                    emails_processed = [d['id'] for d in _GLOBAL_emails_dic[key]]
                    result_email = aa_api_data.parse_message_from_google(result_json)
                    if result_email:  # valid email to add/process to our results, can be None if skipContact
                        if not result_email.id in emails_processed:
                            _GLOBAL_emails_dic[key].append(result_email)


                    if (msg_counter % NUM_EMAIL_PER_API_BATCH_REQUEST == 0):
                        print("-API Gmail API processing #", msg_counter, " of ", str(len(msg_list)))

                    api_processed = [d['id'] for d in _GLOBAL_api_responses[key]]
                    if not response.id in api_processed:
                        _GLOBAL_api_responses[key].append(response)
                    else:
                        print('☇', end='', flush=True)
                    continue  # TODO this seems like a bad logic loop - use if, else instead and check cache conditions

                # NO CACHE, fetch with API
                # Linear, single request way
                # temp_dict = parseEmail(m_id)
                # Batch way
                if session.get('google_scopes_granted') == 'metadata':
                    user_id = 'me'
                    request = service.users().messages().get(userId=user_id, id=m_id, format='metadata')
                else:
                    user_id = 'me'
                    request = service.users().messages().get(userId=user_id, id=m_id)

                # let's check our API CACHE
                # use APIcache
                cache_engine = 'gmail' + session.get('google_scopes_granted')
                cached_mem = aa_sqlalchemy.getCacheObjectAPICache(m_id, cache_engine)

                if cached_mem:
                    response = cached_mem
                    _GLOBAL_api_responses[key].append(response)

                else:
                    try:
                        if cache:
                            cache.delete_memoized(aa_sqlalchemy.getCacheObjectAPICache, m_id,
                                                  cache_engine)  # !! important - ensures cache hits
                    except Exception as e:
                        print('Exception - cache.delete_memoized getCacheObjectAPICache', e)
                    # Let's make a gmail API call

                    batch.add(request, callback=parseGmailAPIResultsRequest)
                    if (msg_counter and msg_counter % 500 == 0):
                        print('g', end='', flush=True)
                    if (msg_counter and msg_counter % NUM_EMAIL_PER_API_BATCH_REQUEST == 0):
                        # Google API LIMIT 1000 requests at any one time (as of Sep 2017)
                        batch.execute(http=http)
                        batch = service.new_batch_http_request()

            batch.execute(http=http)


    else:
        print("API Gmail  Error: APIgetHeadersForAllEmailsForMsgList - could not get http object")

    aa_sqlalchemy.proxyCommit()  # commit all emails cached to db

    parseAllEmailAPIResponses()  # do all processing

    messages_emails = sorted(_GLOBAL_emails_dic[key], key=lambda k: k.id)

    return messages_emails





@cache.memoize(timeout=CACHE_API_GMAIL_TIMEOUT)
def parseGmailAPIResultsRequest(request_id, response, exception):
    '''Http request callback'''
    ''' Store all API responses in a set'''
    key = cacheKey()

    if exception is not None:
        print("Httprequest ERROR - parseEmailResultRequest - exception:", exception)
        global number_of_api_request_errors
        number_of_api_request_errors += 1  # Do something with the exception
        pass
    else:
        # store in cache
        m_id = response.get('id')  # get id of individual message

        cache_engine = 'gmail' + session.get('google_scopes_granted')

        aa_sqlalchemy.setCacheObjectAPICache(cache_engine=cache_engine, key=m_id, value=response)

    _GLOBAL_api_responses[key].append(response)

    return True


import aa_sqlalchemy


def parseAllEmailAPIResponses():  # TODO expensive CPU
    ''' Process all API responses once finished receiving API Data
    - parseEmail, parseContact() and split in interactions
     '''
    msg_counter = 0
    key = cacheKey()

    for response in _GLOBAL_api_responses[key]:
        msg_counter = msg_counter + 1
        parsed_message = None
        try:
            parsed_message = aa_api_data.parse_message_from_google(response)
            if parsed_message:
                processInsightsAndStoreInDbIfNeeded(message_internal = parsed_message)

        except Exception as e:
            log.exception(e,exc_info=True)

        # give user feedback
        if (msg_counter and msg_counter % 50 == 0):
            try:
                date_obj = parsed_message.get('DateTime')
                date_rel_str = aa_helper_methods.relativeDateStrForDate(date_obj)

                print('API Gmail Parsing response ', str(msg_counter), 'of ', str(len(_GLOBAL_api_responses[key])))
                aa_globals.setUserCacheValueForKey("ui_progress_msg",
                                                   "Loading conversation from " + date_rel_str + "...")
            except Exception as exc:
                dbg = 1

        aa_sqlalchemy.proxyCommit()


def processInsightsAndStoreInDbIfNeeded(message_internal: aa_dataclasses.MessageInternal) -> None:
    ''' using internal format
    - generate topics, people insights
    - store insights in db if user sharing & privacy settings allow it '''

    key = cacheKey()

    user_id = aa_users.get_current_user_id()
    organization_id = aa_organizations.get_current_organization_id()

    if message_internal and organization_id and user_id:
        try:
            aa_api_data.parse_and_store_insights_from_message(message=message_internal,
                                                               organization_id=organization_id,
                                                               user_id=user_id)

        except Exception as e:
            log.error(e, exc_info=True)

        if message_internal:
            global _GLOBAL_emails_dic
            emails_processed = [d.id for d in _GLOBAL_emails_dic[key]]
            if not message_internal.id in emails_processed:
                _GLOBAL_emails_dic[key].append(message_internal)  # append to global Dictionary of results







@cache.memoize(timeout=CACHE_API_GMAIL_STANDARD)
def parseEmailCountForLabelRequest(request_id, response, exception):
    _labels_list_of_dics = aa_globals.getUserCacheValueForKey('labels_dic')
    if exception is not None:
        # Do something with the exception
        pass
    else:
        label_response = response  # obtaining proper dic
        parsedLabelCount = parseEmailCountForLabel(label_response)

        # updated global dict of labels used for Jinja and add label count
        if (parsedLabelCount):
            dbd_id = label_response['id']
            to_modify = None
            _labels_list_of_dics = aa_globals.getUserCacheValueForKey('labels_dic')

            for l in _labels_list_of_dics:
                if l['id'] == label_response['id']:
                    to_modify = l
                    break
            if (to_modify):
                to_modify['messagesTotal'] = str(parsedLabelCount)
        if (USE_DB_CACHE):
            aa_db.dbLabelUpdate(aa_users.get_current_user_email(), label_response)

        aa_globals.setUserCacheValueForKey('labels_dic', _labels_list_of_dics)


def parseEmailCountForLabel(label):
    return label['messagesTotal']
