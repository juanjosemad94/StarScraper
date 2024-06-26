import os
import datetime
import logging
import scrapy, re
from dotenv import load_dotenv, find_dotenv
from scrapy.crawler import CrawlerRunner
from twisted.internet import reactor
import urllib.parse
import dateutil.relativedelta
import os
from datetime import datetime
from azure.identity import ClientSecretCredential
from azure.keyvault.secrets import SecretClient
from azure.storage.blob import BlobServiceClient
from azure.core.exceptions import HttpResponseError
import logging
from scrapy.spidermiddlewares.httperror import HttpError
from twisted.internet.error import DNSLookupError
from twisted.internet.error import TimeoutError
from scrapy.utils.project import get_project_settings
from scrapy.utils.log import configure_logging


_ = load_dotenv(find_dotenv ())

class SHPStarRating(scrapy.Spider):

    name = 'SHPStaRatingSpider'
    keyVaultName = os.environ['_vaultName']
    KVUri = f"https://{keyVaultName}.vault.azure.net/"
    _username =None
    _password = None
    connection_string = None
    container_name =  os.environ["star_containername"]                                           
    response_for_keys = None
    report_date = None

     # Define a method to start requests
    def errback(self, failure):
        # log all errback failures
        self.logger.error(repr(failure))
        # you can also check the type of the failure and do different actions
        if failure.check(HttpError):
            # you can get the response
            response = failure.value.response
            self.logger.error('HttpError on %s', response.url)
        elif failure.check(DNSLookupError):
            # this is the original request
            request = failure.request
            self.logger.error('DNSLookupError on %s', request.url)
        elif failure.check(TimeoutError):
            request = failure.request
            self.logger.error('TimeoutError on %s', request.url)


    def __init__(self , shp_rolling_period = 1, **kwargs):

        self.logger.info("__init__ function called for rolling period {}".format(shp_rolling_period))
        self.shp_rolling_period = shp_rolling_period
        _credential = ClientSecretCredential(os.environ["_tenant_id"], os.environ["_client_id"], os.environ["_client_secret"])
        client = SecretClient(vault_url=self.KVUri , credential=_credential)
        self.connection_string = client.get_secret("azure-storage-connection-string").value
        self._user_name = client.get_secret("secret-shp-user-name").value
        self._password = client.get_secret("secret-user-password").value
        super ().__init__ (**kwargs)
        

    def _get_headers(self):
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, '
                          'like Gecko) Chrome/113.0.0.0 Safari/537.36',
            'Accept-Language': 'en-US,en;q=0.9',
            'Upgrade-Insecure-Requests': '1',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,'
                      '*/*;q=0.8,application/signed-exchange;v=b3;q=0.7'
        }
        return headers
    

    def _get_cookies(self, response):
        dict_cookies = dict()
        try:
            cookies = response.headers.getlist('Set-Cookie')
            if cookies:
                cookie_str = re.findall(r"b'\s*([\s\S]*?);", str(cookies))
                for _cookie in cookie_str:
                    cookie_name_value = _cookie.split('=')
                    if cookie_name_value and len(cookie_name_value) > 1:
                        if not cookie_name_value[0] in dict_cookies:
                            dict_cookies[cookie_name_value[0]] = cookie_name_value[1]
        except Exception as err:
            self.logger.error(repr(err))
            cookies = ''
        return dict_cookies

    def start_requests(self):
        self.logger.info("start_requests method called")
        url = 'https://identity.shpdata.com/Account/Login'
        headers = self._get_headers()
        request = scrapy.Request(method='GET', url=url, callback=self._create_request_for_enter_email,
                                 headers=headers, errback=self.errback)
        yield request

    # Request for Enter Email id
    def _create_request_for_enter_email(self, response):
        self.logger.info('_create_request_for_enter_email function called on %s', response.url)
        url = 'https://identity.shpdata.com/Account/EnterEmail'
        headers = self._get_headers()
        headers.update({'Content-Type': 'application/x-www-form-urlencoded'})
        _verification_token = re.findall(r'name="__RequestVerificationToken"[\s\S]*?value="([\s\S]*?)"', response.text)
        if not _verification_token:
            raise Exception('Verification token not found in the response.')
        post_data = f'ReturnUrl=&Username={urllib.parse.quote(self._user_name)}' \
                    f'&__RequestVerificationToken={_verification_token[0]}'
        request = scrapy.Request(method='POST', url=url, body=post_data,
                                 callback=self._create_request_for_login_with_credentials, headers=headers, errback=self.errback)
        yield request

    # Request for Enter credentials
    def _create_request_for_login_with_credentials(self, response):
        self.logger.info('_create_request_for_login_with_credentials function called on %s', response.url)
        url = 'https://identity.shpdata.com/Account/Login'
        headers = self._get_headers()
        headers.update({'Content-Type': 'application/x-www-form-urlencoded'})
        _verification_token = re.findall(r'name="__RequestVerificationToken"[\s\S]*?value="([\s\S]*?)"', response.text)
        if not _verification_token:
            raise Exception('Verification token not found in the response.')
        post_data = f'ReturnUrl=&Username={urllib.parse.quote(self._user_name)}' \
                    f'&Password={urllib.parse.quote(self._password)}&button=login' \
                    f'&__RequestVerificationToken={_verification_token[0]}'
        request = scrapy.Request(method='POST', url=url, body=post_data,
                                 callback=self._create_request_for_back_to_secure, headers=headers, errback=self.errback)
        yield request

    # Back to Secure request
    def _create_request_for_back_to_secure(self, response):
        self.logger.info('_create_request_for_back_to_secure function called on %s', response.url)
        url = 'https://identity.shpdata.com/Profile/BackToSecure'
        headers = self._get_headers()
        headers.update({'Content-Type': 'application/x-www-form-urlencoded'})
        request = scrapy.Request(method='GET', url=url, callback=self._create_secure_request,
                                 headers=headers)
        request.meta['handle_httpstatus_list'] = [301, 302]
        yield request

    # This request is required to generate cookies.
    def _create_secure_request(self, response):
        self.logger.info('_create_secure_request function called on %s', response.url)
        url = response.headers.get('Location').decode('utf-8')
        print("url : {0}".format(url))
        headers = self._get_headers()
        headers.update({'Content-Type': 'application/x-www-form-urlencoded'})
        request = scrapy.Request(method='GET', url=url, callback=self._create_request_for_authorize_client,
                                 headers=headers)
        request.meta['handle_httpstatus_list'] = [301, 302]
        yield request

    # Getting cookies from previous hit and assigning in this request to authorize the client.
    def _create_request_for_authorize_client(self, response):
        self.logger.info('_create_request_for_authorize_client function called on %s', response.url)
        cookies = self._get_cookies(response)
        url = response.headers.get('Location').decode('utf-8')
        headers = self._get_headers()
        headers.update({'Content-Type': 'application/x-www-form-urlencoded'})
        request = scrapy.Request(method='GET', url=url, callback=self._create_request_for_signin_callback_request,
                                 headers=headers, errback=self.errback)
        # Assigning Cookies here
        request.cookies = cookies
        yield request

    # Signin callback request to validate the session
    def _create_request_for_signin_callback_request(self, response):
        self.logger.info('_create_request_for_signin_callback_request function called on %s', response.url)
        url = 'https://secure.shpdata.com/signin-callback.aspx'
        headers = self._get_headers()
        headers.update({'Content-Type': 'application/x-www-form-urlencoded'})
        _token = re.findall(r'name=\'id_token\'\s*value=\'([\s\S]*?)\'', response.text)
        _state = re.findall(r'name=\'state\'\s*value=\'([\s\S]*?)\'', response.text)
        _session_state = re.findall(r'name=\'session_state\'\s*value=\'([\s\S]*?)\'', response.text)
        if not _token or not _state or not _session_state:
            raise Exception('id_token/state/session_state not found in the response.')
        post_data = f'id_token={_token[0]}&scope=openid+profile+id.custom+email' \
                    f'&state={_state[0].replace("&#x2B;", "+")}&session_state={_session_state[0]}'
        request = scrapy.Request(method='POST', url=url, body=post_data,
                                 callback=self._create_request_for_enterprise_selection, headers=headers, errback=self.errback)
        yield request

    # Request for select enterprise name
    def _create_request_for_enterprise_selection(self, response):
        self.logger.info('_create_request_for_enterprise_selection function called on %s', response.url)
        url = response.url
        headers = self._get_headers()
        headers.update({'Content-Type': 'application/x-www-form-urlencoded'})
        _viewstate = re.findall(r'id="__VIEWSTATE"\s*value="([\s\S]*?)"', response.text)
        _viewstategenerator = re.findall(r'id="__VIEWSTATEGENERATOR"\s*value="([\s\S]*?)"', response.text)
        _eventvalidation = re.findall(r'id="__EVENTVALIDATION"\s*value="([\s\S]*?)"', response.text)
        if not _viewstate or not _viewstategenerator or not _eventvalidation:
            raise Exception('_viewstate/_viewstategenerator/_eventvalidation not found in the response.')
        post_data = f'__EVENTTARGET=&__EVENTARGUMENT=&__VIEWSTATE={urllib.parse.quote(_viewstate[0])}' \
                    f'&__VIEWSTATEGENERATOR={_viewstategenerator[0]}' \
                    f'&__EVENTVALIDATION={urllib.parse.quote(_eventvalidation[0])}' \
                    f'&ctl00%24ctl00%24hidAccordionIndex=&ctl00%24ctl00%24hidWelcome=true&ctl00%24ctl00%24ctl01%24ddEnterprises=2829&ctl00%24ctl00%24ctl01%24chkDefault=on&ctl00%24ctl00%24ctl01%24btnOk=Continue&ctl00%24ctl00%24ctl00%24phone=6152828586&ctl00%24ctl00%24ctl00%24phoneExt=&ctl00%24ctl00%24ctl00%24job=Architect'
        request = scrapy.Request(method='POST', url=url, body=post_data,
                                 callback=self._create_request_for_star_rating_review, headers=headers,
                                 dont_filter=True, errback=self.errback)
        yield request

    # Request to Click on star rating review report
    def _create_request_for_star_rating_review(self, response):
        self.logger.info('_create_request_for_star_rating_review function called on %s', response.url)
        # report_id 327 is for Star Ratings Preview report
        _url = 'https://secure.shpdata.com/reports/reportselectcriteria.aspx?mrr=0&reportNo=327'
        headers = self._get_headers()
        request = scrapy.Request(method='GET', url=_url, callback=self._create_request_for_override_reporting_period,
                                 headers=headers, dont_filter=True, errback=self.errback)
        yield request

    # Request to Override Reporting Period dates with custom settings
    def _create_request_for_override_reporting_period(self, response):
        self.logger.info('_create_request_for_override_reporting_period function called on %s', response.url)
        # report_id 327 is for Star Ratings Preview report
        _url = 'https://secure.shpdata.com/reports/reportselectcriteria.aspx?mrr=0&reportNo=327'
        headers = self._get_headers()
        headers.update({'Content-Type': 'application/x-www-form-urlencoded'})
        #reporting period selection
        post_data = self.get_post_data_for_override_reporting_period(response, 'Batch+CCN')
        request = scrapy.Request(method='POST', url=_url, body=post_data,
                                 callback=self._request_for_click_on_view_on_web, headers=headers, dont_filter=True, errback=self.errback)
        
        yield request

    def get_post_data_for_override_reporting_period(self, response, group_or_batch):
        self.logger.info('get_post_data_for_override_reporting_period function called on %s', response.url)
        regex = r'ContentPlaceHolder1_NestedContent1_reportCriteria_RadScriptManager1_TSM&amp;compress=1&amp;' \
                r'_TSM_CombinedScripts_=([\s\S]*?)"'
        reportcriteria_radscripts = re.findall(regex, response.text)
        _viewstate = re.findall(r'id="__VIEWSTATE"\s*value="([\s\S]*?)"', response.text)
        _viewstategenerator = re.findall(r'id="__VIEWSTATEGENERATOR"\s*value="([\s\S]*?)"', response.text)
        _eventvalidation = re.findall(r'id="__EVENTVALIDATION"\s*value="([\s\S]*?)"', response.text)
        checked_index = re.findall(r'"checkedIndexes":\s*(\[[\s\S]*?\])', response.text)
        if reportcriteria_radscripts:
            regex = r'id="__SCROLLPOSITIONY"\s*value="(\d+)"'
            scroll_position_y = re.findall(regex, response.text)
            # id "navId_Reports_Report_327" is for Star Ratings Preview report
            post_data = 'ContentPlaceHolder1_NestedContent1_reportCriteria_RadScriptManager1_TSM=%s' \
                        '&__EVENTTARGET=ctl00$ctl00$ContentPlaceHolder1$NestedContent1$reportCriteria$ctl16$chkOverride' \
                        '&__EVENTARGUMENT=&__LASTFOCUS=&__VIEWSTATE=%s&__VIEWSTATEGENERATOR=%s&__SCROLLPOSITIONX=0' \
                        '&__SCROLLPOSITIONY=%s&__EVENTVALIDATION=%s&ctl00%%24ctl00%%24hidAccordionIndex=' \
                        'navId_Reports_Report_327&ctl00%%24ctl00%%24hidWelcome=true&ctl00%%24ctl00%%24ctl00%%24phone=' \
                        '6152828586&ctl00%%24ctl00%%24ctl00%%24phoneExt=&ctl00%%24ctl00%%24ctl00%%24job=Architect&ctl00%%24ctl00%%24ContentPlaceHolder1%%24NestedContent1%%24reportCriteria%%24NLevelSelector%%24NLevelSelector1%%24NLevelSelectorViewMode=2&ctl00%%24ctl00%%24ContentPlaceHolder1%%24NestedContent1%%24reportCriteria%%24NLevelSelector%%24NLevelSelector1%%24customSelectionApplied=false&ctl00%%24ctl00%%24ContentPlaceHolder1%%24NestedContent1%%24reportCriteria%%24NLevelSelector%%24NLevelSelector1%%24advancedScrollTop=&ctl00%%24ctl00%%24ContentPlaceHolder1%%24NestedContent1%%24reportCriteria%%24NLevelSelector%%24NLevelSelector1%%24ddBasicViewLevel=Enterprise&ctl00_ctl00_ContentPlaceHolder1_NestedContent1_reportCriteria_NLevelSelector_NLevelSelector1_ddBasicViewLevel_ClientState=&ctl00%%24ctl00%%24ContentPlaceHolder1%%24NestedContent1%%24reportCriteria%%24NLevelSelector%%24NLevelSelector1%%24ddBasicViewLevelMember=Compassus+Home+Health&ctl00_ctl00_ContentPlaceHolder1_NestedContent1_reportCriteria_NLevelSelector_NLevelSelector1_ddBasicViewLevelMember_ClientState=&ttHierarchyView_ClientState=%%7B%%22expandedNodes%%22%%3A%%5B%%5D%%2C%%22collapsedNodes%%22%%3A%%5B%%5D%%2C%%22logEntries%%22%%3A%%5B%%5D%%2C%%22selectedNodes%%22%%3A%%5B%%5D%%2C%%22checkedNodes%%22%%3A%s%%2C%%22scrollPosition%%22%%3A0%%7D&ctl00%%24ctl00%%24ContentPlaceHolder1%%24NestedContent1%%24reportCriteria%%24ctl16%%24ddCMS=50&ctl00%%24ctl00%%24ContentPlaceHolder1%%24NestedContent1%%24reportCriteria%%24ctl16%%24chkOverride=on&ctl00%%24ctl00%%24ContentPlaceHolder1%%24NestedContent1%%24reportCriteria%%24dd_PayerType=Match+CMS&ctl00%%24ctl00%%24ContentPlaceHolder1%%24NestedContent1%%24reportCriteria%%24dd_GroupOrBatch=%s' \
                        % (reportcriteria_radscripts[0], urllib.parse.quote(_viewstate[0]),
                           _viewstategenerator[0], scroll_position_y[0], urllib.parse.quote(_eventvalidation[0]),
                           urllib.parse.quote(checked_index[0]), group_or_batch)
            return post_data
        else:
            raise Exception('Regex failed for Reporting period dropdown selection.')

    # Click on "View On Web" button in order to generate report
    def _request_for_click_on_view_on_web(self, response):
        self.logger.info('_request_for_click_on_view_on_web function called on %s', response.url)
        self.response_for_keys = response
        # report_id 327 is for Star Ratings Preview report
        _url = 'https://secure.shpdata.com/reports/reportselectcriteria.aspx?mrr=0&reportNo=327'
        headers = self._get_headers()
        headers.update({'Content-Type': 'application/x-www-form-urlencoded'})
        post_data = self._get_post_data_for_click_on_view_on_web(response, 'Batch+CCN')
        request = scrapy.Request(method='POST', url=_url, body=post_data, callback=self._create_request_for_popup_page,
                                 headers=headers, dont_filter=True, errback=self.errback)
        yield request

    def _get_post_data_for_click_on_view_on_web(self, response, group_or_batch):
        self.logger.info('_get_post_data_for_click_on_view_on_web function called on %s', response.url)
        regex = r'ContentPlaceHolder1_NestedContent1_reportCriteria_RadScriptManager1_TSM&amp;compress=1&amp;' \
                r'_TSM_CombinedScripts_=([\s\S]*?)"'
        reportcriteria_radscripts = re.findall(regex, response.text)
        _viewstate = re.findall(r'id="__VIEWSTATE"\s*value="([\s\S]*?)"', response.text)
        _viewstategenerator = re.findall(r'id="__VIEWSTATEGENERATOR"\s*value="([\s\S]*?)"', response.text)
        _eventvalidation = re.findall(r'id="__EVENTVALIDATION"\s*value="([\s\S]*?)"', response.text)
        checked_index = re.findall(r'"checkedIndexes":\s*(\[[\s\S]*?\])', response.text)
        regex = r'id="ContentPlaceHolder1_NestedContent1_reportCriteria_ctl16_ddOverrideDatesOutcomesProcMeasuresTo"' \
                r'[\s\S]*?</select>'
        select_override_dates_dropdown = re.findall(regex, response.text)
        dates = re.findall(r'value\s*=\s*"(\d+/\d+/\d+)"', select_override_dates_dropdown[0])
        #need modification here 
        formated_new_date = self.getDateForShpPeriod()
        date_to_be_update = None
        for date in dates:
            if date == formated_new_date:
                date_to_be_update = date
                break
        if not date_to_be_update:
            raise Exception('DC/TRF Date not found. Please check the logic.')
        date_to_be_update = urllib.parse.quote_plus(date_to_be_update)
        self.report_date = date_to_be_update

        if reportcriteria_radscripts:
            regex = r'id="__SCROLLPOSITIONY"\s*value="(\d+)"'
            scroll_position_y = re.findall(regex, response.text)
            # id "navId_Reports_Report_327" is for Star Ratings Preview report
            post_data = 'ContentPlaceHolder1_NestedContent1_reportCriteria_RadScriptManager1_TSM=%s&__EVENTTARGET=' \
                        '&__EVENTARGUMENT=&__LASTFOCUS=&__VIEWSTATE=%s&__VIEWSTATEGENERATOR=%s&__SCROLLPOSITIONX=0' \
                        '&__SCROLLPOSITIONY=%s&__EVENTVALIDATION=%s&ctl00%%24ctl00%%24hidAccordionIndex=' \
                        'navId_Reports_Report_327&ctl00%%24ctl00%%24hidWelcome=true&ctl00%%24ctl00%%24ctl00%%' \
                        '24phone=6152828586&ctl00%%24ctl00%%24ctl00%%24phoneExt=&ctl00%%24ctl00%%24ctl00%%24job=Architect&ctl00%%24ctl00%%24ContentPlaceHolder1%%24NestedContent1%%24reportCriteria%%24NLevelSelector%%24NLevelSelector1%%24NLevelSelectorViewMode=2&ctl00%%24ctl00%%24ContentPlaceHolder1%%24NestedContent1%%24reportCriteria%%24NLevelSelector%%24NLevelSelector1%%24customSelectionApplied=false&ctl00%%24ctl00%%24ContentPlaceHolder1%%24NestedContent1%%24reportCriteria%%24NLevelSelector%%24NLevelSelector1%%24advancedScrollTop=&ctl00%%24ctl00%%24ContentPlaceHolder1%%24NestedContent1%%24reportCriteria%%24NLevelSelector%%24NLevelSelector1%%24ddBasicViewLevel=Enterprise&ctl00_ctl00_ContentPlaceHolder1_NestedContent1_reportCriteria_NLevelSelector_NLevelSelector1_ddBasicViewLevel_ClientState=&ctl00%%24ctl00%%24ContentPlaceHolder1%%24NestedContent1%%24reportCriteria%%24NLevelSelector%%24NLevelSelector1%%24ddBasicViewLevelMember=Compassus+Home+Health&ctl00_ctl00_ContentPlaceHolder1_NestedContent1_reportCriteria_NLevelSelector_NLevelSelector1_ddBasicViewLevelMember_ClientState=&ttHierarchyView_ClientState=%%7B%%22expandedNodes%%22%%3A%%5B%%5D%%2C%%22collapsedNodes%%22%%3A%%5B%%5D%%2C%%22logEntries%%22%%3A%%5B%%5D%%2C%%22selectedNodes%%22%%3A%%5B%%5D%%2C%%22checkedNodes%%22%%3A%s%%2C%%22scrollPosition%%22%%3A0%%7D&ctl00%%24ctl00%%24ContentPlaceHolder1%%24NestedContent1%%24reportCriteria%%24ctl16%%24chkOverride=on&ctl00%%24ctl00%%24ContentPlaceHolder1%%24NestedContent1%%24reportCriteria%%24ctl16%%24' \
                        'ddOverrideDatesOutcomesProcMeasuresFrom=%s' \
                        '&ctl00%%24ctl00%%24ContentPlaceHolder1%%24NestedContent1%%24reportCriteria%%24ctl16%%24' \
                        'ddOverrideDatesOutcomesProcMeasuresTo=%s' \
                        '&ctl00%%24ctl00%%24ContentPlaceHolder1%%24NestedContent1%%24reportCriteria%%24ctl16%%24' \
                        'ddOverrideDatesUtilizationOutcomesFrom=%s' \
                        '&ctl00%%24ctl00%%24ContentPlaceHolder1%%24NestedContent1%%24reportCriteria%%24ctl16%%24' \
                        'ddOverrideDatesUtilizationOutcomesTo=%s' \
                        '&ctl00%%24ctl00%%24ContentPlaceHolder1%%24NestedContent1%%24reportCriteria%%24' \
                        'dd_PayerType=Match+CMS&ctl00%%24ctl00%%24ContentPlaceHolder1%%24NestedContent1%%24reportCriteria%%24dd_GroupOrBatch=%s&ctl00%%24ctl00%%24ContentPlaceHolder1%%24NestedContent1%%24reportCriteria%%24btnSubmitHTML2=View+on+Web' \
                        % (reportcriteria_radscripts[0], urllib.parse.quote(_viewstate[0]),
                           _viewstategenerator[0], scroll_position_y[0], urllib.parse.quote(_eventvalidation[0]),
                           urllib.parse.quote(checked_index[0]), date_to_be_update, date_to_be_update,
                           date_to_be_update, date_to_be_update, group_or_batch)
            return post_data
        else:
            raise Exception('Regex failed for Reporting period dropdown selection.')

    def getDateForShpPeriod(self):
        #4,5,6,7,8,9, 10, 11,12, 13 ,14, 15,16 default 4
        current_date = datetime.strptime(f'{datetime.now().strftime("%Y-%m")}-1', "%Y-%m-%d")
        new_date = current_date - dateutil.relativedelta.relativedelta(months=self.shp_rolling_period + 3)
        formated_new_date = f'{new_date.month}/{new_date.day}/{new_date.year}'
        return formated_new_date

    # request for popup page to generate excel report
    def _create_request_for_popup_page(self, response):
        self.logger.info('_create_request_for_popup_page function called on %s', response.url)
        shiz_keys = re.findall(r'popReport\(\)\s*\{\s*window\.open\(\'[a-zA-Z0-9\?.=&]+=([\s\S]*?)&', response.text)
        # report_id 327 is for Star Ratings Preview report
        _url = f'https://secure.shpdata.com/reports/DynamicReportViewer.aspx?reportId=327&shiz={shiz_keys[0]}' \
               f'&format=html'
        headers = self._get_headers()
        request = scrapy.Request(method='GET', url=_url, callback=self._create_request_to_download_excel_file,
                                 headers=headers, dont_filter=True, errback=self.errback)
        yield request

    # request to download excel report
    def _create_request_to_download_excel_file(self, response):
        self.logger.info('_create_request_to_download_excel_file function called on %s', response.url)
        export_urls = re.findall(r'"ExportUrlBase":"([\s\S]*?)"', response.text)
        export_url = export_urls[0].replace("\\u0026", "&")
        _url = f'https://secure.shpdata.com{export_url}EXCELOPENXML'
        headers = self._get_headers()
        request = scrapy.Request(method='GET', url=_url, callback=self._save_excel_file_with_Batch_CCN_group,
                                 headers=headers, dont_filter=True, errback=self.errback)
        yield request

    

    def _save_excel_file_with_Batch_CCN_group(self, response):
        self.logger.info('_save_excel_file_with_Batch_CCN_group function called on %s', response.url)
        blob_Service_Client = BlobServiceClient.from_connection_string(self.connection_string)
        #Blob_Service_Client = BlobServiceClient(account_url=account_url, credential=shared_access_key)
        container_client = blob_Service_Client.get_container_client(container= self.container_name)
        blob_client = container_client.get_blob_client("StarRatingsPreview_with_Batch_CCN.xlsx")
        try :
            if blob_client.exists():
                blob_client = blob_client.delete_blob(delete_snapshots='include')
             
        except Exception as err:
            logging.error(str(err))

            pass  
        blob_client = container_client.upload_blob(name = "StarRatingsPreview_with_Batch_CCN.xlsx", data = response.body) 
 
        # Making request for batch provider group
        # report_id 327 is for Star Ratings Preview report
        _url = 'https://secure.shpdata.com/reports/reportselectcriteria.aspx?mrr=0&reportNo=327'
        headers = self._get_headers()
        headers.update({'Content-Type': 'application/x-www-form-urlencoded'})
        post_data = self._get_post_data_for_click_on_view_on_web(self.response_for_keys, 'Batch+Provider')
        request = scrapy.Request(method='POST', url=_url, body=post_data,
                                 callback=self._create_request_for_popup_page_for_batch_provider, headers=headers,
                                 dont_filter=True)
        yield request

    # request for popup page to generate excel report for Batch Provider
    def _create_request_for_popup_page_for_batch_provider(self, response):
        self.logger.info('_create_request_for_popup_page_for_batch_provider function called on %s', response.url)
        shiz_keys = re.findall(r'popReport\(\)\s*\{\s*window\.open\(\'[a-zA-Z0-9\?.=&]+=([\s\S]*?)&', response.text)
        # report_id 327 is for Star Ratings Preview report
        _url = f'https://secure.shpdata.com/reports/DynamicReportViewer.aspx?reportId=327&shiz={shiz_keys[0]}' \
               f'&format=html'
        headers = self._get_headers()
        request = scrapy.Request(method='GET', url=_url,
                                 callback=self._create_request_to_download_excel_file_for_batch_provider,
                                 headers=headers, dont_filter=True, errback=self.errback)
        yield request

    # request to download excel report for Batch Provider
    def _create_request_to_download_excel_file_for_batch_provider(self, response):
        self.logger.info('_create_request_to_download_excel_file_for_batch_provider function called on %s', response.url)
        export_urls = re.findall(r'"ExportUrlBase":"([\s\S]*?)"', response.text)
        export_url = export_urls[0].replace("\\u0026", "&")
        _url = f'https://secure.shpdata.com{export_url}EXCELOPENXML'
        headers = self._get_headers()
        request = scrapy.Request(method='GET', url=_url, callback=self._save_excel_file_with_Batch_Provider_group,
                                 headers=headers, dont_filter=True, errback=self.errback)
        
        yield request

    
    def _save_excel_file_with_Batch_Provider_group(self, response):
       
        
        blob_Service_Client = BlobServiceClient.from_connection_string(self.connection_string)
        container_client = blob_Service_Client.get_container_client(container = self.container_name)
        blob_client = container_client.get_blob_client("StarRatingsPreview_with_Batch_Provider.xlsx")
        try:
            if blob_client.exists():
                del_blob_resp = blob_client.delete_blob(delete_snapshots='include')
        except HttpResponseError as err:
            pass
        blob_client = container_client.upload_blob(name = "StarRatingsPreview_with_Batch_Provider.xlsx", data = response.body) 
        

        if blob_client is not None:
            logging.info ("file has been uploaded")
        else:
            logging.error ("upload failed for StarRatingsPreview_with_Batch_Provider.xlsx")  


# Function to run the spider
def run_ratingSpider():
    configure_logging ()
    runner = CrawlerRunner(get_project_settings())
    d = runner.crawl(SHPStarRating, shp_rolling_period=1)
    d.addBoth(lambda _: reactor.stop())
    reactor.run()

if __name__ == '__main__':
        from multiprocessing import Process
        process = Process(target=run_ratingSpider)
        process.start()
        process.join()
        logging.info("SHP Star rating complted")

