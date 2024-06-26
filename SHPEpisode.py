import scrapy, re
from scrapy.utils.log import configure_logging
from scrapy.spidermiddlewares.httperror import HttpError
from twisted.internet.error import DNSLookupError
from twisted.internet.error import TimeoutError
import logging
import datetime
import os, io
import pandas as pd
from dotenv import load_dotenv,find_dotenv
from azure.identity import ClientSecretCredential
from azure.keyvault.secrets import SecretClient
from azure.storage.blob import BlobServiceClient
from scrapy.utils.project import get_project_settings
import urllib.parse


_ = load_dotenv(find_dotenv ())

class SHPEpisode(scrapy.Spider):
    # Give a name to the spider
    name = "SHPEpisodeSpider"
    # Define the start URL and the login credentials
    keyVaultName=os.environ["_vaultName"]
    _container_name = os.environ["episode_containername"]
    KVUri = f"https://{keyVaultName}.vault.azure.net/"
    #credential = DefaultAzureCredential(additionally_allowed_tenants=["*"])
    # Create a service principal credential
    credential = ClientSecretCredential(os.environ["_tenant_id"], os.environ["_client_id"], os.environ["_client_secret"])
    client = SecretClient(vault_url=KVUri , credential=credential)
    _user_name = client.get_secret("secret-shp-user-name").value
    _password = client.get_secret("secret-user-password").value
    _storage_connection_string = client.get_secret("azure-storage-connection-string").value
    logging.info("client credential read")
    
    def __init__(self , fromDate=None, toDate=None, timeDelta=1, **kwargs):
        self.logger.info("__init__ function called ")
        self.fromDate = fromDate
        self.toDate = toDate
        self.timeDelta = timeDelta
        super(SHPEpisode, self).__init__(**kwargs)
    

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

    def start_requests(self):
        # Yield a request to the start URL with a callback method
        _url = 'https://identity.shpdata.com/Account/Login'
        self.logger.info('start_requests function called on %s', _url)
        headers = self._get_headers()
        yield scrapy.Request(url=_url, callback=self._create_request_for_enter_email,headers=headers, errback=self.errback)
    
    
   
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
                                 headers=headers, errback=self.errback)
        request.meta['handle_httpstatus_list'] = [301, 302]
        yield request

    # Getting cookies from previous hit and assigning in this request to authorize the client.
    def _create_request_for_authorize_client(self, response):
        self.logger.info('_create_request_for_authorize_client function called on %s', response.url)
        cookies = self._get_cookies(response)
        _url = response.headers.get('Location').decode('utf-8')
        headers = self._get_headers()
        headers.update({'Content-Type': 'application/x-www-form-urlencoded'})
        request = scrapy.Request(method='GET', url=_url, callback=self._create_request_for_signin_callback_request,
                                 headers=headers)
        # Assigning Cookies here
        request.cookies = cookies
        yield request

    # Signin callback request to validate the session
    def _create_request_for_signin_callback_request(self, response):
        self.logger.info('_create_request_for_signin_callback_request function called on %s', response.url)
        _url = 'https://secure.shpdata.com/signin-callback.aspx'
        headers = self._get_headers()
        headers.update({'Content-Type': 'application/x-www-form-urlencoded'})
        _token = re.findall(r'name=\'id_token\'\s*value=\'([\s\S]*?)\'', response.text)
        _state = re.findall(r'name=\'state\'\s*value=\'([\s\S]*?)\'', response.text)
        _session_state = re.findall(r'name=\'session_state\'\s*value=\'([\s\S]*?)\'', response.text)
        if not _token or not _state or not _session_state:
            raise Exception('id_token/state/session_state not found in the response.')
        post_data = f'id_token={_token[0]}&scope=openid+profile+id.custom+email' \
                    f'&state={_state[0].replace("&#x2B;", "+")}&session_state={_session_state[0]}'
        request = scrapy.Request(method='POST', url=_url, body=post_data,
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
                                 callback=self._create_request_for_report_382, headers=headers,
                                 dont_filter=True,errback=self.errback)
        yield request
    
     # Request to Click on hospitalization episode report
    def _create_request_for_report_382(self, response):
        self.logger.info('_create_request_for_report_382 function called on %s', response.url)
        # report_id 327 is for Star Ratings Preview report
        _url = 'https://secure.shpdata.com/reports/reportselectcriteria.aspx?mrr=0&reportNo=382'
        headers = self._get_headers()
        request = scrapy.Request(method='GET', url=_url, callback=self._create_request_for_provider_selection,
                                 headers=headers, dont_filter=True)
        yield request

    # Define a method to parse the reports page
    def _create_request_for_provider_selection(self, response):
        # Extract the report URL from the response
        self.logger.info('_create_request_for_provider_selection function called on %s', response.url)
        _url = 'https://secure.shpdata.com/reports/reportselectcriteria.aspx?mrr=0&reportNo=382'
        headers = self._get_headers()
        headers.update({'Content-Type': 'application/x-www-form-urlencoded'})
        #reporting period selection
        post_data = self.get_post_data_for_provider_selectiond(response)
        request = scrapy.Request(method='POST', url=_url, body=post_data,
                                 callback=self._request_for_click_on_view_on_web, headers=headers, dont_filter=True, errback=self.errback)
        yield request
        

    def get_post_data_for_provider_selectiond(self, response):
        self.logger.info('get_post_data_for_provider_selectiond function called on %s', response.url)    
        regex = r'ContentPlaceHolder1_NestedContent1_reportCriteria_RadScriptManager1_TSM&amp;compress=1&amp;' \
                r'_TSM_CombinedScripts_=([\s\S]*?)"'
        reportcriteria_radscripts = re.findall(regex, response.text)
        _viewstate = re.findall(r'id="__VIEWSTATE"\s*value="([\s\S]*?)"', response.text)
        _viewstategenerator = re.findall(r'id="__VIEWSTATEGENERATOR"\s*value="([\s\S]*?)"', response.text)
        _eventvalidation = re.findall(r'id="__EVENTVALIDATION"\s*value="([\s\S]*?)"', response.text)
        
        
        if reportcriteria_radscripts:
           
            post_data = 'ContentPlaceHolder1_NestedContent1_reportCriteria_RadScriptManager1_TSM={}' \
                        '&__EVENTTARGET=ctl00%24ctl00%24ContentPlaceHolder1%24NestedContent1%24reportCriteria%24NLevelSelector%24NLevelSelector1%24ddBasicViewLevel' \
                        '&__EVENTARGUMENT=%7B%22Command%22%3A%22Select%22%2C%22Index%22%3A0%7D' \
                        '&__VIEWSTATE={}' \
                        '&__VIEWSTATEGENERATOR={}' \
                        '&__SCROLLPOSITIONX=0' \
                        '&__SCROLLPOSITIONX=0' \
                        '&__EVENTVALIDATION={}' \
                        '&ctl00%24ctl00%24hidAccordionIndex=navId_Reports_Report_382&ctl00%24ctl00%24hidWelcome=true&ctl00%24ctl00%24ctl00%24phone=9199580133&ctl00%24ctl00%24ctl00%24phoneExt=&ctl00%24ctl00%24ctl00%24job=Sr.+Programmer' \
                        '&ctl00%24ctl00%24ContentPlaceHolder1%24NestedContent1%24reportCriteria%24NLevelSelector%24NLevelSelector1%24NLevelSelectorViewMode=1' \
                        '&ctl00%24ctl00%24ContentPlaceHolder1%24NestedContent1%24reportCriteria%24NLevelSelector%24NLevelSelector1%24customSelectionApplied=false' \
                        '&ctl00%24ctl00%24ContentPlaceHolder1%24NestedContent1%24reportCriteria%24NLevelSelector%24NLevelSelector1%24advancedScrollTop=' \
                        '&ctl00%24ctl00%24ContentPlaceHolder1%24NestedContent1%24reportCriteria%24NLevelSelector%24NLevelSelector1%24ddBasicViewLevel= Enterprise' \
                        '&ctl00_ctl00_ContentPlaceHolder1_NestedContent1_reportCriteria_NLevelSelector_NLevelSelector1_ddBasicViewLevel_ClientState=%7B%22logEntries%22%3A%5B%5D%2C%22value%22%3A%221%22%2C%22text%22%3A%22Enterprise%22%2C%22enabled%22%3Atrue%2C%22checkedIndices%22%3A%5B%5D%2C%22checkedItemsTextOverflows%22%3Afalse%7D' \
                        '&ctl00_ctl00_ContentPlaceHolder1_NestedContent1_reportCriteria_NLevelSelector_NLevelSelector1_ddBasicViewLevelMember_ClientState=%7B%22logEntries%22%3A%5B%5D%2C%22value%22%3A%22%22%2C%22text%22%3A%22Please+wait...%22%2C%22enabled%22%3Afalse%2C%22checkedIndices%22%3A%5B%5D%2C%22checkedItemsTextOverflows%22%3Afalse%7D' \
                        '&ttHierarchyView_ClientState=%7B%22expandedNodes%22%3A%5B%5D%2C%22collapsedNodes%22%3A%5B%5D%2C%22logEntries%22%3A%5B%5D%2C%22selectedNodes%22%3A%5B%5D%2C%22checkedNodes%22%3A%5B%220%22%2C%220%3A3%22%2C%220%3A3%3A1%22%2C%220%3A3%3A1%3A0%22%5D%2C%22scrollPosition%22%3A0%7D' \
                        '&ctl00%24ctl00%24ContentPlaceHolder1%24NestedContent1%24reportCriteria%24dd_DateType=3' \
                        '&ctl00%24ctl00%24ContentPlaceHolder1%24NestedContent1%24reportCriteria%24calfrom_StartDate={}' \
                        '&ctl00%24ctl00%24ContentPlaceHolder1%24NestedContent1%24reportCriteria%24calto_EndDate={}' \
                        .format(reportcriteria_radscripts[0], urllib.parse.quote(_viewstate[0]),
                           _viewstategenerator[0], urllib.parse.quote(_eventvalidation[0]),
                           urllib.parse.quote_plus(self.fromDate), urllib.parse.quote_plus(self.toDate))
            
            return post_data
        else:
            raise Exception('Regex failed for Reporting period dropdown selection.')

    def _request_for_click_on_view_on_web(self, response):
        self.logger.info('_request_for_click_on_view_on_web function called on %s', response.url) 
        self.response_for_keys = response
        # reportNo: 382 is for Hospitalization episode report
        _url = 'https://secure.shpdata.com/reports/reportselectcriteria.aspx?mrr=0&reportNo=382'
        headers = self._get_headers()
        headers.update({'Content-Type': 'application/x-www-form-urlencoded'})
        post_data = self._get_post_data_for_click_on_view_on_web(response)
        request = scrapy.Request(method='POST', url=_url, body=post_data, callback=self._create_request_for_popup_page,
                                 headers=headers, dont_filter=True, errback=self.errback)
        yield request

    def _get_post_data_for_click_on_view_on_web(self, response):
        self.logger.info('_get_post_data_for_click_on_view_on_web function called on %s', response.url) 
        regex = r'ContentPlaceHolder1_NestedContent1_reportCriteria_RadScriptManager1_TSM&amp;compress=1&amp;' \
                r'_TSM_CombinedScripts_=([\s\S]*?)"'
        reportcriteria_radscripts = re.findall(regex, response.text)
        _viewstate = re.findall(r'id="__VIEWSTATE"\s*value="([\s\S]*?)"', response.text)
        _viewstategenerator = re.findall(r'id="__VIEWSTATEGENERATOR"\s*value="([\s\S]*?)"', response.text)
        _eventvalidation = re.findall(r'id="__EVENTVALIDATION"\s*value="([\s\S]*?)"', response.text)
      

        if reportcriteria_radscripts:
           
            # id "navId_Reports_Report_327" is for Star Ratings Preview report
            post_data = 'ContentPlaceHolder1_NestedContent1_reportCriteria_RadScriptManager1_TSM={}&__EVENTTARGET=' \
                        '&__EVENTARGUMENT=' \
                        '&__VIEWSTATE={}&__VIEWSTATEGENERATOR={}' \
                        '&__SCROLLPOSITIONX=0&__SCROLLPOSITIONY=0' \
                        '&__EVENTVALIDATION={}' \
                        '&ctl00%24ctl00%24hidAccordionIndex=navId_Reports_Report_382&ctl00%24ctl00%24hidWelcome=true&ctl00%24ctl00%24ctl00%24phone=9199580133&ctl00%24ctl00%24ctl00%24phoneExt=&ctl00%24ctl00%24ctl00%24job=Sr.+Programmer' \
                        '&ctl00%24ctl00%24ContentPlaceHolder1%24NestedContent1%24reportCriteria%24NLevelSelector%24NLevelSelector1%24NLevelSelectorViewMode=1' \
                        '&ctl00%24ctl00%24ContentPlaceHolder1%24NestedContent1%24reportCriteria%24NLevelSelector%24NLevelSelector1%24customSelectionApplied=false' \
                        '&ctl00%24ctl00%24ContentPlaceHolder1%24NestedContent1%24reportCriteria%24NLevelSelector%24NLevelSelector1%24advancedScrollTop=' \
                        '&ctl00%24ctl00%24ContentPlaceHolder1%24NestedContent1%24reportCriteria%24NLevelSelector%24NLevelSelector1%24ddBasicViewLevel=Enterprise' \
                        '&ctl00_ctl00_ContentPlaceHolder1_NestedContent1_reportCriteria_NLevelSelector_NLevelSelector1_ddBasicViewLevel_ClientState=' \
                        '&ctl00%24ctl00%24ContentPlaceHolder1%24NestedContent1%24reportCriteria%24NLevelSelector%24NLevelSelector1%24ddBasicViewLevelMember=Compassus+Home+Health' \
                        '&ctl00_ctl00_ContentPlaceHolder1_NestedContent1_reportCriteria_NLevelSelector_NLevelSelector1_ddBasicViewLevelMember_ClientState:=' \
                        '&ttHierarchyView_ClientState=%7B%22expandedNodes%22%3A%5B%5D%2C%22collapsedNodes%22%3A%5B%5D%2C%22logEntries%22%3A%5B%5D%2C%22selectedNodes%22%3A%5B%5D%2C%22checkedNodes%22%3A%5B%220%22%2C%220%3A0%22%2C%220%3A0%3A0%22%2C%220%3A0%3A0%3A0%22%2C%220%3A0%3A0%3A1%22%2C%220%3A0%3A1%22%2C%220%3A0%3A1%3A0%22%2C%220%3A0%3A1%3A1%22%2C%220%3A1%22%2C%220%3A1%3A0%22%2C%220%3A1%3A0%3A0%22%2C%220%3A1%3A0%3A1%22%2C%220%3A1%3A1%22%2C%220%3A1%3A1%3A0%22%2C%220%3A1%3A2%22%2C%220%3A1%3A2%3A0%22%2C%220%3A1%3A2%3A1%22%2C%220%3A1%3A2%3A2%22%2C%220%3A1%3A2%3A3%22%2C%220%3A2%22%2C%220%3A2%3A0%22%2C%220%3A2%3A0%3A0%22%2C%220%3A2%3A1%22%2C%220%3A2%3A1%3A0%22%2C%220%3A2%3A2%22%2C%220%3A2%3A2%3A0%22%2C%220%3A2%3A3%22%2C%220%3A2%3A3%3A0%22%2C%220%3A2%3A4%22%2C%220%3A2%3A4%3A0%22%2C%220%3A3%22%2C%220%3A3%3A0%22%2C%220%3A3%3A0%3A0%22%2C%220%3A3%3A1%22%2C%220%3A3%3A1%3A0%22%2C%220%3A3%3A1%3A1%22%2C%220%3A3%3A1%3A2%22%2C%220%3A3%3A2%22%2C%220%3A3%3A2%3A0%22%2C%220%3A3%3A2%3A1%22%2C%220%3A3%3A2%3A2%22%2C%220%3A3%3A2%3A3%22%2C%220%3A4%22%2C%220%3A4%3A0%22%2C%220%3A4%3A0%3A0%22%2C%220%3A4%3A1%22%2C%220%3A4%3A1%3A0%22%2C%220%3A4%3A2%22%2C%220%3A4%3A2%3A0%22%2C%220%3A4%3A3%22%2C%220%3A4%3A3%3A0%22%2C%220%3A4%3A4%22%2C%220%3A4%3A4%3A0%22%2C%220%3A4%3A5%22%2C%220%3A4%3A5%3A0%22%2C%220%3A4%3A6%22%2C%220%3A4%3A6%3A0%22%2C%220%3A4%3A6%3A1%22%2C%220%3A5%22%2C%220%3A5%3A0%22%2C%220%3A5%3A0%3A0%22%2C%220%3A5%3A1%22%2C%220%3A5%3A1%3A0%22%2C%220%3A5%3A2%22%2C%220%3A5%3A2%3A0%22%2C%220%3A5%3A2%3A1%22%2C%220%3A5%3A2%3A2%22%2C%220%3A5%3A3%22%2C%220%3A5%3A3%3A0%22%2C%220%3A5%3A3%3A1%22%2C%220%3A5%3A3%3A2%22%2C%220%3A5%3A4%22%2C%220%3A5%3A4%3A0%22%2C%220%3A5%3A4%3A1%22%2C%220%3A6%22%2C%220%3A6%3A0%22%2C%220%3A6%3A0%3A0%22%2C%220%3A6%3A1%22%2C%220%3A6%3A1%3A0%22%5D%2C%22scrollPosition%22%3A0%7D' \
                        '&ctl00%24ctl00%24ContentPlaceHolder1%24NestedContent1%24reportCriteria%24dd_DateType=3' \
                        '&ctl00%24ctl00%24ContentPlaceHolder1%24NestedContent1%24reportCriteria%24calfrom_StartDate={}' \
                        '&ctl00%24ctl00%24ContentPlaceHolder1%24NestedContent1%24reportCriteria%24calto_EndDate={}' \
                        '&ctl00%24ctl00%24ContentPlaceHolder1%24NestedContent1%24reportCriteria%24btnSubmitHTML2=View+on+Web' \
                        .format(reportcriteria_radscripts[0], urllib.parse.quote(_viewstate[0]),
                           _viewstategenerator[0],  urllib.parse.quote(_eventvalidation[0]),
                            urllib.parse.quote_plus(self.fromDate),  urllib.parse.quote_plus(self.toDate))
            
            self.logger.info ("report generated from date -->{} to date -->{}".format(self.fromDate, self.toDate))
            #self.logger.info("Post data {}".format(post_data))
            return post_data
        else:
            raise Exception('Regex failed for Reporting period dropdown selection.')

    # request for popup page to generate excel report
    def _create_request_for_popup_page(self, response):
        self.logger.info('_create_request_for_popup_page function called on %s', response.url) 
        shiz_keys = re.findall(r'popReport\(\)\s*\{\s*window\.open\(\'[a-zA-Z0-9\?.=&]+=([\s\S]*?)&', response.text)
        # report_id 327 is for Star Ratings Preview report
        _url = f'https://secure.shpdata.com/reports/DynamicReportViewer.aspx?reportId=382&shiz={shiz_keys[0]}' \
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
        request = scrapy.Request(method='GET', url=_url, callback=self._save_excel_file,
                                 headers=headers, dont_filter=True, errback=self.errback)
        yield request
    
    def _save_excel_file(self, response):
        self.logger.info('_save_excel_file function called on %s', response.url)
        file_name = "Hospitalization Patient Detail.xlsx"
        current_date = datetime.date.today()
        # Get the current date and format it as YYYYMMDD
        file_date = (current_date - datetime.timedelta(days=self.timeDelta)).strftime("%Y%m%d")

        # Replace the file name with a new name that includes the date
        new_file_name = file_name.replace(".xlsx", f" {file_date}.xlsx")
        blob_Service_Client = BlobServiceClient.from_connection_string(self._storage_connection_string)
        container_client = blob_Service_Client.get_container_client(container=self._container_name)
        
        blob_client = container_client.get_blob_client(new_file_name)
       
        upload_blob_resp = blob_client.upload_blob(data=response.body, overwrite=True)
        if upload_blob_resp is not None:
            self.logger.info ("file has been uploaded")
        else:
            self.logger.info ("upload failed for StarRatingsPreview_with_Batch_Provider.xlsx")  

def combine_output():

    keyVaultName=os.environ["_vaultName"]
    _top_lvlcontainer_name = os.environ["toplevel_container"]
    KVUri = f"https://{keyVaultName}.vault.azure.net/"
    #credential = DefaultAzureCredential(additionally_allowed_tenants=["*"])
    credential = ClientSecretCredential(os.environ["_tenant_id"], os.environ["_client_id"], os.environ["_client_secret"])
    client = SecretClient(vault_url=KVUri , credential=credential)
    
    _storage_connection_string = client.get_secret("azure-storage-connection-string").value

    blob_Service_Client = BlobServiceClient.from_connection_string(_storage_connection_string)
    container_client = blob_Service_Client.get_container_client(container=_top_lvlcontainer_name)
    excel_names = container_client.list_blobs(name_starts_with="/SHP/episode/") 
    
    dfs = []
    for file in excel_names:
        print(file.name)  
        # Download the blob content as bytes using the content_as_bytes method
        blob_client = container_client.get_blob_client(file)
        blob_data_file = blob_client.download_blob().content_as_bytes()

        df= pd.read_excel(blob_data_file, skiprows=1, header=0 )
        dfs.append(df)
        blob_client.delete_blob()

    df = pd.concat(dfs, ignore_index=True)
    # Save the combined dataframe into a new excel file
    file_name = "Hospitalization Patient Detail.xlsx" 
    #file_name = os.path.basename(file_path)
    current_date = datetime.date.today()
        # Get the current date and format it as YYYYMMDD
    file_date = current_date.strftime("%Y%m%d")
     # Replace the file name with a new name that includes the date
    new_file_name = file_name.replace(".xlsx", f" {file_date}.xlsx")

    output = io.BytesIO()
    df.to_excel(output, index=False, sheet_name="Hospitalization Episode Detail")
    xlsx_data = output.getvalue()

    # Upload the bytes object to the blob using the blob client
    container_client.upload_blob(name="SHP/episode" + "/" + new_file_name, data=xlsx_data, overwrite=True)
    
    logging.info ("files merged")


def getPeriodRange():

    current_date = datetime.date.today()
    print ("current_date {}".format(current_date))
    from_StartDate1 = current_date - datetime.timedelta(days=4)
    to_EndDate1 = current_date - datetime.timedelta(days=1)
         # Format the dates as strings
    from_StartDate_Str1 = from_StartDate1.strftime("%m/%d/%Y")
    to_EndDate_str1 = to_EndDate1.strftime("%m/%d/%Y")
        ############
        
    from_StartDate2 = current_date - datetime.timedelta(days=8)
    to_EndDate2 = current_date - datetime.timedelta(days=5)
        # Format the dates as strings
    from_StartDate_Str2 = from_StartDate2.strftime("%m/%d/%Y")
    to_EndDate_str2 = to_EndDate2.strftime("%m/%d/%Y")
    from_StartDate3 = current_date - datetime.timedelta(days=12)
    to_EndDate3 =  current_date - datetime.timedelta(days=9)
        # Format the dates as strings
    from_StartDate_Str3 = from_StartDate3.strftime("%m/%d/%Y")
    to_EndDate_str3 = to_EndDate3.strftime("%m/%d/%Y")
    
    logging.info ("from_StartDate_Str1 {} to_EndDate_str1 {} from_StartDate2 {} to_EndDate_str2 {} from_StartDate_Str3 {} to_EndDate_str3{}".format (from_StartDate_Str1,to_EndDate_str1 \
        ,from_StartDate_Str2,to_EndDate_str2,from_StartDate_Str3,to_EndDate_str3))
    
    return from_StartDate_Str1,to_EndDate_str1,from_StartDate_Str2,to_EndDate_str2,from_StartDate_Str3,to_EndDate_str3

def run_shpEpisode():
        from scrapy.crawler import CrawlerRunner
        from twisted.internet import reactor
        configure_logging () 
        from_StartDate_Str1, to_EndDate_str1, from_StartDate_Str2, to_EndDate_str2, from_StartDate_Str3, to_EndDate_str3 = getPeriodRange()
        runner = CrawlerRunner(get_project_settings()

        )
        runner.crawl(SHPEpisode, from_StartDate_Str1, to_EndDate_str1, 4)
        runner.crawl(SHPEpisode, from_StartDate_Str2, to_EndDate_str2, 8)
        runner.crawl(SHPEpisode, from_StartDate_Str3, to_EndDate_str3,12)
        d = runner.join()
        d.addBoth(lambda _: reactor.stop())
        reactor.run()


if __name__ == '__main__':
        from multiprocessing import Process
        process = Process(target=run_shpEpisode)
        process.start()
        process.join()
        combine_output()
        
        logging.info ("scraping completed for patient episode report")