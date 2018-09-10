from .web import *
import urllib

class HybridAnalysis(object):
    HOST = 'www.hybrid-analysis.com'
    GET = 'GET'
    POST = 'POST'
    
    SEARCH_HASH = POST
    SEARCH_HASH = '/api/v2/search/hash'
    SEARCH_HASH_PARAMS = ['hash',]
    
    SEARCH_TERMS_METHOD = POST
    SEARCH_TERMS = '/api/v2/search/terms'
    SEARCH_TERMS_PARAMS = ['filename', 'filetype', 'filetype_desc', 'env_id', 
                           'country', 'verdict', 'av_detect', 'tag', 'port', 
                           'host', 'domain', 'url']

    SAMPLE_OVERVIEW_METHOD = GET
    SAMPLE_OVERVIEW = '/api/v2/overview/{sha256}'
    
    SAMPLE_SUMMARY_METHOD = GET
    SAMPLE_SUMMARY = '/api/v2/overview/{sha256}/summary'
    
    SAMPLE_METHOD = GET
    SAMPLE = '/api/v2/overview/{sha256}'

    REPORT_STATE_METHOD = GET
    REPORT_STATE = '/api/v2/report/{report}/state'

    REPORT_SUMMARY_METHOD = GET
    REPORT_SUMMARY = '/api/v2/report/{report}/summary'

    REPORT_FILE_METHOD = GET
    REPORT_FILE = '/api/v2/report/{report}/file/{filetype}'
    REPORT_FILE_TYPES = ["xml", "json", "html", "pdf", "maec", 
                      "stix", "misp", "misp", "openioc", 
                      "bin", "crt", "memory", "pcap",]

    REPORT_SCREENSHOTS_METHOD = GET
    REPORT_SCREENSHOTS = '/api/v2/report/{report}/screenshots'
    REPORT_DROPPED_FILE_METHOD = GET
    REPORT_DROPPED_FILE = '/api/v2/report/{report}/dropped-file-raw/{sha256}'
    REPORT_DROPPED_FILES_METHOD = GET
    REPORT_DROPPED_FILES = '/api/v2/report/{report}/dropped-files'

    FEED_LATEST_METHOD = GET
    FEED_LATEST = '/api/v2/feed/latest'

    def url(self, endpoint):
        return "https://{}/"

    def __init__(self, apikey, proxies={}, headers={}):
        self.apikey = apikey
        self.proxies = proxies
        self.headers = headers
        self.headers['User-Agent'] = 'Falcon Sandbox'
        self.headers['api-key'] = apikey
        self.last_client = None

    def get_url(self, fmt_url, **kargs):
        return fmt_url.format(**kargs)

    def execute(self, url, method=GET, data=None, payload=None, headers={}):
        rsp = None
        if method.lower() == self.POST:
            return req.post(url, data=data, params=payload, headers=headers)
        else:
            return req.post(url, data=data, params=payload)

    SEARCH_HASH = POST
    SEARCH_HASH = '/api/v2/search/hash'
    SEARCH_HASH_PARAMS = ['hash',]
    
    SEARCH_TERMS_METHOD = POST
    SEARCH_TERMS = '/api/v2/search/terms'
    SEARCH_TERMS_PARAMS = ['filename', 'filetype', 'filetype_desc', 'env_id', 
                           'country', 'verdict', 'av_detect', 'tag', 'port', 
                           'host', 'domain', 'url']

    def search_hash(self, file_hash):
        url_fmt = self.SEARCH_HASH
        method = self.SEARCH_HASH_METHOD
        self.last_client = BaseClient(host=self.HOST, port=443, proxies=self.proxies,
                 uri=self.get_url(url_fmt),
                 headers={}, method=method, debug=debug, retrys=3, data={'hash': file_hash})
        return self.last_client.send_request()

    def search_terms(self, **kargs):
        terms = {k:v for k, v in kargs.items() if k in self.SEARCH_TERMS_PARAMS}
        if len(terms) == 0:
            raise Exception("No search terms specified")
        url_fmt = self.SEARCH_TERMS
        method = self.SEARCH_TERMS_METHOD
        self.last_client = BaseClient(host=self.HOST, port=443, proxies=self.proxies,
                 uri=self.get_url(url_fmt),
                 headers={}, method=method, debug=debug, retrys=3, data=terms)
        return self.last_client.send_request()

    def sample_overview(self, sha256, debug=False):
        url_fmt = self.SAMPLE_OVERVIEW
        method = self.SAMPLE_OVERVIEW_METHOD
        self.last_client = BaseClient(host=self.HOST, port=443, proxies=self.proxies,
                 uri=self.get_url(url_fmt, **{'sha256': sha256}),
                 headers={}, method=method, debug=debug, retrys=3)
        return self.last_client.send_request()

    def sample_summary(self, sha256, debug=False):
        url_fmt = self.SAMPLE_SUMMARY
        method = self.SAMPLE_SUMMARY_METHOD
        self.last_client = BaseClient(host=self.HOST, port=443, proxies=self.proxies,
                 uri=self.get_url(url_fmt, **{'sha256': sha256}),
                 headers={}, method=method, debug=debug, retrys=3)
        return self.last_client.send_request()

    def sample(self, sha256, debug=False):
        url_fmt = self.SAMPLE
        method = self.SAMPLE_METHOD
        self.last_client = BaseClient(host=self.HOST, port=443, proxies=self.proxies,
                 uri=self.get_url(url_fmt, **{'sha256': sha256}),
                 headers={}, method=method, debug=debug, retrys=3)
        return self.last_client.send_request()

    def report_state(self, report, debug=False):
        url_fmt = self.REPORT_STATE
        method = self.REPORT_STATE_METHOD
        self.last_client = BaseClient(host=self.HOST, port=443, proxies=self.proxies,
                 uri=self.get_url(url_fmt, **{'report': report}),
                 headers={}, method=method, debug=debug, retrys=3)
        return self.last_client.send_request()

    def report_summary(self, report, debug=False):
        url_fmt = self.REPORT_SUMMARY
        method = self.REPORT_SUMMARY_METHOD
        self.last_client = BaseClient(host=self.HOST, port=443, proxies=self.proxies,
                 uri=self.get_url(url_fmt, **{'report': report}),
                 headers={}, method=method, debug=debug, retrys=3)
        return self.last_client.send_request()

    def report(self, report, filetype='json', debug=False):
        if not filetype in self.REPORT_FILE_TYPES:
            raise Exception("Invalid report type provided")

        url_fmt = self.REPORT_FILE
        method = self.REPORT_FILE_METHOD
        self.last_client = BaseClient(host=self.HOST, port=443, proxies=self.proxies,
                 uri=self.get_url(url_fmt, **{'report': report, 'filetype': filetype}),
                 headers={}, method=method, debug=debug, retrys=3)
        return self.last_client.send_request()

    def dropped_files(self, report, debug=False):
        url_fmt = self.REPORT_DROPPED_FILES
        method = self.REPORT_DROPPED_FILES_METHOD
        self.last_client = BaseClient(host=self.HOST, port=443, proxies=self.proxies,
                 uri=self.get_url(url_fmt, **{'report': report}),
                 headers={}, method=method, debug=debug, retrys=3)
        return self.last_client.send_request()

    def dropped_file(self, report, sha256, debug=False):
        url_fmt = self.REPORT_DROPPED_FILE
        method = self.REPORT_DROPPED_FILE_METHOD
        self.last_client = BaseClient(host=self.HOST, port=443, proxies=self.proxies,
                 uri=self.get_url(url_fmt, **{'report': report, 'sha256': sha256}),
                 headers={}, method=method, debug=debug, retrys=3)
        return self.last_client.send_request()

    def screenshots(self, report, debug=False):
        url_fmt = self.REPORT_SCREENSHOTS
        method = self.REPORT_SCREENSHOTS_METHOD
        self.last_client = BaseClient(host=self.HOST, port=443, proxies=self.proxies,
                 uri=self.get_url(url_fmt, **{'report': report}),
                 headers={}, method=method, debug=debug, retrys=3)
        return self.last_client.send_request()

    def feed(self, debug=False):
        url_fmt = self.FEED_LATEST
        method = self.FEED_LATEST_METHOD
        self.last_client = BaseClient(host=self.HOST, port=443, proxies=self.proxies,
                 uri=self.get_url(url_fmt),
                 headers={}, method=method, debug=debug, retrys=3)
        return self.last_client.send_request()

