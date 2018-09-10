from .web import *
import urllib

class Malshare(object):
    HOST = 'malshare.com'
    TYPES = ['pe32', 'pe64', 'pe32+', 'elf', 'composite', 'html', 'zip', 'java' ]
    GETLIST = "/api.php?api_key={apikey}&action=getlist"
    GETSRCS = "/api.php?api_key={apikey}&action=getsources"
    GETFILE = "/api.php?api_key={apikey}&action=getfile&hash={hash}"
    DETAILS = "/api.php?api_key={apikey}&action=details&hash={hash}"
    FTYPES =  "/api.php?api_key={apikey}&&action=type&type={ftype}"
    SEARCH =  "/search.php?query={query}"

    GET = 'get'
    POST = 'post'

    def url(self, endpoint):
        return "https://{}/"

    def __init__(self, apikey, proxies={}, headers={}):
        self.apikey = apikey
        self.proxies = proxies
        self.headers = headers
        self.last_client = None

    def get_url(self, fmt_url, **kargs):
        kargs['apikey'] = self.apikey
        return fmt_url.format(**kargs)

    def execute(self, url, method=GET, data=None, payload=None, headers={}):
        rsp = None
        if method.lower() == self.POST:
            return req.post(url, data=data, params=payload, headers=headers)
        else:
            return req.post(url, data=data, params=payload)

    def get_list(self, debug=False):
        self.last_client = BaseClient(host=self.HOST, port=443, proxies=self.proxies,
                 uri=self.get_url(self.GETLIST),
                 headers={}, method='GET', debug=debug, retrys=3)
        return self.last_client.send_request()

    def get_sources(self, debug=False):
        self.last_client = BaseClient(host=self.HOST, port=443, proxies=self.proxies,
                 uri=self.get_url(self.GETSRCS),
                 headers={}, method='GET', debug=debug, retrys=3)
        return self.last_client.send_request()

    def get_file(self, filehash, debug=False):
        self.last_client = BaseClient(host=self.HOST, port=443, proxies=self.proxies,
                 uri=self.get_url(self.GETFILE, hash=filehash),
                 headers={}, method='GET', debug=debug, retrys=3)
        return self.last_client.send_request()

    def get_details(self, filehash, debug=False):
        self.last_client = BaseClient(host=self.HOST, port=443, proxies=self.proxies,
                 uri=self.get_url(self.DETAILS, hash=filehash),
                 headers={}, method='GET', debug=debug, retrys=3)
        return self.last_client.send_request()

    def get_search(self, query, debug=False):
        _query = urllib.parse.quote_plus(query)
        self.last_client = BaseClient(host=self.HOST, port=443, proxies=self.proxies,
                 uri=self.get_url(self.SEARCH, query=_query),
                 headers={}, method='GET', debug=debug, retrys=3)
        return self.last_client.send_request()

    def get_ftypes(self, ftype, debug=False):
        if not ftype in self.TYPES:
            raise Exception('Unknown API file type') 
        self.last_client = BaseClient(host=self.HOST, port=443, proxies=self.proxies,
                 uri=self.get_url(self.FTYPES, ftype=ftype),
                 headers={}, method='GET', debug=debug, retrys=3)
        return self.last_client.send_request()
