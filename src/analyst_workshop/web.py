import json
from http.cookiejar import CookieJar 
from urllib.parse import urlparse, urlencode
from datetime import datetime, timedelta
from requests import Request, Session
from requests.auth import HTTPBasicAuth


class Proxies(object):
    HTTP_HOST = "http_host"
    HTTP_PORT = "http_port"

    HTTPS_HOST = "https_host"
    HTTPS_PORT = "https_port"

    DFLT_HTTP_PORT = 3128
    DFLT_HTTP_HOST = "127.0.0.1"
    DFLT_HTTPS_PORT = 3128
    DFLT_HTTPS_HOST = "127.0.0.1"

    def __init__(self, http_host=None, http_port=DFLT_HTTP_PORT,
                 https_host=None, https_port=DFLT_HTTP_PORT):
        self.proxies = {}
        if not http_host is None:
            self.proxies['http'] = 'http://{}:{}'.format(http_host, http_port)
        if not https_host is None:
            self.proxies['https'] = 'https://{}:{}'.format(https_host, https_port)


class WebResponse(object):

    def __init__(self, http_req, http_response, cookies=None, **kwargs):
        self.http_request = http_req
        self.http_response = http_response
        self.data = {}
        self.jar = cookies if cookies is not None else CookieJar()

        self.json = {}
        self.text = getattr(http_response, 'text', '') if http_response is not None else ''
        self.raw = None
        # note the function call here
        self.json = None
        try:
            self.json = getattr(http_response, 'json', dict)() if http_response is not None else {}
        except:
            pass
        json_str = kwargs.get('json_str', None)
        if not json_str is None:
            d = json.loads(json_str)
            self.json.update(d)
            self.content = self.json
        else:
            self.raw = http_response.content
            self.content = self.raw

        # json_dict = kwargs.get('json_dict', {})
        # try:
        #     self.json.update(json_dict)
        # except:
        #     pass


    def get_param(self, key):
        return self.json.get(key, None)

    def get_content(self):
        return self.content

    def get_raw(self):
        if self.raw is None:
            return json.dumps(self.json)
        return self.raw


class BaseClient(object):

    URL_FMT = "{prefix}://{host}:{port}{uri}"

    def __init__(self, host='127.0.0.1', port=80, proxies={},
                 uri='/', auth_type=None,
                 content_type='application/json', user=None, token=None,
                 cookies=None, headers={}, method='GET', debug=False,
                 param=None, data=None, prefix="https", retrys=3):
        self.retrys = retrys
        self.debug = debug
        self.user = user
        self.token = token
        self.auth_type = auth_type
        self.port = port
        self.host = host
        self.prefix = prefix
        self.proxies = proxies
        self.content_type = content_type
        self.uri = uri
        self.cookies = cookies
        self.headers = headers
        self.headers['Content-Type'] = content_type
        self.method = method
        self.jar = cookies if cookies is not None else CookieJar()
        self.response = None
        self.data = data
        self.params = param

    def get_proxies(self):
        return self.proxies.copy()

    def get_headers(self):
        return self.headers.copy()

    def get_cookies(self):
        return self.cookies

    def get_auth(self):
        if self.user is None or self.token is None:
            return None
        if self.auth_type == 'basic':
            return HTTPBasicAuth(self.user, self.token)
        return None

    def get_url(self):
        d = {'prefix': self.prefix, 'host': self.host,
             'port': self.port, 'uri': self.uri}
        return self.URL_FMT.format(**d)

    def send_request(self):
        self.last_req = Request(self.method, self.get_url(),
                                params=self.params,
                                data=self.data, headers=self.get_headers(),
                                cookies=self.get_cookies(),
                                auth=self.get_auth())

        session = Session()
        req_prepped = self.last_req.prepare()
        cnt = 0
        self.last_response = None

        while True:
            try:
                if self.debug:
                    self.pretty_print_req(req_prepped)

                self.last_response = session.send(req_prepped,
                                                  proxies=self.get_proxies(),
                                                  verify=False)
                break
            except:
                if cnt >= self.retrys:
                    raise
                cnt += 1

        json_data = getattr(self.last_response, 'json', None)
        web_response = WebResponse(self.last_req,
                                   self.last_response,
                                   json_data=json_data)
        return web_response

    def emit_curl(self):
        cmdp = {}
        cmdp['user_token'] = ''
        auth = self.get_auth()
        if auth is not None:
            cmdp['user_token'] = '-u "%s:%s"' % (auth.username, auth.password)
        cmdp['content_type'] = ''
        if self.content_type is not None:
            cmdp['content_type'] = '-H "Content-Type: %s"' % self.content_type
        cmdp['method'] = "-X %s" % self.method
        url_parts = list(urlparse.urlparse(self.get_url()))
        if self.params is not None:
            url_parts[4] = urlencode(self.params)
        cmdp['url'] = '"%s"' % urlparse.urlunparse(url_parts)
        cmdp['data'] = ""
        if self.data is not None:
            cmdp['data'] = '--data "%s"' % urlencode(self.data)

        cmd = "curl {method} {content_type} {user_token} {url} {data}"
        return cmd.format(**cmdp).strip()
