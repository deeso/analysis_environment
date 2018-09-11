from pymongo import MongoClient
import json, os, time, signal, threading, sys                          
from datetime import datetime, timedelta
from gglsbl import SafeBrowsingList

from datetime import datetime
from datetime import datetime, timedelta
from virus_total_apis import PrivateApi, PublicApi
import argparse
import sys

URLPARSE = None


try:
    from urllib.parse import urlparse as URLPARSE
except:
    pass

try:
    if URLPARSE is None:
        from urllib2 import urlparse as URLPARSE
except:
    pass

LINUX_DFT_PATH = '/tmp/gsb_4.db'
MIN_NEW_DOMS = 5
NUM_ITERS = 10
MIN_DAYS = 5
MIN_HITS = 4
DFMT = "%Y-%m-%d %H:%M:%S"
CMD_DESC = 'evaluate related domains for badness.'
parser = argparse.ArgumentParser(description=CMD_DESC)
parser.add_argument('-api_key', type=str, default=None,
                    help='api key for virus total')

parser.add_argument('-db_path', type=str, default=LINUX_DFT_PATH,
                    help='api key for virus total')

parser.add_argument('-domain', type=str, default=None,
                    help='domain to evaluate')

parser.add_argument('-url', type=str, default=None,
                    help='url to evaluate')
parser.add_argument('-mongohost', type=str, default=None,
                    help='mongohost to save domains too')

parser.add_argument('-mongoport', type=str, default=27017,
                    help='mongoport to save domains too')

parser.add_argument('-mongodb', type=str, default='google-safe-browsing',
                    help='mongo db')

def save_to_mongo(mongohost, mongoport, mongodb, mongocol, data):
    c = MongoClient(mongohost, mongoport)
    db = c[mongodb]
    col = db[mongocol]
    col.insert_one(data)
    c.close()


SB_CHECK = None
class SafeBrowsing(object):
    def __init__(self, api_key, db_path=LINUX_DFT_PATH, update_hash_prefix_cache=False):
        global API_KEY, DB_PATH
        API_KEY = api_key
        DB_PATH = db_path

        self.sbl = SafeBrowsingList(api_key, db_path=db_path)
        self.update_hash_prefix_cache = update_hash_prefix_cache
        try:
            os.stat(db_path)
        except:
            self.update_hash_prefix_cache = True

        if self.update_hash_prefix_cache:
            # this may take a while so be patient (over 1600MB of data)
            self.sbl.update_hash_prefix_cache()

    def is_blacklisted(self, url):
        return not SafeBrowsing.thread_safe_lookup(url) is None

    def lookup_url(self, url):
        # cp_fmt = '{scheme}://{netloc}/{path}'
        # up = URLPARSE(url)
        # cp = cp_fmt.format(**{'scheme':up.scheme, 'netloc':up.netloc, 'path':up.path}).strip('/')+'/'
        return self.sbl.lookup_url(url)

    @classmethod
    def init(cls, api_key):
        return SafeBrowsing(api_key)
    
    @staticmethod
    def set_global(api_key, db_path='/tmp/gsb_4.db'):
        global SB_CHECK, API_KEY, DB_PATH
        API_KEY = api_key, db_path
        SB_CHECK = SafeBrowsing(api_key, db_path=db_path)

    @staticmethod
    def thread_safe_lookup(url):
        global SB_CHECK
        sbl = SafeBrowsing(API_KEY, db_path=DB_PATH)
        return sbl.lookup_url(url)

      
if __name__ == "__main__":
    args = parser.parse_args()

    api_key = args.api_key
    db_path = args.db_path
    mongohost = args.mongohost
    mongoport = args.mongoport
    mongodb = args.mongodb

    if api_key is None:
        print("Provide a Google SafeBrowsing API Key")
        sys.exit(-1)

    domain = args.domain
    url = args.url
    if domain is None and url is None:
        print("Provide a domain or URL to check")
        sys.exit(-1)

    sb = SafeBrowsing(api_key, db_path=db_path)
    r = None

    if domain is not None:
        r = sb.lookup_url('http://'+domain)
        mds = datetime.now().strftime(DFMT)
        d = {'value': domain, 'date': mds, 'clean': False, 'classifications':[], 'domain':domain}
        print ("[%s] Checked from: http://%s" % (mds, domain))
        if r is None:
            print ("Site appears clean")
            d['clean'] = True
        else:
            print ("Following classifications apply: %s" % "\n".join([str(i) for i in r]))
            d['classifications'] = [str(i) for i in r]

        if mongohost is not None:
            save_to_mongo(mongohost, mongoport, mongodb, 'domains', d)

    elif url is not None:
        r = sb.lookup_url(url)
        mds = datetime.now().strftime(DFMT)
        print ("[%s] Checked from: %s" % (mds, url))
        domain = URLPARSE(url).netloc
        d = {'value': url, 'date': mds, 'clean': False, 'classifications':[], 'domain':domain}
        if r is None:
            print ("Site appears clean")
            d['clean'] = True
        else:
            print ("Following classifications apply: %s" % "\n".join([str(i) for i in r]))
            d['classifications'] = [str(i) for i in r]
        
        if mongohost is not None:
            save_to_mongo(mongohost, mongoport, mongodb, 'urls', d)