from tarfile import TarFile
from gzip import GzipFile
from zipfile import ZipFile

from pymongo import MongoClient
import investigate
import yaml

from . import malshare

from virus_total_apis import IntelApi, PublicApi, PrivateApi

from .hybridanalysis import HybridAnalysis

# class reads a zip and extracts content in memory
class ReadCompressed(object):

    @classmethod
    def zip_contents(cls, zipfile_name, passwd=None, names=None):
        results = {}
        zf = ZipFile(zipfile_name)
        if names is None:
            names = zf.namelist()

        if isinstance(passwd, str):
            passwd =  bytes(passwd.encode('utf8'))

        for n in names:
            results[n] = zf.read(n, pwd=passwd)
        return results

    @classmethod
    def gzip_contents(cls, gz_filename):
        results = {}
        gzf = GzipFile(gz_filename)

        results[gz_filename] = gzf.read()
        return results


    @classmethod
    def tar_contents(cls, tarfile_name, passwd=None, names=None):
        results = {}
        tf = TarFile(tarfile_name)
        if names is None:
            names = tf.getnames()

        for n in names:
            results[n] = tf.extractfile(n).read()
        return results

class GetInterface(object):
    MALSHARE = 'malshare'
    MONGO = 'pymongo'
    HOST = 'host'
    PORT = 'port'
    IVG = 'pyinvestigate'
    API_KEY = 'apikey'

    VTAPI = 'vtapi'
    PRIVATE = 'private'
    PUBLIC = 'public'
    INTEL = 'intel'

    HYBRID_ANALYSIS = 'hybridanalysis'


    def __init__(self, config_file):
        self.my_config = yaml.load(open(config_file))

    def get_ivg(self):
        block = self.IVG
        config_dict = self.my_config.get(block, None)
        if config_dict is None:
            raise Exception("Missing %s config" % block)

        apikey = config_dict.get(self.API_KEY)
        return investigate.Investigate(apikey)

    def get_mongo_connection(self):
        block = self.IVG
        config_dict = self.my_config.get(block, None)
        if config_dict is None:
            raise Exception("Missing %s config" % block)

        host = config_dict.get(self.HOST)
        port = config_dict.get(self.PORT)
       
        return  MongoClient(host=host, port=port)

    def get_mongo_db(self, db):
        conn = self.get_mongo_connection()
        return conn[db]

    def get_mongo_collection(self, db, collection):
        conn = self.get_mongo_connection()
        return conn[db][collection]
    
    def get_malshare(self):
        block = self.MALSHARE
        config_dict = self.my_config.get(block, None)
        if config_dict is None:
            raise Exception("Missing %s config" % block)

        apikey = config_dict.get(self.API_KEY)
        return malshare.Malshare(apikey)


    def get_private_vt(self):
        block = self.VTAPI
        config_dict = self.my_config.get(block, None)
        if config_dict is None:
            raise Exception("Missing %s config" % block)

        if self.PRIVATE in config_dict and \
           config_dict.get(self.PRIVATE, False): 
            apikey = config_dict.get(self.API_KEY)
            return PrivateApi(apikey)

        raise Exception("Unable to instantiate PrivateApi for VT")            

    def get_intel_vt(self):
        block = self.VTAPI
        config_dict = self.my_config.get(block, None)
        if config_dict is None:
            raise Exception("Missing %s config" % block)

        if self.INTEL in config_dict and \
           config_dict.get(self.INTEL, False):
            apikey = config_dict.get(self.API_KEY) 
            return IntelApi(apikey)
    
        raise Exception("Unable to instantiate IntelApi for VT")            

    def get_public_vt(self):
        block = self.VTAPI
        config_dict = self.my_config.get(block, None)
        if config_dict is None:
            raise Exception("Missing %s config" % block)

        apikey = config_dict.get(self.API_KEY)
        return PublicApi(apikey)

    def get_hybrid_analysis(self):
        block = self.HYBRID_ANALYSIS
        config_dict = self.my_config.get(block, None)
        if config_dict is None:
            raise Exception("Missing %s config" % block)

        apikey = config_dict.get(self.API_KEY)
        return HybridAnalysis(apikey)