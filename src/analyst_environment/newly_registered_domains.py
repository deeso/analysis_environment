LINUX_DFT_PATH = '/tmp/domains.txt'
MIN_NEW_DOMS = 5
NUM_ITERS = 10
MIN_DAYS = 5
MIN_HITS = 4
DFMT = "%Y-%m-%d"
CMD_DESC = 'evaluate related domains for badness.'
NRD_URL_FMT = "https://whoisds.com//whois-database/newly-registered-domains/{date}.zip/nrd"


class DownloadNewlyRegistered(object):

    def __init__(self, get_interface, output_path=LINUX_DFT_PATH, start_date=None, days=0):
        self.start_date = datetime.now().strftime(DFMT) if start_date is None else start_date
        self.days = days
        self.output_path = output_path

        self.domain_names = {}
        self.downloaded = False
        self.mongo_client = get_interface.get_mongo_connection()

    def save_to_mongo(self, data, mongodb=None, mongocol=None):
        if self.mongo_client is None:
            return
        c = self.mongo_client
        db = c[self.mongodb] if mongodb is None else c[mongodb]
        col = db[self.mongocol] if mongocol is None else c[mongocol]
        col.insert_one(data)

    @classmethod    
    def create_url(cls, date):
        dt = date.strftime(DFMT)
        return NRD_URL_FMT.format(**{"date":dt}) 

    @classmethod
    def extract_zip_content(cls, data):
        fd = BytesIO(data)
        zf = ZipFile(fd)
        name = zf.namelist()[0]
        domains = zf.read(name).decode('ascii').split()
        date = name.split('.')[0]
        return date, domains

    @classmethod
    def download_file_extract(cls, url):
        rsp = requests.get(url)
        if rsp.status_code == 200:
            data = rsp.content
            try:
                return cls.extract_zip_content(data)
            except:
                pass
        return None, None

    def perform_file_downloads(self, mongodb='nrd', mongocol='new_domains'):
        if self.days == 0:
            self.days = 1
        day = 0
        start = datetime.strptime(self.start_date, DFMT)
        results = {}
        while day < self.days:
            if (start + timedelta(days=day)) > datetime.now():
                break
            url = self.create_url(start + timedelta(days=day))
            date, domains = self.download_file_extract(url)
            if date is not None:
                self.domain_names[date] = domains
                data = {'date': date, 'domains': domains}
                self.save_to_mongo(data, mongodb=mongodb, mongocol=mongocol)
            day += 1
        self.downloaded = True
        return self.domain_names

    def download_and_write_domains(self, mongodb='nrd', 
                                   mongocol='new_domains', 
                                   output_file=None):
        self.perform_file_downloads(mongodb=mongodb, mongocol=mongocol)
        self.perform_write_domains(output_file=output_file)
        return self.domain_names

    def write_domains(self, output_file=None):
        output_file = self.output_file if output_file is None else output_file
        if not self.downloaded:
        keys = sorted(self.domain_names.keys())
        with open(output_file, 'w') as out: 
            for k in keys:
                d = ["%s,%s" % (k, v) for v in self.domain_names[k]]
                out.write('\n'.join(d))
        return self.domain_names