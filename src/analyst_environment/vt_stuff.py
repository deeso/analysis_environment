import socket
from datetime import datetime
from datetime import datetime, timedelta
import sys


MIN_NEW_DOMS = 5
NUM_ITERS = 10

MIN_DAYS = 5
MIN_HITS = 4
DFMT = "%Y-%m-%d %H:%M:%S"
BASE_DATE = datetime.now()

class VTPivots(object):

    def __init__(self, get_interface, min_days=MIN_DAYS, 
                 min_hits=MIN_HITS, mongodb='vt-default-db', 
                 mongocol='domain-lookup', base_date=BASE_DATE, 
                 use_public=True, num_iters=NUM_ITERS, 
                 min_new_doms=MIN_NEW_DOMS, max_domain_pivots=100):

        self.vt = get_interface.get_public_vt()
        if not use_public:
            self.vt = get_interface.get_private_vt()

        self.max_domain_pivots = max_domain_pivots
        self.ivg = get_interface.get_ivg()
        self.update_date(base_date=base_date, min_days=min_days)
        self.mongo_client = get_interface.get_mongo_connection()
        self.min_hits = min_hits
        self.base_date = base_date
        self.min_date = self.base_date - timedelta(days=self.min_days)
        self.mongodb = mongodb
        self.mongocol = mongocol

    def update_date(self, base_date=None, min_days=None):
        if isinstance(base_date, str):
            base_date = datetime.strptime(base_date, DFMT)

        if not base_date is None:
            self.base_date = base_date

        if not min_days is None:
            self.min_days = min_days

        self.min_date = self.base_date - timedelta(days=self.min_days)
        return self.min_date


    def save_to_mongo(self, data, mongodb=None, mongocol=None):
        if self.mongo_client is None:
            return
        c = self.mongo_client
        db = c[self.mongodb] if mongodb is None else c[mongodb]
        col = db[self.mongocol] if mongocol is None else db[mongocol]
        try:
            col.insert_one(data)
        except:
            pass


    def domain_lookups(self, domains):
        if isinstance(domains, str):
            domains = [domains,]

        subdomain_info = {}
        accumulate_subs = set()
        for domain in domains:
            print ("Looking up %s in VirusTotal"%domain)
            di = self.vt.get_domain_report(domain)
            r = di.get('results', {})
            accumulate_subs = set(r.get('subdomains', []))
            subdomain_info[domain] = r

        return accumulate_subs, subdomain_info

    def extract_potential_bad(self, domain_info):
        results = []
        result = False
        dtus = domain_info.get('detected_urls', [])

        for dtu in dtus:
            hits = dtu.get('positives', 0)
            if hits <= self.min_hits:
                continue
            scan_date = dtu.get('scan_date', None)
            if scan_date is None:
                continue
            sdt = datetime.strptime(scan_date, DFMT)

            if sdt >= self.min_date:
                results.append(dtu)

        return len(results) > 0, results

    def accumulate_domains(self, accumulate_subs, subdomain_info, max_domain_pivots=100):
        subdomains = accumulate_subs
        completed = 0
        for s in subdomains:
            if s in subdomain_info:
                continue
            if not max_domain_pivots is None and completed >= max_domain_pivots:
                break
            print ("Acquiring report for subdomain: %s" % s)
            r = self.vt.get_domain_report(s)
            completed += 1
            if not 'results' in r:
                subdomain_info[s] = None
                continue
            results = r['results']
            subdomain_info[s] = results
            accumulate_subs |= set(results.get('domain_siblings', []))
            accumulate_subs |= set(results.get('subdomains', []))
        return accumulate_subs, subdomain_info

    def execute_domain_pivots(self, domains, mongodb='vt-domain-infos'):    
        accumulate_subs, subdomain_info = self.domain_lookups(domains)
        for domain_info in subdomain_info.values():
            self.save_to_mongo(domain_info, mongodb=mongodb, mongocol='domain-lookup')

        potential_bad = {}
        for n, di in subdomain_info.items():
            bad, results = self.extract_potential_bad(di)
            if bad:
                potential_bad[n] = results


        potential_bad_results = {}
        for domain, baddies in potential_bad.items():
            ip = ''
            try:
                ip = socket.gethostbyname(domain)
            except:
                pass
            categories = []
            try:
                domain_tag_result = self.ivg.domain_tags(domain)
                categories = sorted(set([i.get('category') for i in domain_tag_result if 'category' in i]))
            except:
                pass
            d = {'domain':domain, 'bad_urls': baddies, 'ip': ip, 'categories':categories}
            potential_bad_results[domain] = d


        for d in potential_bad.values():
            self.save_to_mongo(d, mongodb=mongodb, mongocol='potentially-bad')

        return self.min_date, potential_bad_results

    def execute_ip_pivots(self, ip, mongodb='vt-ip-pivots'):
        ii = self.vt.get_ip_report(ip)
        iir = ii['results']
        self.save_to_mongo(iir, mongodb=mongodb, mongocol='ip-lookup')
        resolutions = [i['hostname'] for i in iir.get('resolutions')] 

        accumulate_subs, subdomain_info = self.domain_lookups(resolutions)
        for domain_info in subdomain_info.values():
            self.save_to_mongo(domain_info, mongodb=mongodb, mongocol='domain-lookup')


        num_iters = self.num_iters
        exit_accumulation = False
        last_len = len(accumulate_subs)
        while not exit_accumulation:
            accumulate_subs, subdomain_info = self.accumulate_domains(accumulate_subs, subdomain_info, max_domains=self.max_domain_pivots)
            if num_iters <= 0 or (len(accumulate_subs) - last_len) < self.min_new_doms:
                exit_accumulation = True
            else:
                last_len = len(accumulate_subs)
            num_iters += -1

        potential_bad = {}
        bad, results = self.extract_potential_bad(iir)
        if bad:
            for r in results:
                r = URLPARSE(r['url'])
                if r.netloc not in potential_bad:
                    potential_bad[r.netloc] = []

                potential_bad[r.netloc] = potential_bad[r.netloc] + results

        for n, di in subdomain_info.items():
            bad, results = self.extract_potential_bad(di)
            if bad:
                for r in results:
                    r = URLPARSE(r['url'])
                    if r.netloc not in potential_bad:
                        potential_bad[r.netloc] = []

                    potential_bad[r.netloc] = potential_bad[r.netloc] + results

        if mongohost is not None:
            for domain, baddies in potential_bad.items():
                ip = ''
                try:
                    ip = socket.gethostbyname(domain)
                except:
                    pass
                d = {'domain':domain, 'bad_urls': baddies, 'ip': ip}

                self.save_to_mongo(d, mongodb=mongodb, mongocol='potentially-bad')

        return min_date, potential_bad
