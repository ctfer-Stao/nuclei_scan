import datetime

from web import DB



class SrcDomain(DB.Model):
    '''主域名表'''

    __tablename__ = 'src_domain'
    domain = DB.Column(DB.String(100), primary_key=True)
    domain_name = DB.Column(DB.String(100), nullable=True)
    domain_time = DB.Column(DB.String(30))
    flag = DB.Column(DB.String(30))

    def __init__(self, domain, domain_name, flag="null"):
        self.domain = domain
        self.domain_name = domain_name
        self.flag = flag
        self.domain_time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

class SrcSubDomain(DB.Model):
    '''子域名表'''

    __tablename__ = 'src_subdomain'
    subdomain = DB.Column(DB.String(150), primary_key=True)
    domain_name = DB.Column(DB.String(100))
    subdomain_ip = DB.Column(DB.String(20))
    cdn = DB.Column(DB.Boolean)
    flag = DB.Column(DB.Boolean)
    flag_url = DB.Column(DB.Boolean)
    flag_jg = DB.Column(DB.Boolean)
    subdomain_time = DB.Column(DB.String(30))


    def __init__(self, subdomain, domain, subdomain_ip, cdn, flag=False,flag_url=False,flag_jg=False):
        self.subdomain = subdomain
        self.domain_name = domain
        self.subdomain_ip = subdomain_ip
        self.cdn = cdn
        self.flag = flag
        self.flag_url = flag_url
        self.flag_jg=flag_jg
        self.subdomain_time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

class SrcVuln(DB.Model):
    '''子域名表'''

    __tablename__ = 'src_vuln'
    url = DB.Column(DB.String(150),primary_key=True)
    severity = DB.Column(DB.String(200))
    vuln_name = DB.Column(DB.String(200))
    src_name = DB.Column(DB.String(200))
    vuln_time = DB.Column(DB.String(30))


    def __init__(self, url,severity,name,src_name):
        self.url=url
        self.severity=severity
        self.vuln_name=name
        self.src_name=src_name
        self.vuln_time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

class SrcWeb(DB.Model):
    '''URL表'''

    __tablename__ = 'src_web'
    url = DB.Column(DB.String(500), primary_key=True)
    domain_name = DB.Column(DB.String(150))
    title = DB.Column(DB.String(300))
    status = DB.Column(DB.String(100))
    nuclei = DB.Column(DB.Boolean)
    dirsearch = DB.Column(DB.Boolean)
    dir = DB.Column(DB.String(300))
    url_time = DB.Column(DB.String(30))
    def __init__(self, url,domain_name,status,title,nuclei=False,dirsearch=False):
        self.url=url
        self.title=title
        self.domain_name=domain_name
        self.status=status
        self.nuclei=nuclei
        self.dirsearch=dirsearch
        self.dir=""
        self.url_time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")