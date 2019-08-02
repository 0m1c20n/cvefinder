import gzip
import json
import requests
import subprocess
import sys

from pycvesearch import CVESearch
from urllib.request import urlopen
from xml.dom.minidom import parse, parseString

CPEs = None
CVE = None
CVEs = {}


def logo():
    print('''
                  __ _           _           
                 / _(_)         | |          
   _____   _____| |_ _ _ __   __| | ___ _ __ 
  / __\ \ / / _ \  _| | '_ \ / _` |/ _ \ '__|
 | (__ \ V /  __/ | | | | | | (_| |  __/ |   
  \___| \_/ \___|_| |_|_| |_|\__,_|\___|_|   
                                             
                                   by 0m1c20n
                                             ''')


def setup():
    global CPEs, CVE
    CVE = CVESearch()

    cpes_file = 'official-cpe-dictionary_v2.3.xml.gz'
    file_url = 'https://static.nvd.nist.gov/feeds/xml/cpe/dictionary/official-cpe-dictionary_v2.3.xml.gz'
    
    print('Downloading CPE dictionary from NIST ...')
    r = requests.get(file_url)
    open(cpes_file,'wb').write(r.content)
    
    infile = gzip.open(cpes_file)
    content = infile.read()
    print('Parsing XML ...')
    dom = parseString(content)
    print('Getting CPEs ...')
    CPEs = dom.getElementsByTagName('cpe-item')
    print('Ready to scan urls')


def wappalyzer_scan(url):
    applications = []
    cmd = ['node','cli.js', url]
    output = subprocess.check_output(cmd)
    json_data = json.loads(output.decode('utf-8'))
    print('    Applications detected:')
    for wap_app in json_data['applications']:
        app = {}
        app['name'] = wap_app['name'].lower()
        app['confidence'] = wap_app['confidence']
        app['version'] = ''
        if wap_app['version']:
            app['version'] = wap_app['version']
            print('      '+app['name']+' '+app['version'])
        else:
            print('      '+app['name'])
        applications.append(app)
    return applications



def cve_search(applications):
    global CVEs
    result = []
    cpes = []
    print('    CPEs and CVEs:')
    for app in applications:
        if app['version']:
            for cpe in CPEs:
                name = cpe.getElementsByTagName('cpe-23:cpe23-item')[0].getAttribute('name')
                if name not in cpes and app['name'] in name and app['version'] in name:
                    cpes.append(name)
                    print('      '+name)
                    cves = CVE.cvefor(name)
                    for cve in cves:
                        print('        '+cve['id'])


if __name__ == '__main__':
    logo()
    if len(sys.argv) == 2:
        setup()
        RESULTS = {}
        URL = sys.argv[1]
        result = {}
        print('  Scanning '+ URL + ' ...')
        applications = wappalyzer_scan(URL)
        cve_search(applications)

    else:
        print('Usage: python cvefinder.py URL')
        sys.exit(0)