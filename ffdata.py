from gevent import monkey
monkey.patch_all()

from SMLoki import SMLoki
from bs4 import BeautifulSoup
from urllib.parse import urlparse
from uuid import uuid1
from multiprocessing import Process


import signal as signal_module
import requests
import json
import signal
import sys,os
import time

api_dev_key = ''
username = ''
password = ''

def signal_handler(signal, frame):
    sys.exit(0)


def check_folder(folder):
    if os.path.exists(folder):
            pass
    else:
        import pathlib
        pathlib.Path(os.path.abspath(folder)).mkdir(
            parents=True, exist_ok=True)

def store(info, filename):
    check_folder('./metaJson')
    metapath = './metaJson/{}'.format(filename)
    with open(metapath, 'a') as dest:
        dest.write(info)

def get_raw_paste_content(item_raw_url,):
    return requests.get(item_raw_url)

def get_intersting_res(scan, data):
    _, res = scan.scan_Target(data)
    if _ :
        return res
    else:
        return

def get_api_user_key():
    data = {
        'api_dev_key': api_dev_key ,
        'api_user_name': username,
        'api_user_password': password
        }

    res = requests.post('https://pastebin.com/api/api_login.php', data=data)
    return res.content

def get_api_raw_data(folder,pastebin_id):
    res = requests.get(
        'https://pastebin.com/api_scrape_item.php?i={}'.format(pastebin_id))

    outputpath = os.path.join(folder, str(uuid1()))
    print(outputpath)

    with open(outputpath, 'a') as out:
        out.write(res.text)

    return res.text  

def get_pastebin_trends(folder):
    
    trends_url_list = []

    trends_data = {
        'api_dev_key': api_dev_key,
        'api_option' : 'trends'
    }

    res = requests.post('https://pastebin.com/api/api_post.php', data= trends_data )

    soup = BeautifulSoup(res.text,'lxml')
    
    for trends in soup.find_all('paste_url'):
        url = trends.contents[0]
        # trends_url_list.append(url)
        pastebin_tid = urlparse(url).path.replace('/', '')
        res = get_api_raw_data(folder,pastebin_tid)

def get_pastebin_250(folder):
    """
        Life Time Pro, 250. if not , https://pastebin.com/api_scraping.php
        Also, Due to scrape api rule, we were allowed crawle data 1time/1second
    """

    common = "https://pastebin.com/api_scraping.php?limit=250"
    res = requests.get(common)
    store(res.text, str(uuid1()))

    data = json.loads(res.text)
    for item in data:
        res = get_api_raw_data(folder,item['key'])
        # print("Common 250:", item['scrape_url'], res[:100])
        
if __name__ == '__main__':
    
    signal_module.signal(signal_module.SIGINT, signal_handler)

    # use crontab, not while True
    spid = os.path.join('./output/',str(uuid1()))
    try:
        check_folder(spid)
        p = Process(target=get_pastebin_250, args=(spid,))
        q = Process(target=get_pastebin_trends, args=(spid,))
        p.start()
        q.start()
        p.join()
        q.join()
        
    except Exception as e:
        # If Exception, that's mean Response None, Also Mean C
        rulespath = os.path.abspath('./YaraRules/')
        scan = SMLoki(rules=rulespath)
        scan.init_yara_rules()
        res = get_intersting_res(scan,spid)
        for item in res:
            
            print(item['filename'])
            # you can do what ever you want with those interesting data
            with open(item['filename']) as f:
                print(f.read())
