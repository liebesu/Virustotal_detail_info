# -*- encoding:utf-8 -*-
import cookielib
import httplib
import os
import urllib
import urllib2

__author__ = 'liebesu'
import pefile
import requests
from bs4 import BeautifulSoup
s=requests.session()
longurl='https://www.virustotal.com/en/file/634f60864019a56185191d387e69faecead42a978075d844aa2deca8e7987c4a/analysis/'
#apiurl='https://www.virustotal.com/en/user/'+param['username']+'/apikey/'
headers = { "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
            'accept-encoding':'gzip, deflate, sdch',
            'accept-language':'zh-CN,zh;q=0.8,zh-TW;q=0.6'}
parms={ 'User-Agent': 'Mozilla/5.0 (Windows NT 6.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/28.0.1500.95 Safari/537.36',
           'Referer': 'https://www.virustotal.com/en/file/6076632ad5b0c3dedd84769a9b6f13bff1723a2bfa4ab75820aa61df7b33b458/analysis/',
           'Content-Type': 'application/x-www-form-urlencoded',}
cookies={'VT_PREFERRED_LANGUAGE=en'}
r=s.get(longurl,verify=True)
print r.cookies
print len(r.text)
print r.text
if r.status_code == 200:
    page=r.text.encode('ascii', 'ignore')
    print page


