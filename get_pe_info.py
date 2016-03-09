import os

__author__ = 'liebesu'
import pefile
import requests
from bs4 import beautiful
def openurl(sha256):
    urllong='https://www.virustotal.com/en/file/4dd2e027e5eb580efcb7b08a5250cbb0c4de78b31697a9009faf0ee980bda041/analysis/'
    r=requests.session()
    parms={
        'User-Agent':'Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/48.0.2564.116 Safari/537.36',
        'Referer':urllong
    }

    r.post(urllong,parms=parms)
    print r.text()

if __name__=="__main__":

