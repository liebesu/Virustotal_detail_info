# -*- encoding:utf-8 -*-
import cookielib
import os
import urllib2

__author__ = 'liebesu'
import pefile
import requests
from bs4 import BeautifulSoup
def openurl():
    url='https://www.virustotal.com/en/file/4dd2e027e5eb580efcb7b08a5250cbb0c4de78b31697a9009faf0ee980bda041/analysis/'
    print "1"
    response=urllib2.urlopen(url)
    print response.getcode()
    print len(response.read())
    print "2"
    request = urllib2.Request(url)
    request.add_header("user-agent","Mozilla/5.0")
    response2=urllib2.urlopen(request)
    print response2.getcode()
    print len(response2.read())
    print "3"
    cj=cookielib.CookieJar()
    opener=urllib2.build_opener(urllib2.HTTPCookieProcessor(cj))
    urllib2.install_opener(opener)
    response3=urllib2.urlopen(request)
    print response3.getcode()
    print len(response3.read())
    print cj
    print "4"
    r=requests.session()
    s=r.get(url)


    print "5"


    #Cookie 容器
    __cookie = cookielib.CookieJar()
    __req = urllib2.build_opener(urllib2.HTTPCookieProcessor(__cookie))
    urllib2.install_opener(__req)

    #先请求一下首页, 得到Cookie
    urllib2.urlopen(url)

    #然后再请求查询
    response = urllib2.urlopen(url)
    html=response.read()

    #输出结果
    print html
    print "6"
    f=requests.get(url)
    f=str(f)
    print f

if __name__=="__main__":
    openurl()

