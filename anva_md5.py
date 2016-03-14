# -*- encoding:utf-8 -*-
import requests
from bs4 import BeautifulSoup

__author__ = 'liebesu'
num=0
headers={'User-Agent':'Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/48.0.2564.116 Safari/537.36'}
parms={'type':'200501',
       'max':'10',
       'offset':str(num+10)}
url='http://www.anva.org.cn/virusSample/listBlack'

a=requests.get(url,headers=headers,data=parms)
print a.status_code
soup=BeautifulSoup(a.text,"html.parser")
tds= soup.find_all('td')
print len(tds)
print tds[1]
print tds
a=open("md5","a")
for i in range(2,len(tds)/8):
    m=5*i-9
    a.write(str(tds[m]).replace('<td>','').replace('</td>','').replace(' ',''))
    a.write('\n')
a.close()