# -*- encoding:utf-8 -*-
import requests
from bs4 import BeautifulSoup

__author__ = 'liebesu'

def get_info(type,p,row,filename):
    page=(p-1)*20
    headers={'User-Agent':'Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/48.0.2564.116 Safari/537.36'}
    parms={'type':str(type),
           'max':'20',
           'offset':str(page)}
    url='http://www.anva.org.cn/virusSample/listBlack'

    a=requests.get(url,headers=headers,params=parms)
    print a.url
    print a.status_code
    soup=BeautifulSoup(a.text,"html.parser")
    tds= soup.find_all('td')
    print len(tds)
    a=open(filename,"a")
    for i in range(1,len(tds)/8+1):
        m=(row-1)+(i-1)*8
        print m
        w=str(tds[m]).replace(' ','').replace('<td>','').replace('</td>','').replace('\t','').replace('\n','')
        print w
        a.write(w)
        a.write('\n')
    a.close()

if __name__=="__main__":
    #type栏目ID，num代表总数，row代表取哪一列，filename代表保存文件名
    type=200500
    num=58009
    row=2
    filename='Android_md5'
    m=num/20+1
    for p in range(1,m):
        get_info(type,p,row,filename)

