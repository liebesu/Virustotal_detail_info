# -*- encoding:utf-8 -*-
from multiprocessing import Pool
import re
import requests
from bs4 import BeautifulSoup

__author__ = 'liebesu'

def get_info(p):
    page=(p-1)*20
    headers={'User-Agent':'Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/48.0.2564.116 Safari/537.36'}
    parms={
           'max':'20',
           'offset':str(page)}
    url='http://www.anva.org.cn/virusAddress/listBlack'

    a=requests.get(url,headers=headers,params=parms)
    print a.url
    print a.status_code
    soup=BeautifulSoup(a.text,"html.parser")
    tds= soup.find_all(href=re.compile('/virusAddress/show/'))
    for link in tds:
        href_url=link.get('href')
        durl='http://www.anva.org.cn'
        full_url=durl+href_url
        openurl(full_url)
    print len(tds)

def openurl(full_url):
    filename='anva_url'
    headers={'User-Agent':'Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/48.0.2564.116 Safari/537.36'}
    a=requests.get(full_url,headers=headers)
    soup=BeautifulSoup(a.text,"html.parser")
    url=soup.find_all(style=re.compile('word-break:break-all;'))
    url_str=str(url).replace('<h2 style="word-break:break-all;">','').replace('</h2>','')
    a=open(filename,"a")
    a.write(url_str)
    a.write('\n')
    a.close()

if __name__=="__main__":
    #type栏目ID，num代表总数，row代表取哪一列，filename代表保存文件名
    #type=200500
    num=58009
    row=2
    m=num/20+1
    pool = Pool(processes=150)
    pool.map(get_info, range(1,m))
    pool.close()
    pool.join()

