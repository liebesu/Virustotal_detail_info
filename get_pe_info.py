import httplib
from multiprocessing import Pool
import os
import re
from bs4 import BeautifulSoup
import json
import MySQLdb
import time
from lib.core.readcnf import read_conf
from lib.core.constants import ROOTPATH
datebaseip,datebaseuser,datebasepsw,datebasename,datebasetable,sha256filename=read_conf()
result = {}
value=""
def get_page(sha256):
    headers = {
               'user-agent':'Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/49.0.2623.87 Safari/537.36',
               'Referer': 'https://www.virustotal.com/en/',
            }
    conn = httplib.HTTPSConnection("www.virustotal.com")
    conn.request(method='GET', url='/en/file/'+sha256+'/analysis/',
                     headers=headers)
    response = conn.getresponse()
    print response.status
    a=open("reason","a")
    a.write(str(response.status)+"\r\n")
    a.close()
    if response.status == 200:

        HTML=response.read()
        try:
            result['File_defail'] =''
            result['Behavioural'] =''
            result['File_defail'] = convert_detail_to_json(HTML)
            result['Behavioural']=convert_behavioutal_to_json(HTML)
            json_to_database(sha256,result)
        except Exception as e :
            print e
            a=open("fail_sha256","a")
            a.write(sha256+"\r\n")
            a.close()
            pass
    elif response.status == 403:
        a=open(response.reason,"a")
        a.write(sha256+"\r\n")
        a.close()
        time.sleep(60)

        '''result['File_defail'] =''
        result['Behavioural'] =''
        result['File_defail'] = convert_detail_to_json(HTML)
        result['Behavioural']=convert_behavioutal_to_json(HTML)
        json_to_database(sha256,result)'''
def convert_detail_to_json(page_data):
    global value
    jsons={}
    content={}
    soup=BeautifulSoup(page_data,"html.parser")
    file_details=soup.find_all(id="file-details")
    soup_details=BeautifulSoup(str(file_details),"html.parser")
    enumss=soup_details.find_all(class_="enum-container")
    for enums in enumss:
        h5_str=enums.previous_sibling.previous_sibling.get_text().encode("utf-8","ignore")
        if  "PE sections" in h5_str:
            enums=BeautifulSoup(str(enums),"html.parser")
            keys=enums.find(class_="text-bold")
            key=[key.encode("utf-8","ignore").replace("\n","").replace("\\n","") for key in keys.stripped_strings]
            while '' in key:
                key.remove('')
            enumss=enums.find_all(class_="enum")
            content=[]
            for enums in enumss:
                value=[enum.encode("utf-8","ignore").replace("\n","").replace("\\n","") for enum in enums.stripped_strings]
                while '' in value:
                    value.remove('')
                if key !=value:
                    content.append(dict(zip(key, value)))
            jsons[h5_str]=content
        elif 'PE imports' in h5_str:
            enums=BeautifulSoup(str(enums),"xml")
            enums=enums.find_all(class_="expand-canvas")
            content={}
            for enum in enums:
                key=enum.a.string.encode("utf-8","ignore").replace("[+]","")
                value=[string.encode("utf-8","ignore").replace("\\n","").replace(key,"").replace("[+]","") for string  in enum.stripped_strings]
                while '' in value:
                    value.remove('')
                content[key]=value
            jsons[h5_str]=content
        else:
            enums=BeautifulSoup(str(enums),"xml")
            enums=enums.find_all(class_="enum")
            content={}
            for enum in enums:
                if "Advanced heuristic and reputation engines"  in h5_str:
                    key=enum.find(class_=re.compile("field-key"))
                    key=key.string.encode("utf-8","ignore")
                if "ExifTool file metadata" in h5_str:
                    key=enum.find(class_=re.compile("field-key"))
                    key=key.string.encode("utf-8","ignore")
                if "Trusted verdicts" in h5_str:
                    key=""

                else:
                    if enum.span:
                        key=enum.span.stripped_strings.next().encode("utf-8","ignore")
                    else:
                        keys=enum.find(class_=re.compile("field-key"))
                        try:
                            key=keys.string.encode("utf-8","ignore")
                        except:
                            key=""
                value=enum.get_text(strip=True).encode("utf-8","ignore").replace(key,"").replace("\n","").replace("\\n","").replace("\'","/").replace('"',"/")

                content[key]=value
            jsons[h5_str]=content
    return jsons


def convert_behavioutal_to_json(page_data):
    global value
    jsons={}
    content={}
    soup=BeautifulSoup(page_data,"html.parser")
    file_details=soup.find_all(id="behavioural-info")
    soup_details=BeautifulSoup(str(file_details),"html.parser")
    enumss=soup_details.find_all(class_=re.compile("enum-container"))
    for enums in enumss:
        h5_str=enums.previous_sibling.previous_sibling.get_text().encode("utf-8","ignore")
        enums=BeautifulSoup(str(enums),"xml")
        enums=enums.find_all(class_="enum")
        content={}
        for enum in enums:
            if enum.span:
                value=enum.span.string.encode("utf-8","ignore")
            key=enum.get_text(strip=True).encode("utf-8","ignore").replace(value,"").replace("\n","").replace("\\n","").replace('"',"")
            content[key]=value
        jsons[h5_str]=content

    return jsons

def json_to_database(sha256,result):
    try:
        db = MySQLdb.connect(datebaseip,datebaseuser,datebasepsw,datebasename)
        cursor = db.cursor()
        sql = "insert into %s (Sha256,File_detail,Behavioural_info) values ('%s','%s','%s')" % (datebasetable,sha256,json.dumps(result['File_defail']).replace("'","\\'"),json.dumps(result['Behavioural']).replace("'","\\'").replace("\\","//"))
        #sql = "insert into %s (Sha256,File_detail,Behavioural_info) values ('%s','%s','%s')" , (datebasetable,sha256,json.dumps(result['File_defail']),json.dumps(result['Behavioural']))
        cursor.execute(sql)
        db.commit()
        cursor.close()
        db.close()
    except:
        cursor.close()
        db.close()
        pass

def sha256():
    db = MySQLdb.connect(datebaseip,datebaseuser,datebasepsw,datebasename)
    cursor = db.cursor()
    tmpsha256file='/var/lib/mysql-files/tmpsha256'
    if os.path.exists(tmpsha256file):
        os.remove(tmpsha256file)
    sha256sql='select sha256 from '+datebasetable+' into outfile '+'"'+tmpsha256file+'"'
    cursor.execute(sha256sql)
    db.commit()
    cursor.close()
    db.close()
    sha256filedir = os.path.join(ROOTPATH,"sha256")
    allsha256file=os.path.join(sha256filedir,sha256filename)
    os.system('cat '+tmpsha256file+" "+allsha256file +" |sort | uniq -u > sha256/tmp")
    newsha256file=os.path.join(sha256filedir,'tmp')
    newsha256=open(newsha256file,"r").readlines()
    newsha256=[sha256.replace('\n', '').replace('\r', '') for sha256 in newsha256]
    print len(newsha256)
    return newsha256
if __name__=="__main__":
    allsha256 = sha256()
    '''for sha256 in allsha256:
        print sha256
        get_page(sha256)'''

    pool = Pool(processes=5)
    pool.map(get_page, allsha256)
    pool.close()
    pool.join()
    print "finish"

