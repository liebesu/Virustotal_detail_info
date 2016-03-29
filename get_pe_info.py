import httplib
import re
from bs4 import BeautifulSoup
import json
from requests.packages import chardet


def get_page():
    headers = {
               'user-agent':'Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/49.0.2623.87 Safari/537.36',
               'Referer': 'https://www.virustotal.com/en/',
            }
    conn = httplib.HTTPSConnection("www.virustotal.com")
    conn.request(method='GET', url='/en/file/4ee9e741d65680cd4c44b5e9a5d7636511c0ae4b3e774b454b17fdc675edf289/analysis/',
                     headers=headers)
    response = conn.getresponse()
    if response.status == 200:
        HTML=response.read()
        convert_to_json(HTML)
def convert_to_json(page_data):
    result={}
    jsons={}
    content={}
    soup=BeautifulSoup(page_data,"html.parser")
    file_details=soup.find_all(id="file-details")
    soup_details=BeautifulSoup(str(file_details),"html.parser")
    enumss=soup_details.find_all(class_="enum-container")
    a=open("enum-cib.html","a")
    a.write(str(enumss))
    a.close()
    print len(enumss)
    for enums in enumss:
        h5_str=enums.previous_sibling.previous_sibling.get_text()
        print h5_str
        if  "PE sections" in h5_str:
            enums=BeautifulSoup(str(enums),"html.parser")
            keys=[keys.span.get_text().replace("\n","") for keys in enums.find_all(class_="text-bold")]
            print keys
            for key in keys:
                content[key]=enum.span.string.encode("utf-8","ignore")
                print content
        else:
            enums=BeautifulSoup(str(enums),"html.parser")
            enums=enums.find_all(class_="enum")
            content={}
            for enum in enums:
                key=enum.span.string.encode("utf-8","ignore")

                value=enum.get_text(strip=True).encode("utf-8","ignore").replace(key,"").replace("\n","").replace("\\n","")

                content[key]=value
        jsons[h5_str]=content
        result['file-detail']=jsons
        print result
   # print [soup_detail.replace("\n","") for soup_detail in soup_details]

    '''enum_cons=soup_details1.find_all(class_="enum-container")
    for enum_con in enum_cons:
        #print soup_detail
        h5=enum_con.previous_sibling.previous_sibling.get_text()
        key=enum_con.span.get_text()
        value=enum_con.get_text().replace(key,"")
        print h5
        print key
        print value
        soup_key=soup_details.span
        soup_value=soup_details.span.parent
        key=soup_value.get_text().replace(soup_key.get_text(),"").replace("\n","").replace("u","")
        result1={soup_h5.get_text():{soup_key.get_text():key}}
        jsons[soup_h5]=result1
        print jsons
    print soup.h5.next_sibling.get_text()
    if ' PE imports' in  [h5.text for h5 in soup.find_all('h5')]:
        pass

    first=soup.h5
    se=first.next_sibling
    print se.children
'''
        #setions=soup.find_all(class_='')




    #h5s=soup.find('h5')

    #spans=soup.find_all('span','field_key')
    '''classs=soup.find(id="file-details")
    inner_items = [li.text.strip() for li in classs.find_all('h5')]'''

    #print h5s.get_text()
    '''for text1 in h5s:
        print text1.get_text()'''
    #for span in spans:
     #   print span.get_text()
    '''for class_ in classs:
        print [text for text in class_.stripped_strings]'''




    #soup=BeautifulSoup(HTML,'html.parser')
if __name__=="__main__":
    get_page()
