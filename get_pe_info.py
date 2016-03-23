import httplib
from bs4 import BeautifulSoup
import json
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
    jsons={}
    soup=BeautifulSoup(page_data,"html.parser")
    keynum=len(soup.find_all(class_='field-key'))
    print keynum



    #h5s=soup.find('h5')

    #spans=soup.find_all('span','field_key')
    classs=soup.find(id="file-details")
    inner_items = [li.text.strip() for li in classs.find_all('h5')]

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
