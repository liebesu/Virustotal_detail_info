import httplib
import BeautifulSoup
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
        print len(HTML)
        a=open("html1",'a')
        a.write(HTML)
        a.close()
def convert_to_json():
    pass

    #soup=BeautifulSoup(HTML,'html.parser')
if __name__=="__main__":
    get_page()
