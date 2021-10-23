import argparse
import requests,threading,queue,time,re,random
from bs4 import BeautifulSoup
from art import *
import urllib.parse

parser = argparse.ArgumentParser(description='NOOBSCAN XSS BY ST3XZ')
parser.add_argument('-d','--domain', metavar='' , required=True ,help='enter domain name')
parser.add_argument('-sx','--skipxss', action='store_true' ,help='use when you don\' want to scan for xss.')
args = parser.parse_args() 

tprint('\n N O O B - S C A N \n')
start = time.perf_counter()

# -----------------------------------------------------------------------------------------------#
#                                P A R A M - E X T R A C T E R                                   #
# -----------------------------------------------------------------------------------------------#
if not args.skipxss:
    Parameters = []
    def param_extracter(domain):
        global Parameters

        blacklist = ['.png', '.jpg', '.jpeg', '.mp3', '.mp4', '.avi', '.gif', '.svg','.pdf','.js','.css']
        refused_connection = True
        retries = 3

        while refused_connection:
            try:
                url = f"https://web.archive.org/cdx/search/cdx?url=*.{domain}/*&output=txt&fl=original&collapse=urlkey&page=/"
                response = requests.get(url)

                ''' 
                Function to extract URLs with parameters (ignoring the black list extention)
                regexp : r'.*?:\/\/.*\?.*\=[^$]'
                
                '''

                parsed = list(set(re.findall(r'.*?:\/\/.*\?.*\=[^$]' , response.text)))
                final_uris = []
                    
                for i in parsed:
                    delim = i.find('=')
                    final_uris.append((i[:delim+1]))

                blacklisted_url = []
                dublicates = []
                if final_uris != []:
                    for x in final_uris:
                        for b in blacklist:
                            if b in x:
                                blacklisted_url.append(x)
                        if x not in blacklisted_url:
                            if x not in Parameters:
                                dublicates.append(x)
                for x in dublicates:
                    if x not in Parameters:
                        Parameters.append(x)
                refused_connection = False
            except Exception as e:
                print("Error :",e)
                retries -= 1
                if retries == 0:
                    refused_connection = False
                time.sleep(20*random.randint(2,4))


    # -----------------------------------------------------------------------------------------------#
    #                                      -  S C A N N E R  -                                       #
    # -----------------------------------------------------------------------------------------------#
                
    req_size,req_count,founds = 0,0,0
    output = open('result.txt','w')
    output.close()
    def noobscan(target):
        global req_size,req_count,founds,total,count

        xss_payloads = ['%3Ch1%3Exxxxx%3C%2Fh1%3E%0A','<h1>xxxxx</h1>']
        try:
            for payload in xss_payloads:
                response = requests.get(target+payload,timeout=3)
                if urllib.parse.unquote(payload).strip() in response.text:
                    output = open('result.txt','a')
                    output.write(target+payload+'\n')
                    output.close()
                    founds += 1
                else:
                    print("Requests :",req_count,"/",req_size," Found :",founds)  
                req_count += 1
        except:
            req_count += 1
            None        

    # ---------------- ParamExtractor / XSS scan ----------------

    param_extracter(args.domain)

    try:
        scannerqueue = queue.Queue()
        for parameter in Parameters:
            scannerqueue.put(parameter)
        req_size = scannerqueue.qsize() * 2
        req_count = 0
        def QueueScanning():
            while not scannerqueue.empty():
                parameter = scannerqueue.get()
                noobscan(parameter)
        threads2 = []
        for _ in range(9):
            t = threading.Thread(target=QueueScanning)
            t.start()
            threads2.append(t)
        for thread in threads2:
            thread.join()
    except Exception as e:
        print(e)
    print('\n')

# ---------------- SPF check ----------------

domain = args.domain.replace('https://','').replace('http://','').replace('www.','').replace('/','')
vulns = 0
def spfcheck(domain):
    global vulns            
    headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/90.0.4430.93 Safari/537.36s"
            }

    url = "https://www.kitterman.com/spf/getspf3.py"

    values = {
            "serial": "fred12",
            "domain": domain
            }

    page = requests.post(url, data=values, headers=headers)
    soup = BeautifulSoup(page.text, features="html.parser")

    spf = soup(text=lambda t: "all" in t)
    spf_content = str(spf)

    if ("-all" not in spf_content):
        if ("~all" in spf_content):
            print(f"[*] SPF ~all Found  ===>  {domain}  ===> can be spoofed!")
        elif ("?all" in spf_content):
            print(f"[*] SPF ?all Found  ===> {domain}  ===> can be spoofed!")
        else:
            print(f"[*] NO SPF records Found ===> {domain}  ===> can be spoofed!")
        vulns = 1


def clickjacking(domain):
    global vulns
    res = requests.get(f"https://{domain}/")
    if not "X-Frame-Options" in res.headers:
        print("[*] Vulnerable to ClickJacking Attack")
        vulns = 1

spfcheck(domain)
clickjacking(domain)
finish = time.perf_counter()
if not args.skipxss:
    if founds != 0:
        print(f'\n\n[*] Scan Completed In {round(finish-start,4)} Secounds, Check result.txt\n')
    else:
        print(f'\n\n[*] Scan Completed In {round(finish-start,4)} Secounds, No Vulnerabilities was detected!\n')
else:
    if vulns != 0:
        print(f'\n\n[*] Scan Completed In {round(finish-start,4)} Secounds, Some Vulnerabilities was detected!\n')
    else:
        print(f'\n\n[*] Scan Completed In {round(finish-start,4)} Secounds, No Vulnerabilities was detected!\n')
