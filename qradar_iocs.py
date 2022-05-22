###########################################################

# This script is developed by Mohab El-Banna (Mouhab-dev)
# Version 1.0 (9/7/2021)
# Follow me on Github for more work: github.com/mouhab-dev

###########################################################

import base64
# import configparser
import json
# import ssl
import sys
# import os
import requests
import getpass
import csv
import re
import pandas as pd

print('''

Welcome to 
 __   __        __        __         __   __   __      __   ___ ___  ___  __  ___    __       
/  \ |__)  /\  |  \  /\  |__) .   | /  \ /  ` /__`    |  \ |__   |  |__  /  `  |  | /  \ |\ | 
\__X |  \ /~~\ |__/ /~~\ |  \ .   | \__/ \__, .__/    |__/ |___  |  |___ \__,  |  | \__/ | \| 
                                                                                 Version: 1.0                                                                                                   
                                                                           By: Mohab El-Banna
                                                                           Github: Mouhab-dev\n''')

# TODO
# Domain (DONE)
# Sender Mail (DONE)
# Case-Insensitive when searching for Hashes (DONE) (solution): use LOWER() on query --very slow or use ref_set
# Make json into excel directly (DONE)
# Remove IOCs from ref set after search (DONE)

#Supress SSL Certifacte warnings
requests.packages.urllib3.disable_warnings()

'''
Based on AQL Guide Documentation

# Time Format Example. WHERE START '2014-04-25 15:51' STOP '2014-04-25 17:00:20'
# PARSEDATETIME('3 months ago') for IOCs Detection

QIDNAME(qid)         =          TCP_MISS
QIDDESCRIPTION(qid)  =          The requested object was not in the cache (TCP_MISS)

#AQL Statments:
    - Search for IP as IOC Last 3 Months:
        SELECT * FROM events WHERE sourceip IN ('','') OR destinationip IN ('') START PARSEDATETIME('3 months ago')

    - Search for MD5 Hash as IOC Last 3 Months:
        SELECT * FROM events WHERE "Hash_MD-5" IN ('c73fd6a93428d195fdde2294a4b4513e') START PARSEDATETIME('3 months ago')

    - Search for SHA256 Hash as IOC Last 3 Months:
        SELECT * FROM events WHERE "Hash_MD-5" IN ('c73fd6a93428d195fdde2294a4b4513e','HASH') START PARSEDATETIME('3 months ago')

'''
# Options to change
search_period = '3 Months ago'           # The time period you will scan for IOCs 3 Months ago

# Prompt for server host and credentials.
# host = input("Please input the IP address of Qradar: ").strip()
host=''
# username = input("Username: ").strip()
username = ''
password = getpass.getpass("Password: ")
#certificate_file = input("Enter path to TLS PEM certificate (optional): ").strip()

userpass = username + ":" + password
encoded_credentials = b"Basic " + base64.b64encode(userpass.encode('ascii'))

headers = {'Version': '9.0', 'Accept': 'application/json',
        'Authorization': encoded_credentials}

# VARs
md5_list,sha1_list,sha256_list,urls_list,domains_list,ips_list,sender_email_list,sender_domain_list = [],[],[],[],[],[],[],[]

ul = '\u00a1-\uffff'  # unicode letters range (must not be a raw string)

# Regex patterns to validate IP,Domain,URL formats:

# IP patterns 
ipv4_re = r'(?:25[0-5]|2[0-4]\d|[0-1]?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|[0-1]?\d?\d)){3}' 
ipv6_re = r'\[[0-9a-f:\.]+\]'
ip_regex=re.compile(r'(?:' + ipv4_re + '|' + ipv6_re + ')')

# Host patterns 
hostname_re = r'[a-z' + ul + r'0-9](?:[a-z' + ul + r'0-9-]{0,61}[a-z' + ul + r'0-9])?'
domain_re = r'(?:\.(?!-)[a-z' + ul + r'0-9-]{1,63}(?<!-))*' # domain names have max length of 63 characters
tld_re = ( 
    r'\.'                                # dot 
    r'(?!-)'                             # can't start with a dash 
    r'(?:[a-z' + ul + '-]{2,63}'         # domain label 
    r'|xn--[a-z0-9]{1,59})'              # or punycode label 
    r'(?<!-)'                            # can't end with a dash 
    r'\.?'                               # may have a trailing dot 
) 
host_re = '(' + hostname_re + domain_re + tld_re + '|localhost)'

# URL patterns
url_regex = re.compile( 
    r'^(?:http|ftp)s?://' # http(s):// or ftp(s)://
    r'(?:\S+(?::\S*)?@)?'  # user:pass authentication 
    r'(?:' + ipv4_re + '|' + ipv6_re + '|' + host_re + ')' # localhost or ip
    r'(?::\d{2,5})?'  # optional port
    r'(?:[/?#][^\s]*)?'  # resource path
    r'\Z', re.IGNORECASE)

# Domain patterns
domain_pattern=r'(([a-zA-Z]{1})|([a-zA-Z]{1}[a-zA-Z]{1})|([a-zA-Z]{1}[0-9]{1})|([0-9]{1}[a-zA-Z]{1})|([a-zA-Z0-9][-_.a-zA-Z0-9]{0,61}[a-zA-Z0-9]))\.([a-zA-Z]{2,13}|[a-zA-Z0-9-]{2,30}.[a-zA-Z]{2,3})$'
domain_regex = re.compile(r'^' + domain_pattern)
sender_email_regex=re.compile(r'^.*?@' + domain_pattern)


def create_search(query_expression,ioc_type):
    '''
    This function creates a search depening on the query.
    Argumetns: query expression that would run the search and ioc type
    Returns: search_id to check if search has finished or not
    '''
    search_url = 'https://'+host+'/api/ariel/searches'  #POST
    query={"query_expression" : query_expression}
    request = requests.post(search_url, headers=headers, verify=False, data=query)
    if request.status_code not in range (200,202):
        print('[Error]: ' + request.json()['message'])
        exit(1)
    else:
        print('[+] '+ioc_type+ ' Search has been created successfully.')
    # print(request)
    # print(request.text)
    return request.json()['search_id']


def check_sh_result(search_id,ioc_type):
    '''
    This function would check search result to determine if search has finished or not.
    Arguments: search_id and ioc type
    Returns: void
    '''
    check_sh_result = 'https://'+host+'/api/ariel/searches/'+search_id   #GET
    while True:
        request = requests.get(check_sh_result,headers=headers,verify=False)
        if request.json()['status'] != 'COMPLETED':
            t_sec = int(request.json()['query_execution_time']/1000)
            m, s = divmod(t_sec,60)
            h, m  = divmod(m,60)
            print('[!] '+ioc_type+" Search Progress: "+str(request.json()['progress'])+ f"% | Time Elapsed: {h:02d}:{m:02d}:{s:02d}",end='\r') # \r to overwrite the same line
            print("",end='\r')
            continue
        else:
            print('\n[*] '+ioc_type+' Search Completed!')
            break


def cancel_search(search_id,ioc_type):
    cancel_sh_link = 'https://'+host+'/api/ariel/searches/'+search_id+'?status=CANCELED'    #POST
    request = requests.post(cancel_sh_link,headers=headers,verify=False)
    if request.status_code == 200:
        print('[!] '+ioc_type+' Search has been Canceled!\n')
    else:
        print('[Error]: ' + request.json()['message'])


def get_results(search_id,filename):
    '''
    This function get the results of a search given its search ID.
    Argumetns: search_id assigned when creating the search
    Returns: csv file with the search results
    '''
    res_url = 'https://'+host+'/api/ariel/searches/'+search_id+'/results'   #GET
    request = requests.get(res_url, headers=headers, verify=False)
    events = request.json()['events']
    if  events == []:
        print('[!] No Events were found!\n')
    else:
        # Convert JSON to Excel File
        df = pd.json_normalize(events)
        df.to_excel(filename+'.xlsx',index=False)
        print('[IMPACT] Events were found, an Excel file has been created.\n')
        # with open(filename+'.json', 'w') as f:
        #     f.write(request.text)
        # print('[IMPACT] Events were found, a JSON file has been created.\n')


# need abrevation for the below 3 FNs into 1 single fn
def check_hash(hash):
    global md5_list, sha1_list, sha256_list, row_num
    if len(hash) == 32 and hash.isalnum():
        md5_list.append(hash)
    elif len(hash) == 40 and hash.isalnum():
        # sha1_list.append(hash)
        print("[REMINDER] SHA1 Hash found!, REMEMBER to check it using Nexthink Script.")
    elif len(hash) == 64 and hash.isalnum():
        sha256_list.append(hash)
    else:
        print('[Error] Hash in row no. {} is not-valid: {}'.format(row_num+1,hash))
        print('Please, edit the above IOC first --> Terminating the script...')
        exit(1)


def check_url(url):
    url = url.replace('hxxp://','http://')
    url = url.replace('hxxps://','https://')
    url = url.replace('[.]','.')
    url = url.replace('[:]',':')
    if url_regex.fullmatch(url) != None :
        urls_list.append(url)
    else:
        print('[Error] URL in row no. {} is not-valid: {}'.format(row_num+1,url))
        print('Please, edit the above IOC first --> Terminating the script...') 
        exit(1)


def check_domain(domain,email=False):
    domain = domain.replace('[.]','.')
    if domain_regex.fullmatch(domain) != None:
        if email:
            sender_domain_list.append(domain)
        else:
            domains_list.append(domain)
    else:
        if email: 
            print('[Error] Sender Domain in row no. {} is not-valid: {}'.format(row_num+1,domain))
        else:
            print('[Error] Domain in row no. {} is not-valid: {}'.format(row_num+1,domain))
        print('Please, edit the above IOC first --> Terminating the script...') 
        exit(1)


def check_ip(ip):
    ip=ip.replace('[.]','.')
    if ip_regex.fullmatch(ip):
        ips_list.append(ip)
    else:
        print('[Error] IP in row no. {} is not-valid: {}'.format(row_num+1,ip))
        print('Please, edit the above IOC first --> Terminating the script...') 
        exit(1)


def check_sender_em(sender_email):
    sender_email=sender_email.replace('[.]','.')
    if sender_email_regex.fullmatch(sender_email) != None :
        sender_email_list.append(sender_email)
    else:
        print('[Error] Sender Mail in row no. {} is not-valid: {}'.format(row_num+1,sender_email))
        print('Please, edit the above IOC first --> Terminating the script...') 
        exit(1)


def identify_ioc(row_num,row):
    if row[0].lower().strip() == 'hash':
        check_hash(row[1].lower().strip())
    elif row[0].lower().strip() == 'url':
        check_url(row[1].strip())
    elif row[0].lower().strip() == 'domain':
        check_domain(row[1].strip())
    elif row[0].lower().strip() == 'ip':
        check_ip(row[1].strip())
    elif row[0].lower().strip() == 'sender mail':
        check_sender_em(row[1].strip())
    elif row[0].lower().strip() == 'sender domain':
        check_domain(row[1].strip(),email=True)
    else:
        print(f'[!] Error: Unknown IOC type at row no. {row_num+1} | IOC value: {row[1]}, Please review the csv file and try again.')
        exit(1)


def add_2_ref_set(ioc_list,ioc_type):
    # /api/reference_data/sets/{name} (single Value)
    # /api/reference_data/sets/bulk_load/{name} (multiple values at once)
    if ioc_type=='MD5':
        ref_set_name = 'IOC-Test-MD5'
    elif ioc_type=='SHA256':
        ref_set_name = 'IOC-Test-SHA256'
    elif ioc_type=='Domain':
        ref_set_name='IOC-Check-Domains'
    elif ioc_type=='IP':
        ref_set_name='IOC-Check-IPs'
    elif ioc_type=='URL':
        ref_set_name='IOC-Check-URLs'
    elif ioc_type=='Sender Email':
        ref_set_name='IOC-Test-Sender-Email'
    elif ioc_type=='Sender Domain':
        ref_set_name='IOC-Test-Sender-Domain'

    add_ref_set_url = 'https://'+host+f'/api/reference_data/sets/bulk_load/{ref_set_name}'
    ioc_list = json.dumps(ioc_list) # Convert list to json
    request = requests.post(add_ref_set_url, headers=headers, verify=False, data=ioc_list)

    if request.status_code not in range (200,202):
        print('[Error]: ' + request.json()['message'])
        exit(1)
    else:
        print("=================== " +ioc_type+ " ===================")
        print(f'[+] IOCs has been added to reference set: {ref_set_name}')


def clear_ref_set(ref_set_name):
    # /api/reference_data/sets/{name}
    del_ref_set_url = 'https://'+host+f'/api/reference_data/sets/{ref_set_name}?purge_only=true'
    request = requests.delete(del_ref_set_url,headers=headers,verify=False)
    if request.status_code not in range (200,203):
        print(request)
        print(request.text)
    else:
        print('[-] '+ref_set_name+' Reference Set has been cleared successfully.\n')
    

def stats():
    sha256_len,md5_len,domains_len = len(sha256_list), len(md5_list), len(domains_list)
    sender_email_len,urls_len,ips_len = len(sender_email_list), len(urls_list), len(ips_list)
    sender_domain_len=len(sender_domain_list)
    sum = sha256_len + md5_len + domains_len + sender_email_len + urls_len + ips_len +sender_domain_len
    print('\n****************** IOCs Statistics ******************\n')
    print(f'Total Number of Sender Domains: {sender_domain_len}')
    print(f'Total Number of Email Senders:  {sender_email_len}')
    print(f'Total Number of SHA256 Hahses:  {sha256_len}')
    print(f'Total Number of MD5 Hashes:     {md5_len}')
    print(f'Total Number of Domains:        {domains_len}')
    print(f'Total Number of URLs:           {urls_len}')
    print(f'Total Number of IPs:            {ips_len}')
    print("-----------------------------------------")
    print(f'Total Number of IOCs:           {sum}')


# ===================================================================== Script's LOGIC ====================================================================
with open('observables.csv', "r", encoding='utf-8-sig') as iocs_file:
    csv_reader = csv.reader(iocs_file, delimiter=';')

    for row_num,row in enumerate(csv_reader):
        if len(row)!=2:
            print('[!] Error in observables.csv file format.')
            print(f'Please review the file format again at row no.{row_num}, Terminating the Script...')
            exit(1)
        else:
            identify_ioc(row_num,row) # Identifying and Extracting iocs done

# Now running the Search queries on Qradar by calling FNs
# ips_list = ['10.155.21.41'] # TEST
# ips_list = [] # Uncomment this to bypass the search (test purposes)
if len(ips_list) != 0:
    try:
        add_2_ref_set(ips_list,'IP')
        ip_query=("SELECT QIDNAME(qid) AS 'Event Name', LOGSOURCENAME(logsourceid) AS 'Log Source', "
                "DATEFORMAT(starttime,'dd-MM-YYYY, hh:mm:ss a') AS 'Start Time', CATEGORYNAME(Category) As 'Category', "
                "sourceip AS 'Source IP',sourceport AS 'Source Port',destinationip AS 'Destination IP',destinationport AS 'Destination Port',username AS 'Username' "
                "FROM events WHERE REFERENCESETCONTAINS('IOC-Check-IPs',destinationip) OR REFERENCESETCONTAINS('IOC-Check-IPs',sourceip) "
                "START PARSEDATETIME("+ "'" + search_period + "'" + ')'
                )
        # print(ip_query)
        ips_search_id = create_search(ip_query,'IP')
        check_sh_result(ips_search_id,'IP')
        get_results(ips_search_id,'ip_ioc')
        clear_ref_set('IOC-Check-IPs')
    except KeyboardInterrupt:
        clear_ref_set('IOC-Check-IPs')
        cancel_search(ips_search_id,'IP')


# md5_list=[] # Uncomment this to bypass the search (test purposes)
if len(md5_list) != 0:
    try:
        add_2_ref_set(md5_list,'MD5') # Add the iocs to the associated ref set
        md5_query=("SELECT QIDNAME(qid) AS 'Event Name', LOGSOURCENAME(logsourceid) AS 'Log Source', \"Hash_MD-5\", "
                "DATEFORMAT(starttime,'dd-MM-YYYY, hh:mm:ss a') AS 'Start Time', CATEGORYNAME(Category) As 'Category', "
                "sourceip AS 'Source IP',sourceport AS 'Source Port',destinationip AS 'Destination IP',destinationport AS 'Destination Port',username AS 'Username' "
                "FROM events WHERE REFERENCESETCONTAINS('IOC-Test-MD5',\"Hash_MD-5\") START PARSEDATETIME("+ "'" + search_period + "'" + ')'
                )
        # print(md5_query)
        md5_search_id = create_search(md5_query,'MD5')
        check_sh_result(md5_search_id,'MD5')
        get_results(md5_search_id,'md5_ioc')
        clear_ref_set('IOC-Test-MD5')
    except:
        clear_ref_set('IOC-Test-MD5')
        cancel_search(md5_search_id,'MD5')


# sha256_list=[] # Uncomment this to bypass the search (test purposes)
if len(sha256_list) != 0:
    try:
        add_2_ref_set(sha256_list,'SHA256') # Add the iocs to the associated ref set
        sha256_query=("SELECT QIDNAME(qid) AS 'Event Name', LOGSOURCENAME(logsourceid) AS 'Log Source', \"Hash SHA256\", "
                "DATEFORMAT(starttime,'dd-MM-YYYY, hh:mm:ss a') AS 'Start Time', CATEGORYNAME(Category) As 'Category', "
                "sourceip AS 'Source IP',sourceport AS 'Source Port',destinationip AS 'Destination IP',destinationport AS 'Destination Port',username AS 'Username' "
                "FROM events WHERE REFERENCESETCONTAINS('IOC-Test-SHA256',\"Hash SHA256\") START PARSEDATETIME("+ "'" + search_period + "'" + ')'
                )
        # print(sha256_query)
        sha256_search_id = create_search(sha256_query,'SHA-256')
        check_sh_result(sha256_search_id,'SHA-256')
        get_results(sha256_search_id,'sha256_ioc')
        clear_ref_set('IOC-Test-SHA256')
    except KeyboardInterrupt:
        clear_ref_set('IOC-Test-SHA256')
        cancel_search(sha256_search_id,'SHA-256')        


# urls_list = []  # Uncomment this to bypass the search (test purposes)
if len(urls_list) != 0:
    try:
        add_2_ref_set(urls_list,'URL') # Add the iocs to the associated ref set
        urls_query=("SELECT QIDNAME(qid) AS 'Event Name', LOGSOURCENAME(logsourceid) AS 'Log Source', Referer, URL, "
                "DATEFORMAT(starttime,'dd-MM-YYYY, hh:mm:ss a') AS 'Start Time', CATEGORYNAME(Category) As 'Category', "
                "sourceip AS 'Source IP',sourceport AS 'Source Port',destinationip AS 'Destination IP',destinationport AS 'Destination Port',username AS 'Username' "
                "FROM events WHERE REFERENCESETCONTAINS('IOC-Check-URLs', 'URL') START PARSEDATETIME("+ "'" + search_period + "'" + ')'
                )
        # print(urls_query)
        urls_search_id = create_search(urls_query,'URL')
        check_sh_result(urls_search_id,'URL')
        get_results(urls_search_id,'urls_ioc')
        clear_ref_set('IOC-Check-URLs')
    except KeyboardInterrupt:
        clear_ref_set('IOC-Check-URLs')
        cancel_search(urls_search_id,'URL')        


# domains_list=[]  # Uncomment this to bypass the search (test purposes)
if len(domains_list) != 0:
    try:
        add_2_ref_set(domains_list,'Domain') # Add the iocs to the associated ref set
        domains_query=("SELECT QIDNAME(qid) AS 'Event Name', LOGSOURCENAME(logsourceid) AS 'Log Source', \"Domain name\", "
                "DATEFORMAT(starttime,'dd-MM-YYYY, hh:mm:ss a') AS 'Start Time', CATEGORYNAME(Category) As 'Category', "
                "sourceip AS 'Source IP',sourceport AS 'Source Port',destinationip AS 'Destination IP',destinationport AS 'Destination Port',username AS 'Username' "
                "FROM events WHERE REFERENCESETCONTAINS('IOC-Check-Domains',\"Domain name\") START PARSEDATETIME("+ "'" + search_period + "'" + ')'
                )
        # print(domains_query)
        domains_search_id = create_search(domains_query,'Domain')
        check_sh_result(domains_search_id,'Domain')
        get_results(domains_search_id,'domains_ioc')
        clear_ref_set('IOC-Check-Domains')
    except KeyboardInterrupt:
        clear_ref_set('IOC-Check-Domains')
        cancel_search(domains_search_id,'Domain')


# sender_email_list=[]  # Uncomment this to bypass the search (test purposes)
if len(sender_email_list) != 0:
    try:
        add_2_ref_set(sender_email_list,'Sender Email') # Add the iocs to the associated ref set
        sender_email_query=("SELECT QIDNAME(qid) AS 'Event Name', LOGSOURCENAME(logsourceid) AS 'Log Source', \"Mail-Sender\", "
                "\"Mail-Recipient\",\"Mail-Subject\", DATEFORMAT(starttime,'dd-MM-YYYY, hh:mm:ss a') AS 'Start Time', CATEGORYNAME(Category) As 'Category', "
                "sourceip AS 'Source IP',sourceport AS 'Source Port',destinationip AS 'Destination IP',destinationport AS 'Destination Port',username AS 'Username' "
                "FROM events WHERE REFERENCESETCONTAINS('IOC-Test-Sender-Email',\"Mail-Sender\") "
                "START PARSEDATETIME("+ "'" + search_period + "'" + ')'
        )
        # print(sender_email_query)
        sender_email_search_id = create_search(sender_email_query,'Sender Emails')
        check_sh_result(sender_email_search_id,'Sender Emails')
        get_results(sender_email_search_id,'sender_email_ioc')
        clear_ref_set('IOC-Test-Sender-Email')
    except KeyboardInterrupt:
        clear_ref_set('IOC-Test-Sender-Email')
        cancel_search(sender_email_search_id,'Sender Emails')


# sender_domain_list=[]  # Uncomment this to bypass the search (test purposes)
if len(sender_domain_list) != 0:
    try:
        add_2_ref_set(sender_domain_list,'Sender Domain') # Add the iocs to the associated ref set
        sender_domain_query=("SELECT QIDNAME(qid) AS 'Event Name', LOGSOURCENAME(logsourceid) AS 'Log Source', \"Sender-Domain\", \"Mail-Sender\", "
                "\"Mail-Recipient\", \"Mail-Subject\", DATEFORMAT(starttime,'dd-MM-YYYY, hh:mm:ss a') AS 'Start Time', CATEGORYNAME(Category) As 'Category', "
                "sourceip AS 'Source IP',sourceport AS 'Source Port',destinationip AS 'Destination IP',destinationport AS 'Destination Port',username AS 'Username' "
                "FROM events WHERE REFERENCESETCONTAINS('IOC-Test-Sender-Domain',\"Sender-Domain\") "
                "START PARSEDATETIME("+ "'" + search_period + "'" + ')'
        )
        # print(sender_domain_query)
        sender_domain_search_id = create_search(sender_domain_query,'Sender Domain')
        check_sh_result(sender_domain_search_id,'Sender Domains')
        get_results(sender_domain_search_id,'sender_domain_ioc')
        clear_ref_set('IOC-Test-Sender-Domain')
    except KeyboardInterrupt:
        clear_ref_set('IOC-Test-Sender-Domain')
        cancel_search(sender_domain_search_id,'Sender Domain')
        

stats() # Print stats info
exit(0)

'''
# search_id = '4350afa5-51cc-40a6-87f3-ae818790ef45'
'''
