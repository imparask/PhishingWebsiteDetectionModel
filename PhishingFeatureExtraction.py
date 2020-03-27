# -*- coding: utf-8 -*-
"""
Created on Sat Mar 21 22:26:01 2020

@author: PARAS
"""

import numpy as np
import pandas as pd
import whois
import re
from bs4 import BeautifulSoup
import urllib.request
from datetime import datetime
import time
import socket


raw_data = pd.read_csv("Data/phishingurls1.csv") #loading websites data

raw_data.head()

seperation_of_protocol = raw_data['websites'].str.split("://",expand = True) #expand argument in the split method will give you a new column

print(seperation_of_protocol.head())

type(seperation_of_protocol)

seperation_domain_name = seperation_of_protocol[1].str.split("/",1,expand = True) #split(seperator,no of splits according to seperator(delimiter),expand)

type(seperation_domain_name)

seperation_domain_name.columns=["domain_name","address"] #renaming columns of data frame

print(seperation_domain_name.head())

#Concatenation of data frames
splitted_data = pd.concat([seperation_of_protocol[0],seperation_domain_name],axis=1)

splitted_data.columns = ['protocol','domain_name','address']

splitted_data.head()

def having_ip_address(url):
    try:
        match=re.search('(([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\/)|'  #IPv4
                    '((0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\/)'  #IPv4 in hexadecimal
                    '(?:[a-fA-F0-9]{1,4}:){7}[a-fA-F0-9]{1,4}',url)     #Ipv6
        if match:
            #print match.group()
            return 1
        else:
            #print 'No matching pattern found'
            return 0
    except:
        return 0
    
splitted_data['Having_IP'] = raw_data['websites'].apply(having_ip_address)


def long_url(l):
    """This function is defined in order to differntiate website based on the length of the URL"""
    try:
        if len(l) < 54:
            return 0
        elif len(l) >= 54 and len(l) <= 75:
            return 2
        return 1
    except:
        return 1

#Applying the above defined function in order to divide the websites into 3 categories

splitted_data['URL_Length'] = raw_data['websites'].apply(long_url)


def have_at_symbol(l):
    """This function is used to check whether the URL contains @ symbol or not"""
    try:
        if "@" in l:
            return 1
        return 0
    except:
        return 1

splitted_data['Having_@_symbol'] = raw_data['websites'].apply(have_at_symbol)


def redirection(l):
    """If the url has symbol(//) after protocol then such URL is to be classified as phishing """
    try:
        if "//" in l:
            return 1
        return 0
    except:
        return 1

splitted_data['Redirection_//_symbol'] = seperation_of_protocol[1].apply(redirection)


def prefix_suffix_seperation(l):
    try:
        if '-' in l:
            return 1
        return 0
    except:
        return 1

splitted_data['Prefix_suffix_seperation'] = seperation_domain_name['domain_name'].apply(prefix_suffix_seperation)

def sub_domains(l):
    
    try:
        if l.count('.') < 3:
            return 0
        elif l.count('.') == 3:
            return 2
        return 1
    except:
        return 1

splitted_data['Sub_domains'] = splitted_data['domain_name'].apply(sub_domains)

def shortening_service(url):
    try:
        match=re.search('bit\.ly|goo\.gl|shorte\.st|go2l\.ink|x\.co|ow\.ly|t\.co|tinyurl|tr\.im|is\.gd|cli\.gs|'
                    'yfrog\.com|migre\.me|ff\.im|tiny\.cc|url4\.eu|twit\.ac|su\.pr|twurl\.nl|snipurl\.com|'
                    'short\.to|BudURL\.com|ping\.fm|post\.ly|Just\.as|bkite\.com|snipr\.com|fic\.kr|loopt\.us|'
                    'doiop\.com|short\.ie|kl\.am|wp\.me|rubyurl\.com|om\.ly|to\.ly|bit\.do|t\.co|lnkd\.in|'
                    'db\.tt|qr\.ae|adf\.ly|goo\.gl|bitly\.com|cur\.lv|tinyurl\.com|ow\.ly|bit\.ly|ity\.im|'
                    'q\.gs|is\.gd|po\.st|bc\.vc|twitthis\.com|u\.to|j\.mp|buzurl\.com|cutt\.us|u\.bb|yourls\.org|'
                    'x\.co|prettylinkpro\.com|scrnch\.me|filoops\.info|vzturl\.com|qr\.net|1url\.com|tweez\.me|v\.gd|tr\.im|link\.zip\.net',url)
        if match:
            return 1
        return 0
    except TypeError:
        return 1
    

splitted_data['tiny_url'] = raw_data['websites'].apply(shortening_service)


def web_traffic(url):
    try:
        rank = BeautifulSoup(urllib.request.urlopen("http://data.alexa.com/data?cli=10&dat=s&url=" + url).read()).find("REACH")['RANK']
    except:
        return 1
    rank= int(rank)
    print(rank)
    if (rank<100000):
        return 0
    else:
        return 2
    
splitted_data['web_traffic'] = raw_data['websites'].apply(web_traffic)


def domain_registration_length_sub(domain):
    expiration_date = domain.expiration_date
    today = time.strftime('%Y-%m-%d')
    today = datetime.strptime(today, '%Y-%m-%d')
    if expiration_date is None:
        return 1
    elif type(expiration_date) is list or type(today) is list :
        return 2             #If it is a type of list then we can't select a single value from list. So,it is regarded as suspected website  
    else:
        registration_length = abs((expiration_date - today).days)
        if registration_length / 365 <= 1:
            return 1
        else:
            return 0
        
def domain_registration_length_main(domain):
    dns = 0
    try:
        domain_name = whois.whois(domain)
    except:
        dns = 1
        
    if dns == 1:
        return 1
    else:
        return domain_registration_length_sub(domain_name)
    
splitted_data['domain_registration_length'] = splitted_data['domain_name'].apply(domain_registration_length_main)

def dns_record(domain):
    dns = 0
    try:
        domain_name = whois.whois(domain)
        print(domain_name)
    except:
        dns = 1
        
    if dns == 1:
        return 1
    else:
        return dns
    
splitted_data['dns_record'] = splitted_data['domain_name'].apply(dns_record)


def statistical_report(url):
    try:
        hostname = url
        h = [(x.start(0), x.end(0)) for x in re.finditer('https://|http://|www.|https://www.|http://www.', hostname)]
        z = int(len(h))
        if z != 0:
            y = h[0][1]
            hostname = hostname[y:]
            h = [(x.start(0), x.end(0)) for x in re.finditer('/', hostname)]
            z = int(len(h))
            if z != 0:
                hostname = hostname[:h[0][0]]
        url_match=re.search('at\.ua|usa\.cc|baltazarpresentes\.com\.br|pe\.hu|esy\.es|hol\.es|sweddy\.com|myjino\.ru|96\.lt|ow\.ly',url)
        try:
            ip_address = socket.gethostbyname(hostname)
            ip_match=re.search('146\.112\.61\.108|213\.174\.157\.151|121\.50\.168\.88|192\.185\.217\.116|78\.46\.211\.158|181\.174\.165\.13|46\.242\.145\.103|121\.50\.168\.40|83\.125\.22\.219|46\.242\.145\.98|107\.151\.148\.44|107\.151\.148\.107|64\.70\.19\.203|199\.184\.144\.27|107\.151\.148\.108|107\.151\.148\.109|119\.28\.52\.61|54\.83\.43\.69|52\.69\.166\.231|216\.58\.192\.225|118\.184\.25\.86|67\.208\.74\.71|23\.253\.126\.58|104\.239\.157\.210|175\.126\.123\.219|141\.8\.224\.221|10\.10\.10\.10|43\.229\.108\.32|103\.232\.215\.140|69\.172\.201\.153|216\.218\.185\.162|54\.225\.104\.146|103\.243\.24\.98|199\.59\.243\.120|31\.170\.160\.61|213\.19\.128\.77|62\.113\.226\.131|208\.100\.26\.234|195\.16\.127\.102|195\.16\.127\.157|34\.196\.13\.28|103\.224\.212\.222|172\.217\.4\.225|54\.72\.9\.51|192\.64\.147\.141|198\.200\.56\.183|23\.253\.164\.103|52\.48\.191\.26|52\.214\.197\.72|87\.98\.255\.18|209\.99\.17\.27|216\.38\.62\.18|104\.130\.124\.96|47\.89\.58\.141|78\.46\.211\.158|54\.86\.225\.156|54\.82\.156\.19|37\.157\.192\.102|204\.11\.56\.48|110\.34\.231\.42',ip_address)  
        except:
            return 1

        if url_match:
            return 1
        else:
            return 0
    except:
        return 1
    
splitted_data['statistical_report'] = raw_data['websites'].apply(statistical_report)


def age_of_domain_sub(domain):
    
    try:
        creation_date = domain.creation_date
        expiration_date = domain.expiration_date
        if ((expiration_date is None) or (creation_date is None)):
            return 1
        elif ((type(expiration_date) is list) or (type(creation_date) is list)):
            return 2
        else:
            ageofdomain = abs((expiration_date - creation_date).days)
            if ((ageofdomain/30) < 6):
                return 1
            else:
                return 0
    except:
        return 1
        
def age_of_domain_main(domain):
    try:
        dns = 0
        try:
            domain_name = whois.whois(domain)
        except:
            dns = 1
        
        if dns == 1:
            return 1
        else:
            return age_of_domain_sub(domain_name)
    except:
        return 1
    
splitted_data['age_domain'] = splitted_data['domain_name'].apply(age_of_domain_main)


def https_token(url):
    try:
        match=re.search('https://|http://',url)
        if match.start(0)==0:
            url=url[match.end(0):]
        match=re.search('http|https',url)
        if match:
            return 1
        else:
            return 0
    except:
        return 1
    
splitted_data['http_token'] = raw_data['websites'].apply(https_token)


splitted_data.drop(splitted_data.iloc[:, 0:3], inplace = True, axis = 1)
splitted_data.to_csv("Data/splitted_data4.csv")




