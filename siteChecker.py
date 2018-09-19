#!/usr/bin/python3
from urllib.request import urlopen
import json
import requests

def searcherAndChecker(query):
    obj = urlopen('https://api.duckduckgo.com/?q=' + str(query) + '&format=json&pretty=1')  # search query
    bytes = obj.read()
    jtext = bytes.decode('utf8')
    jobj = json.loads(jtext)  # store json of query
    increasable = True  # variable to help determine if there're more links in the search to scan
    index = 0;  # index for json to go through and get the urls from the search
    urls = []  # list for store all the site urls
    while increasable:  # loop to get all the urls from the search
        try:
            urls.append(jobj["RelatedTopics"][index]["FirstURL"])
            index += 1
        except IndexError:
            increasable = False  # there're no more urls so stop the loop
        except KeyError:
            try:
                index2 = 0
                while True:
                    urls.append(jobj["RelatedTopics"][index]["Topics"][index2]["FirstURL"])
                    index2 += 1
            except:
                index += 1
        except:
            index += 1


    NumberOfSites = len(urls)  # get the nymber of urls
    counter = 0
    while counter < NumberOfSites:  # loop to go through all the urls and scan them
        scanParams = {'apikey': 'xxxxccc',
                      'url': str(urls[counter])}
        scanResponse = requests.post('https://www.virustotal.com/vtapi/v2/url/scan', data=scanParams)
        reportParams = {'apikey': 'xxxxxxx',
                        'resource': str(urls[counter])}
        reportResponse = requests.post('https://www.virustotal.com/vtapi/v2/url/report', params=reportParams)
        try:  # trying to translate response to json
            jReport = reportResponse.json()
            result = int(jReport['positives'])  # check if the scanned site was detected to have any viruses
            if result > 0:
                print("the site " + str(urls[counter]) + "was detected by one of the scanners to have a virsus")
				f = open('links.txt', 'a')
				f.write(str(urls[counter]))
				f.write('\n')
				f.close()
            counter += 1
        except:  # request lib failed to translate response to json move to the next
            counter += 1

query = input('what do you want to search to have me check?\n')
searcherAndChecker(query)
