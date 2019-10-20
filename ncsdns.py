#!/usr/bin/python

from copy import copy
from optparse import OptionParser, OptionValueError
import pprint
from random import seed, randint
import struct
from socket import *
from sys import exit, maxsize as MAXINT
from time import time, sleep

from libs.collections_backport import OrderedDict
from libs.dnslib.RR import *
from libs.dnslib.Header import Header
from libs.dnslib.QE import QE
from libs.inetlib.types import *
from libs.util import *

count = 0

EMPTY_RESOURCE_RECORD = None

# timeout in seconds to wait for reply
TIMEOUT = 5

# domain name and internet address of a root name server
ROOTNS_DN = "f.root-servers.net."
ROOTNS_IN_ADDR = "192.5.5.241"

# cache objects
class RR_A_Cache:
    def __init__(self):
        self.cache = dict()     # domain_name -> [(ip_address, expiration_time, authoritative)]

    def put(self,domain_name,ip_addr,expiration,authoritative=False):
        if domain_name not in self.cache:
            self.cache[domain_name] = dict()
        self.cache[domain_name][ip_addr] = (expiration,authoritative)

    def contains(self,domain_name):
        return domain_name in self.cache
    
    def getIpAddresses(self,domain_name):
        return list(self.cache[domain_name].keys())

    def getExpiration(self,domain_name,ip_address):
        return self.cache[domain_name][ip_address][0]
    
    def getAuthoritative(self,domain_name,ip_address):
        return self.cache[domain_name][ip_address][1]

    def __str__(self):
        return str(self.cache)

class CN_Cache:
    def __init__(self):
        self.cache = dict()     # domain_name -> (cname, expiration_time)

    def put(self,domain_name,canonical_name,expiration):
        self.cache[domain_name] = (canonical_name,expiration)

    def contains(self,domain_name):
        return domain_name in self.cache

    def getCanonicalName(self, domain_name):
        return self.cache[domain_name][0]

    def getCanonicalNameExpiration(self,domain_name):
        return self.cache[domain_name][1]

    def __str__(self):
        return str(self.cache)

class RR_NS_Cache:
    def __init__(self):
        self.cache = dict()     # domain_name -> (NS_record,expiration_time, authoritative)
        
    def put(self,zone_domain_name,name_server_domain_name,expiration,authoritative):
        if zone_domain_name not in self.cache:
            self.cache[zone_domain_name] = OrderedDict()
        self.cache[zone_domain_name][name_server_domain_name] = (expiration,authoritative)

    def get(self,zone_domain_name):
        list_name_servers = []
        for name_server in self.cache[zone_domain_name]:
            list_name_servers += [(name_server,self.cache[zone_domain_name][name_server][0],self.cache[zone_domain_name][name_server][1])]
        return list_name_servers

    def contains(self,zone_domain_name):
        return zone_domain_name in self.cache

    def __str__(self):
        return str(self.cache)


# >>> entry point of ncsdns.py <<<

# Seed random number generator with current time of day:
now = int(time())
seed(now)

# Initialize the pretty printer:
pp = pprint.PrettyPrinter(indent=3)

# Initialize the cache data structures
acache = RR_A_Cache()
acache.put(DomainName(ROOTNS_DN),InetAddr(ROOTNS_IN_ADDR),expiration=MAXINT,authoritative=True)

nscache = RR_NS_Cache()
nscache.put(DomainName("."),DomainName(ROOTNS_DN),expiration=MAXINT,authoritative=True)

cnamecache = CN_Cache()

# Recursive DNS lookup




# Parse the command line and assign us an ephemeral port to listen on:
def check_port(option, opt_str, value, parser):
    if value < 32768 or value > 61000:
        raise OptionValueError("need 32768 <= port <= 61000")
    parser.values.port = value

parser = OptionParser()
parser.add_option("-p", "--port", dest="port", type="int", action="callback",
                  callback=check_port, metavar="PORTNO", default=0,
                  help="UDP port to listen on (default: use an unused ephemeral port)")
(options, args) = parser.parse_args()

# Create a server socket to accept incoming connections from DNS
# client resolvers (stub resolvers):
ss = socket(AF_INET, SOCK_DGRAM)
ss.bind(("127.0.0.1", options.port))
serveripaddr, serverport = ss.getsockname()

# NOTE: In order to pass the test suite, the following must be the
# first line that your dns server prints and flushes within one
# second, to sys.stdout:
print("%s: listening on port %d" % (sys.argv[0], serverport))
sys.stdout.flush()

# Create a client socket on which to send requests to other DNS
# servers:
setdefaulttimeout(TIMEOUT)
cs = socket(AF_INET, SOCK_DGRAM)   

def randomStuff():
    inet = InetAddr("")
    addr = inet.toNetwork()
    print(addr)


def getEmptyRecord(data):
    header = Header.fromData(data)
    question_entry = QE.fromData(data,offset=len(header))
    rr = RR.fromData(data,offset=len(header)+ len(question_entry))
    return data[-(rr[1]):]


def constructQuery(header,domain_name,type):
    # print("...Original Header...\n")
    # header = Header.fromData(data)
    header_bin = header.pack()
   
    question_entry = QE(type=type,dn=domain_name)
    qe_bin = question_entry.pack()

    new_query = header_bin+qe_bin
    # print(new_query)
    return new_query


def deconstructData(data):
    header = Header.fromData(data)
    question_entry = QE.fromData(data,offset=len(header))
    resource_records = []
    offset = len(header) + len(question_entry)
    while True:
        try:
            resource_record = RR.fromData(data,offset=offset)
            offset += resource_record[1]
            resource_records.append(resource_record[0])
        except struct.error as error:
            break
    return (header,question_entry,resource_records)
    

def printDeconstructOutgoing(data):
    header = Header.fromData(data)
    question_entry = QE.fromData(data,offset=len(header))
    resource_records = []
    offset = len(header) + len(question_entry)
    while True:
        try:
            resource_record = RR.fromData(data,offset=offset)
            offset += resource_record[1]
            resource_records.append(resource_record)
        except struct.error as error:
            break
    
    print(header)
    print(question_entry)
    for resource_record in resource_records:
        if(resource_record[0]._type == 1):
            print("authoritative record", resource_record[0])
        elif(resource_record[0]._type == 2):
            print("name server record", resource_record[0])
        



def printDeconstructIncoming(data):
    header = Header.fromData(data)
    question_entry = QE.fromData(data,offset=len(header))
    resource_record = RR.fromData(data,offset=(len(header) + len(question_entry)))
    # resource_record2 = RR.fromData(data,offset=(len(header) + len(question_entry) + resource_record[1]))

    print("Header Is ##################################")
    print(header)
    print("Header len",len(header))
    print("Question entry is ############################")
    print(question_entry)
    print("Question len",len(question_entry))
    print("Resource record is #########################")
    print(resource_record[0])
    print("###################")


def getRecordsLength(resourceRecords):
    return sum([len(record) for record in resourceRecords])


def getRecords(answers,addresses,nameservers,data):
    rr_bin = b''
    for r in answers:
        try:
            rr_bin += r.pack()
        except (struct.error,Exception) as e:
            header,question_entry,resource_records = deconstructData(data)
            rr_bin += data[len(header)+len(question_entry):]
        
    for r in nameservers:
        try:
            rr_bin += r.pack()
        except struct.error as error:
            pass
        except Exception as e:
            pass
    for r in addresses:
        try:
            rr_bin += r.pack()
        except struct.error as error:
            pass
        except Exception as e:
            pass
    return rr_bin
def recursiveLookup(data,address):
    answers = []
    addresses = []
    nameservers = []
    cnames = []
    cs.sendto(data,(address,53))
    try:
        (serverData,serverAddress) = cs.recvfrom(512)
    except timeout:
        # if int(time()) - now > 2 * TIMEOUT:
        #     return data
        return None
    header,question_entry,resource_records = deconstructData(serverData)

    if(header._ancount > 0):
        for i in range(header._ancount):
            answers.append(resource_records[i])
        for i in range(header._ancount,len(resource_records)):
            if resource_records[i]._type == RR.TYPE_NS:
                nameservers.append(resource_records[i])
            elif resource_records[i]._type == RR.TYPE_A:
                addresses.append(resource_records[i])
        
        # print("Answers exists already :)")
        answer_record = resource_records[0]
        if answer_record._type == 1:
            # print("Found an answer! Returning...")
            
            return serverData
        elif answer_record._type == 5:
            # print("Canonical record detected:",answer_record)
            address_to_search = str(answer_record._cname)
            # print(address_to_search)
            

            cnameData = constructQuery(header=Header.fromData(data),
                                        domain_name=DomainName(address_to_search),type=QE.TYPE_A) + EMPTY_RESOURCE_RECORD 

            cnameServerData = recursiveLookup(cnameData,ROOTNS_IN_ADDR)

            if cnameServerData is not None:
                anscount = arcount = nscount = 0
                # print("Canonical server data returned for",answer_record,"is")
                # printDeconstructOutgoing(cnameServerData)
                cnameHeader,cnameQuestionEntry,cnameResourceRecords = deconstructData(cnameServerData)
                # print(hexdump(answer_record.pack()))
                cnameResourceRecordsBin = b''
                cnameResourceRecordsBin += answer_record.pack()
                anscount += 1
                
                # try:
                #     cnameResourceRecordsBin = answer_record.pack()
                # except struct.error as error:
                #     print(error)
                #     try:
                #         cnameResourceRecordsBin = serverData[len(header)+len(question_entry):]
                #     except (struct.error , Exception ) as e:
                #         print(e)
                #         cnameResourceRecordsBin = serverData[-(len(answer_record)):]
                # except Exception as e:
                #     pass
                
                for cnameRecord in cnameResourceRecords:
                    if cnameRecord._type == RR.TYPE_CNAME:
                        cnameResourceRecordsBin = cnameResourceRecordsBin + cnameRecord.pack()
                        anscount += 1
                    elif cnameRecord._type == RR.TYPE_A:
                        cnameResourceRecordsBin = cnameResourceRecordsBin + cnameRecord.pack()
                        anscount += 1
                    else:
                        break
                    
                # cnameFinalRecord = cnameResourceRecords[0]
                # cnameResourceRecordsBin += cnameFinalRecord.pack()
                # try:
                #     cnameResourceRecordsBin += cnameFinalRecord.pack()
                # except struct.error as error:
                #     try:
                #         cnameResourceRecordsBin += cnameServerData[len(cnameHeader)+len(cnameQuestionEntry):]
                #     except (struct.error , Exception ) as e:
                #         cnameResourceRecordsBin += cnameServerData[-(len(cnameFinalRecord)):]
                # except Exception as e:
                #     pass
                # if cnameResourceRecordsBin == b'':
                #     cnameResourceRecordsBin = cnameServerData[len(cnameHeader)+len(cnameQuestionEntry):]
                oldQuestionDomain = question_entry._dn
                oldQuestionString = oldQuestionDomain.__str__()
                cnameQuestionEntry = QE(type=QE.TYPE_A,dn=oldQuestionDomain)

                
                cnameHeader._aa = False
                cnameHeader._ra = True 
                cnameHeader._ancount = anscount
                cnameHeader._nscount = nscount
                cnameHeader._arcount = arcount

                newCnameServerData = cnameHeader.pack() + cnameQuestionEntry.pack() + cnameResourceRecordsBin
                # print("New data returned should be:")
                # printDeconstructOutgoing(newCnameServerData)

                return newCnameServerData

            else:
                print("ERROR - NO CANNONICAL RECORD FOUND, RETURNING...")
                return None
                                
    else:
        flag = 0
        for record in resource_records:
            if record._type == RR.TYPE_A:
                # print("Address Record found is", record)
                new_address = str(InetAddr.fromNetwork(record._addr))
                # print("---------------------------RECURSIVE CALL-------------------------------")
                newServerData = recursiveLookup(data, new_address)
                if(newServerData is not None):
                    # printDeconstructOutgoing(newServerData)
                    # h,q,rr = deconstructData(newServerData)
                    # for i in range(h._ancount):
                    #     answers.append(rr[i])
                    # for i in range(h._ancount,len(rr)):
                    #     if rr[i]._type == RR.TYPE_NS:
                    #         nameservers.append(rr[i])
                    #     elif rr[i]._type == RR.TYPE_A:
                    #         addresses.append(rr[i])
                    
                    # # print("Success! Sending response to Client")
                    
                    # flag = 1
                    # h._ancount = len(answers)
                    # h._nscount = len(nameservers)
                    # h._arcount = len(addresses)
                    # h._aa = False
                    # h._ra = True
                    # rr_bin = getRecords(answers,addresses,nameservers,newServerData)
                    # pp.pprint(answers)
                    # printDeconstructOutgoing(h.pack() + question_entry.pack() + rr_bin)
                    return newServerData
                    # return newServerData
                else:
                    print("DIDNT GET ANYTHING BACK, continue")
                    continue

            if flag == 1:
                break

        if flag == 0:
            for record in resource_records:
                if(record._type == RR.TYPE_NS):
                    new_address = str(record._nsdn)
                    # print("SEARCH FOR", new_address)
                    nsData = constructQuery(header= Header.fromData(data),
                                            domain_name=DomainName(new_address),type=QE.TYPE_A) + EMPTY_RESOURCE_RECORD
                    # print("-----------------------NS RECURSIVE CALL----------------")
                    nsServerData = recursiveLookup(nsData,ROOTNS_IN_ADDR)
                    if nsServerData is not None:
                        # print("Got from root")
                        # printDeconstructOutgoing(nsServerData)
                        nsHeader,nsQuestionEntry,nsResourceRecords = deconstructData(nsServerData)
                        if(len(nsResourceRecords) == 0):
                            continue
                        if(nsResourceRecords[0]._type==RR.TYPE_SOA):
                            # print("SOA detected")
                            return None
                        nsIpAddress = str(InetAddr.fromNetwork(nsResourceRecords[0]._addr))
                        # print("Data to resolve")
                        printDeconstructOutgoing(data)
                        # print("Resolved NS IP, now resolve:",question_entry,"using",nsIpAddress)
                        # print("-----------------------NS RECURSIVE CALL----------------")
                        newServerData = recursiveLookup(data, nsIpAddress)
                        if(newServerData is not None):
                            # print("Success! Sending response to Client")
                            # printDeconstructOutgoing(newServerData)
                            return newServerData
                        else:
                            continue
                elif(record._type == RR.TYPE_SOA):
                        # print("SOA detected, returning...")
                    return serverData
                else:   
                    continue

    print("Literally nothing can be done")
    returnRecord = EMPTY_RESOURCE_RECORD
    return header.pack() + question_entry.pack() + returnRecord

# This is a simple, single-threaded server that takes successive
# connections with each iteration of the following loop:
while 1:
    count += 1
    (data, client_address,) = ss.recvfrom(512) # DNS limits UDP msgs to 512 bytes
    
    if not data:
        logger.error("client provided no data")
        print("ERROR - NO DATA PROVIDED")
        continue
    print("Client address is",client_address)
    print("Query received from client is:\n%s" %(hexdump(data)))
    # dump = hexdump(data)

    # print(bytearray.fromhex(hexdump(data)).decode())
    #
    # header = Header.fromData(data)
    
    # printDeconstruct(data)

    # recursiveLookup(data)
    EMPTY_RESOURCE_RECORD = getEmptyRecord(data)
    serverData = recursiveLookup(data,ROOTNS_IN_ADDR)
    # print("Data returned is")
    # printDeconstructOutgoing(serverData)



    reply = serverData
    # print("My reply is")
    # printDeconstructOutgoing(serverData)
    if not reply:
        print("NO DATA FOUND")
        ss.sendto(b'hello',client_address)
    else:    
        logger.log(DEBUG2, "our reply in full:")
        logger.log(DEBUG2, hexdump(reply))
        ss.sendto(reply, client_address)
    # print("Count is",count)
    
