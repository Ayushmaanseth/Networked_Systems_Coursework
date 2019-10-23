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

    def deleteExpiredRecords(self,originalTime):
        for domain_name in self.cache.keys():
            flag = 0
            for ip_addr in self.cache[domain_name].keys():
                if self.cache[domain_name][ip_addr][0] < int(time()) - originalTime:
                    self.cache.pop(domain_name,None)
                    flag = 1
                    break
            if flag == 1:
                break

    

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

    def deleteExpiredRecords(self,originalTime):
        for domain_name in self.cache.keys():
            if self.cache[domain_name][1] < int(time()) - originalTime:
                self.cache.pop(domain_name,None)
                break



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
newQueryTime = int(time())

# Initialize the pretty printer:
pp = pprint.PrettyPrinter(indent=3)

# Initialize the cache data structures
acache = RR_A_Cache()
# acache.put(DomainName(ROOTNS_DN),InetAddr(ROOTNS_IN_ADDR).toNetwork(),expiration=MAXINT,authoritative=True)

# Just for testing purposes
# acache.put(DomainName("www.google.com"),InetAddr("172.217.169.36"),expiration=172800,authoritative=False)


nscache = RR_NS_Cache()
nscache.put(DomainName("."),DomainName(ROOTNS_DN),expiration=MAXINT,authoritative=True)

# nscache.put(DomainName("google.com"),DomainName("ns2.google.com"),expiration=172800,authoritative=True)

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
    
    print(header,"\n")
    print(question_entry,"\n")
    for resource_record in resource_records:
        if(resource_record[0]._type == 1):
            print("authoritative record\n", resource_record[0])
        elif(resource_record[0]._type == 2):
            print("name server record\n", resource_record[0])
        elif(resource_record[0]._type == RR.TYPE_CNAME):
            print("canonical_name record\n",resource_record[0])
        elif(resource_record[0]._type == RR.TYPE_AAAA):
            print("name server record\n", resource_record[0])

        



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

def getAdditionalRecords(nsResourceRecords):
    additionals = []
    for record in nsResourceRecords:
        if record._type == RR.TYPE_A:
            additionals.append(record)
    return additionals


def extractAddress(resource_records):
    addresses = []
    for record in resource_records:
        if record._type == RR.TYPE_A:
            addresses.append(record)
    return addresses

def getAddressFromCache(acache,domain_name):
    if acache.contains(domain_name):   
        list_addresses = acache.getIpAddresses(domain_name)
        final_addresses = []
        for address in list_addresses:
            if acache.getExpiration(domain_name,address) >= (int(time()) - now):
                final_addresses.append(address)
            else:
                continue
        print("LIST ADDRESS WITHOUT RR_A",list_addresses)
        print(RR_A(domain_name,acache.getExpiration(domain_name,list_addresses[0]), list_addresses[0]))
        addresses = list(map(lambda x: RR_A(domain_name,acache.getExpiration(domain_name,x), x),final_addresses))
        # print(RR_A(domain_name,acache.getExpiration(domain_name,list_addresses[0]),list_addresses[0]))
        for address in addresses:
            print("ADDRESS CACHED IS",address)
        # print(addresses)
        return addresses
    return []
    


def getNameserversFromCache(nscache,acache,domain_name):
    parents = []
    # parents.append(domain_name)
    parent_domain_name = domain_name.parent()
    while str(parent_domain_name) != "." :
            parents.append(parent_domain_name)
            parent_domain_name = parent_domain_name.parent()
    print("PARENTS ARE")
    pp.pprint(parents)
    additionals = []
    nameservers = []
    # name_servers_domains = []
    # parents = parents[:len(parents)-1]
    for parent in parents:
        if nscache.contains(parent):
            name_servers_domains = []
            print("Entering an NS into NSCACHE")
            name_servers_domains = nscache.get(parent)
            ns_temp = []
            # additonals = []
            for domain in name_servers_domains:
                # print("DOMAIN IS",type(domain[0]))
                # print(acache)
                if not acache.contains(domain[0]):
                    continue
                addresses = getAddressFromCache(acache,domain[0])
                ns_temp.append(domain)
                # print("DOMAIN OBJECT MAA HELP",domain)
                # print("SAALA CHUTIYA",addresses)
                additionals.extend(addresses)
                # RR_NS(domain_name,x[1],x[0])
            # print("BEHEN KA TAKKA",name_servers_domains)
            nameservers.extend(list(map(lambda x : RR_NS(parent,x[1],x[0]),ns_temp)))

    # print("NAME SERVERS GOT ARE",name_servers_domains)
    # nameservers = list(map(lambda x : RR_NS(parent,x[1],x[0]),name_servers_domains))
    print(nameservers)
    print(additionals)
    return nameservers,additionals
            

def putAddressInCache(acache,record):
    acache.put(record._dn,record._addr,record._ttl,False)

def putNSInCache(nscache,record):
    nscache.put(record._dn,record._nsdn,record._ttl ,True)

def putCNAMEInCache(cnamecache,cnameRecord):
    cnamecache.put(cnameRecord._dn,cnameRecord._cname,cnameRecord._ttl)

def putInCache(record):
    if record._type == RR.TYPE_A:
        acache.put(record._dn,record._addr,record._ttl,False)
    elif record._type == RR.TYPE_CNAME:
        cnamecache.put(record._dn,record._cname,record._ttl)
    elif record._type == RR.TYPE_NS:
        nscache.put(record._dn,record._nsdn,record._ttl ,True)

def findMoreCnames(cname):
    temp = cname
    cnames = []
    while cnamecache.contains(temp):        
        # if cnamecache.contains(temp):
            newCname = cnamecache.getCanonicalName(temp)
            cnames.append(RR_CNAME(temp,cnamecache.getCanonicalNameExpiration(temp),newCname))
            temp = newCname

    return cnames

def packRecords(records):
    recordBin = b''
    for record in records:
        recordBin += record.pack()

    return recordBin

def recursiveLookup(data,address):
    answers = []
    addresses = []
    nameservers = []
    cnames = []
    # CACHE
    # Only for final answer

    


    originalHeader,originalQuery,originalRecords = deconstructData(data)

    if int(time()) - newQueryTime > 50:
        print("TOOK A LOT OF TIME")
        originalHeader._rcode = Header.RCODE_SRVFAIL
        originalHeader._ra = 1
        return originalHeader.pack() + originalQuery.pack() + packRecords(originalRecords)

    if acache.contains(originalQuery._dn):
        print("USING FROM ADDRESS CACHE")
        # sleep(1)
        finalRecords = b''
        answers = getAddressFromCache(acache, originalQuery._dn)
        print("DID I ACTUALLY GET THE ANSWERS?",answers)
        if len(answers) > 0: 
            # finalRecords += answer.pack()
            nameservers,additionals = getNameserversFromCache(nscache,acache,originalQuery._dn)
            print("answers are",answers,type(answers))
            print("nameservers are",nameservers)
            # print("additionals are",additionals)

            originalHeader._ancount = len(answers)
            if len(nameservers) > 0:
                answers.extend(nameservers)
            if len(answers) > 0:
                answers.extend(additionals)
            for record in answers:
                try:
                    print(record)
                    finalRecords += record.pack()
                except (struct.error , Exception) as e:
                    pp.pprint(e)
                    continue


            # originalHeader._ancount = len(answers)
            originalHeader._nscount = len(nameservers)
            originalHeader._arcount = len(additionals)
            originalHeader._qr = 1
            originalHeader._aa = 0
            originalHeader._ra = 1

            # printDeconstructOutgoing(originalHeader.pack() + originalQuery.pack() + finalRecords)
            return originalHeader.pack() + originalQuery.pack() + finalRecords
            

    cs.sendto(data,(address,53))
    try:
        (serverData,serverAddress) = cs.recvfrom(512)
    except timeout: 
        # if int(time()) - now > 60:
        #     return data
        return None
    # printDeconstructOutgoing(serverData)
    header,question_entry,resource_records = deconstructData(serverData)

    if header._qdcount > 1:
        print("CAN'T RESOLVE MULTIPLE QUERIES, EXITING...")
        return data

    if(header._ancount > 0):
        for i in range(header._ancount):
            answers.append(resource_records[i])
        for i in range(header._ancount,len(resource_records)):
            if resource_records[i]._type == RR.TYPE_NS:
                nameservers.append(resource_records[i])
                putInCache(resource_records[i])
            elif resource_records[i]._type == RR.TYPE_A:
                addresses.append(resource_records[i])
                putInCache(resource_records[i])

        
        # print("Answers exists already :)")
        answer_record = resource_records[0]
        if answer_record._type == RR.TYPE_A:
            # print("Found an answer! Returning...")
            return serverData
        elif answer_record._type == 5:
            if cnamecache.contains(answer_record._dn) and cnamecache.getCanonicalNameExpiration(answer_record._dn) >= int(time()) - now:
                # pass
                cname = cnamecache.getCanonicalName(answer_record._dn)
                furtherCnames = findMoreCnames(cname)
                cname_addresses = []

                print("MORE CNAMES ARE",furtherCnames)
                if len(furtherCnames) == 0:
                    print("THIS IS ONLY CNAME, NOW GET ANSWER AND NS")
                    
                    cname_addresses.extend(getAddressFromCache(acache,cname))
                    if len(cname_addresses) > 0:
                        cname_addresses.insert(0,answer_record)
                        print("WE GOT ADDRESSES BITCHES")
                        cname_nameservers,cname_additionals = getNameserversFromCache(nscache,acache,cname)
                        cname_cache_bin = getRecords(cname_addresses,cname_additionals,cname_nameservers,data)

                        originalHeader._ancount = len(cname_addresses)
                        originalHeader._nscount = len(cname_nameservers)
                        originalHeader._arcount = len(cname_additionals)
                        originalHeader._qr = 1
                        originalHeader._aa = 0
                        originalHeader._ra = 1
                        originalHeader._rd = 0

                        # print("BOHOT ZYADA HARD")

                        # printDeconstructOutgoing(originalHeader.pack() + originalQuery.pack() + cname_cache_bin)

                        return originalHeader.pack() + originalQuery.pack() + cname_cache_bin

                    else:
                        pass

                else:
                    try:

                        cflag = 0
                        cname_addresses.extend(furtherCnames)

                        cname_addresses.extend(getAddressFromCache(acache,cname))
                        cname_nameservers,cname_additionals = getNameserversFromCache(nscache,acache,cname)

                        for furtherCname in furtherCnames:

                            # print("LOOK FOR THE CNAME",cname,"FOR ADDRESSES")
                            if(len(getAddressFromCache(acache,furtherCname._cname)) > 0):
                                cflag = 1

                            else:
                                qec = furtherCnames[-1]._dn
                                query = constructQuery(originalHeader,qec,QE.TYPE_A) + EMPTY_RESOURCE_RECORD
                                cnameCacheData = recursiveLookup(query,ROOTNS_IN_ADDR)
                                ch,cq,crr = deconstructData(cnameCacheData)
                                ch._ancount += len(furtherCnames)
                                crr_bin = b''
                                for furtherCname in furtherCnames:
                                    crr_bin += furtherCname.pack()
                                for cr in crr:
                                    crr_bin += cr.pack()

                                return ch.pack() + cq.pack() + crr_bin

                            cname_addresses.extend(getAddressFromCache(acache,furtherCname._cname))
                            cname_nameservers_temp,cname_additionals_temp = getNameserversFromCache(nscache,acache,furtherCname._cname)
                            cname_additionals.extend(cname_additionals_temp)
                            cname_nameservers.extend(cname_nameservers_temp)


                        cname_addresses.insert(0,answer_record)
                        print("FINAL CNAME ADDRS ARE",cname_addresses)
                        cname_cache_bin = getRecords(cname_addresses,cname_additionals,cname_nameservers,data)

                        originalHeader._ancount = len(cname_addresses)
                        originalHeader._nscount = len(cname_nameservers)
                        originalHeader._arcount = len(cname_additionals)
                        originalHeader._qr = 1
                        originalHeader._aa = 0
                        originalHeader._ra = 1
                        originalHeader._rd = 0

                        # print("BOHOT BOHOT ZYADA HARD")
                        
                        # printDeconstructOutgoing(originalHeader.pack() + originalQuery.pack() + cname_cache_bin)
                        if cflag == 1:
                            return originalHeader.pack() + originalQuery.pack() + cname_cache_bin
                        else:
                            print("NEED TO SEARCH SOME CNAME BS")
                            pass

                    except (struct.error,error,Exception) as e:
                        pass



            else:
                putInCache(answer_record)
            # print("Canonical record detected:",answer_record)
            address_to_search = str(answer_record._cname)
            # print(address_to_search)

            cnameData = constructQuery(header=Header.fromData(data),
                                        domain_name=DomainName(address_to_search),type=QE.TYPE_A) + EMPTY_RESOURCE_RECORD 
            cnameServerData = recursiveLookup(cnameData,ROOTNS_IN_ADDR)

            if cnameServerData is not None:
                anscount = arcount = nscount = 0
                print("Canonical server data returned for",answer_record,"is")
                # printDeconstructOutgoing(cnameServerData)
                cnameHeader,cnameQuestionEntry,cnameResourceRecords = deconstructData(cnameServerData)
                # print(hexdump(answer_record.pack()))
                cnameResourceRecordsBin = b''
                cnameResourceRecordsBin += answer_record.pack()
                anscount += 1
               
                cnt = 0
                for cnameRecord in cnameResourceRecords:
                    
                    if cnameRecord._type == RR.TYPE_CNAME:
                        cnameResourceRecordsBin = cnameResourceRecordsBin + cnameRecord.pack()
                        anscount += 1
                        putInCache(cnameRecord)
                    elif cnameRecord._type == RR.TYPE_A:
                        putInCache(cnameRecord)
                        cnameResourceRecordsBin = cnameResourceRecordsBin + cnameRecord.pack()
                        anscount += 1 
                    else:
                        break
                    cnt += 1
                    
                # for cnameRecord in cnameResourceRecords:
                #     if cnameRecord._type == RR.TYPE_NS:
                #         cnameResourceRecordsBin += cnameRecord.pack()

                # for i in range(cnameHeader._ancount+cnameHeader._nscount,len(cnameResourceRecords)):
                #     cnameResourceRecordsBin += cnameResourceRecords[i]

                rem = cnameResourceRecords[cnt:]
                print("REMAINING RECORDS PLEASE",rem)
                for cnameRecord in rem:
                    if cnameRecord._type == RR.TYPE_NS:
                        cnameResourceRecordsBin = cnameResourceRecordsBin + cnameRecord.pack()
                        nscount += 1
                        putInCache(cnameRecord)
                    elif cnameRecord._type == RR.TYPE_A:
                        cnameResourceRecordsBin = cnameResourceRecordsBin + cnameRecord.pack()
                        arcount += 1
                        putInCache(cnameRecord)

                
                oldQuestionDomain = question_entry._dn
                oldQuestionString = oldQuestionDomain.__str__()
                cnameQuestionEntry = QE(type=QE.TYPE_A,dn=oldQuestionDomain)

                
                cnameHeader._aa = 0
                cnameHeader._ra = 1 
                cnameHeader._qr = 1
                cnameHeader._ancount = anscount
                cnameHeader._nscount = nscount
                cnameHeader._arcount = arcount
                cnameHeader._rd = 0

                newCnameServerData = cnameHeader.pack() + cnameQuestionEntry.pack() + cnameResourceRecordsBin
                print("New data returned should be:")
                # printDeconstructOutgoing(newCnameServerData)

                return newCnameServerData

            else:
                print("ERROR - NO CANNONICAL RECORD FOUND, RETURNING...")
                return None
                                
    else:
        flag = 0
        ns = []
        add = []
        for resource_record in resource_records:
            if resource_record._type == RR.TYPE_NS:
                ns.append(resource_record)
                putInCache(resource_record)
            elif resource_record._type == RR.TYPE_A:
                add.append(resource_record)
                putInCache(resource_record)

        for record in resource_records:
            if record._type == RR.TYPE_A:
                putInCache(record)
                # addresses.append(record)
                # print("Address Record found is", record)
                new_address = str(InetAddr.fromNetwork(record._addr))
                # print("---------------------------RECURSIVE CALL-------------------------------")
                newServerData = recursiveLookup(data, new_address)
                if(newServerData is not None):
                    # printDeconstructOutgoing(newServerData)
                    h,q,rr = deconstructData(newServerData)
                    for i in range(h._ancount):
                        answers.append(rr[i])
                        putInCache(rr[i])
                    for i in range(h._ancount,len(rr)):
                        if rr[i]._type == RR.TYPE_NS:
                            nameservers.append(rr[i])
                            putInCache(rr[i])
                        elif rr[i]._type == RR.TYPE_A:
                            addresses.append(rr[i])
                            putInCache(rr[i])
                    
                    addresses.append(record)
                    for nameserver in ns:
                        putInCache(nameserver)
                        if str(record._dn) == str(nameserver._nsdn):
                            if nameserver not in nameservers:
                                nameservers.append(nameserver)
                            break

                    print("Success! Sending response to Client")
                    
                    flag = 1
                    h._ancount = len(answers)
                    h._nscount = len(nameservers)
                    h._arcount = len(addresses)
                    h._aa = 0
                    h._ra = 1
                    h._qr = 1
                    h._rd = 1
                    rr_bin = getRecords(answers,addresses,nameservers,newServerData)
                    pp.pprint(answers)
                    # printDeconstructOutgoing(h.pack() + question_entry.pack() + rr_bin)
                    return h.pack() + question_entry.pack() + rr_bin
                    # return newServerData
                else:
                    print("DIDNT GET ANYTHING BACK, continue")
                    continue

            if flag == 1:
                break
 
        if flag == 0:
            for record in resource_records:
                if(record._type == RR.TYPE_NS):
                    putInCache(record)
                    # nameservers.append(record)
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
                            return None # TODO IS THIS CORRECT? SHOULDNT I CONTINUE????
                        nsIpAddress = ROOTNS_IN_ADDR
                        if nsHeader._ancount == 0:
                            print("MAA KI CHUT")
                            continue
                        else:
                            nsIpAddress = str(InetAddr.fromNetwork(nsResourceRecords[0]._addr))
                            # print("Success! Sending response to Client")
                        # nsIpAddress = str(InetAddr.fromNetwork(nsResourceRecords[0]._addr))
                        
                            
                        # print("Data to resolve")
                        # printDeconstructOutgoing(data)
                        # print("Resolved NS IP, now resolve:",question_entry,"using",nsIpAddress)
                        # print("-----------------------NS RECURSIVE CALL----------------")
                        newServerData = recursiveLookup(data, nsIpAddress)
                        if(newServerData is not None):
                            h,q,rr = deconstructData(newServerData)
                            for i in range(h._ancount):
                                answers.append(rr[i])
                                putInCache(rr[i])
                            for i in range(h._ancount,len(rr)):
                                if rr[i]._type == RR.TYPE_NS:
                                    nameservers.append(rr[i])
                                    putInCache(rr[i])
                                elif rr[i]._type == RR.TYPE_A:
                                    addresses.append(rr[i])
                                    putInCache(rr[i])
                            
                            # print("Success! Sending response to Client")
                            
                            flag = 1
                            h._ancount = len(answers)
                            h._nscount = len(nameservers)
                            h._arcount = len(addresses)
                            h._aa = False
                            h._ra = True
                            h._qr = 1
                            h._rd = 0
                            rr_bin = getRecords(answers,addresses,nameservers,newServerData)
                            pp.pprint(answers)
                            # printDeconstructOutgoing(h.pack() + question_entry.pack() + rr_bin)
                            return h.pack() + question_entry.pack() + rr_bin
                            # return newServerData
                            
                            # print("Success! Sending response to Client")
                            # printDeconstructOutgoing(newServerData)
                            # return newServerData
                        else:
                            continue
                elif(record._type == RR.TYPE_SOA):
                        # print("SOA detected, returning...")
                    return serverData
                else:   
                    continue

    print("Literally nothing can be done")
    returnRecord = EMPTY_RESOURCE_RECORD
    header._rcode = Header.RCODE_SRVFAIL
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

    newQueryTime = int(time())
    acache.deleteExpiredRecords(now)
    cnamecache.deleteExpiredRecords(now)
    sleep(51)
    try:
        serverData = recursiveLookup(data,ROOTNS_IN_ADDR)
    except (Exception,struct.error,error) as e:
        header,question_entry,resource_records = deconstructData(data)
        header._rcode = Header.RCODE_SRVFAIL
        serverData = header.pack() + question_entry.pack() + EMPTY_RESOURCE_RECORD
    # print("Data returned is")
    # printDeconstructOutgoing(serverData)



    reply = serverData
    print(acache,"\n")
    print(nscache,"\n")
    print(cnamecache,"\n")
    print("My reply is")
    printDeconstructOutgoing(serverData)
    if not reply:
        print("NO DATA FOUND")
        ss.sendto(data,client_address)
    else:    
        logger.log(DEBUG2, "our reply in full:")
        logger.log(DEBUG2, hexdump(reply))
        ss.sendto(reply, client_address)
    # print("Count is",count)
    
