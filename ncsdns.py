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

    """
    Method for deleting expired records, Checks time to live against elapsed time
    """

    def deleteExpiredRecords(self,originalTime):
        print("DELETING NOW....")
        l = list(self.cache.keys())
        for domain_name in l:
            if domain_name in self.cache.keys():
                l2 = list(self.cache[domain_name].keys())
                for ip_addr in l2:
                    if ip_addr in self.cache[domain_name].keys() and self.cache[domain_name][ip_addr][0] < int(time()) - originalTime:
                        self.cache.pop(domain_name,None)
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

    """
    Method for deleting expired records, Checks time to live against elapsed time
    """

    def deleteExpiredRecords(self,originalTime):
        l = list(self.cache.keys())
        for domain_name in l:
            if domain_name in self.cache.keys() and self.cache[domain_name][1] < int(time()) - originalTime:
                self.cache.pop(domain_name,None)



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

# For checking 60 seconds timeout
newQueryTime = int(time()) 

# Initialize the pretty printer:
pp = pprint.PrettyPrinter(indent=3)

# Initialize the cache data structures
acache = RR_A_Cache()


nscache = RR_NS_Cache()
nscache.put(DomainName("."),DomainName(ROOTNS_DN),expiration=MAXINT,authoritative=True)


cnamecache = CN_Cache()




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
    """
    Returns an empty record with type = RR.TYPE_UNKNOWN
    """
    header = Header.fromData(data)
    question_entry = QE.fromData(data,offset=len(header))
    rr = RR.fromData(data,offset=len(header)+ len(question_entry))
    return data[-(rr[1]):]


def constructQuery(header,domain_name,type):

    """
    Constructs a binary-packed query using header, domain name and query type
    """
    
    header_bin = header.pack()
   
    question_entry = QE(type=type,dn=domain_name)
    qe_bin = question_entry.pack()

    new_query = header_bin+qe_bin
    # print(new_query)
    return new_query


def deconstructData(data):

    """
    Deconstructs/Unpacks given binary data to Header, QE objects and a list of RR objects
    """
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
    """
    Utility function for printing binary-packed query
    """
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

    """
    Another utility function for printing incoming data with no resource records
    """
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
    """
    Returns total length of a list of resource records as packed in binary
    """
    return sum([len(record) for record in resourceRecords])


def getRecords(answers,addresses,nameservers,data):

    """
    Converts 3 lists - answer records, authorities and additional records into binary
    Returns binary packed records
    """
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

    """
    Utility function to extract glue records and answers
    """

    additionals = []
    for record in nsResourceRecords:
        if record._type == RR.TYPE_A:
            additionals.append(record)
    return additionals


def extractAddress(resource_records):

    """
    Utility function to extract glue records and answers
    """

    addresses = []
    for record in resource_records:
        if record._type == RR.TYPE_A:
            addresses.append(record)
    return addresses

def getAddressFromCache(acache,domain_name):
    """
    Gets non-expired ip addresses from RR_A cache using given domain name

    """

    if acache.contains(domain_name):   
        list_addresses = acache.getIpAddresses(domain_name)
        final_addresses = []
        for address in list_addresses:
            """
            Do not return expired records
            """
            if acache.getExpiration(domain_name,address) >= (int(time()) - now):
                final_addresses.append(address)
            else:
                continue
        # print("LIST ADDRESS WITHOUT RR_A",list_addresses)
        # print(RR_A(domain_name,acache.getExpiration(domain_name,list_addresses[0]), list_addresses[0]))
        addresses = list(map(lambda x: RR_A(domain_name,acache.getExpiration(domain_name,x), x),final_addresses))
        # print(RR_A(domain_name,acache.getExpiration(domain_name,list_addresses[0]),list_addresses[0]))
        # for address in addresses:
            # print("ADDRESS CACHED IS",address)
        # print(addresses)
        return addresses
    return []
    


def getNameserversFromCache(nscache,acache,domain_name):

    """
    Gets nameservers and non-expired additional glue records from RR_NS and RR_A caches respectively

    """

    parents = []
    # parents.append(domain_name)
    parent_domain_name = domain_name.parent()
    while str(parent_domain_name) != "." :
            parents.append(parent_domain_name)
            parent_domain_name = parent_domain_name.parent()
    # print("PARENTS ARE")
    # pp.pprint(parents)
    additionals = []
    nameservers = []
    # name_servers_domains = []
    # parents = parents[:len(parents)-1]
    for parent in parents:
        if nscache.contains(parent):
            name_servers_domains = []
            # print("Entering an NS into NSCACHE")
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
    # print(nameservers)
    # print(additionals)
    return nameservers,additionals
            

def putAddressInCache(acache,record):
    acache.put(record._dn,record._addr,record._ttl,False)

def putNSInCache(nscache,record):
    nscache.put(record._dn,record._nsdn,record._ttl ,True)

def putCNAMEInCache(cnamecache,cnameRecord):
    cnamecache.put(cnameRecord._dn,cnameRecord._cname,cnameRecord._ttl)

def putInCache(record):
    """
    Puts record in respective cache using type of record

    """

    if record._type == RR.TYPE_A:
        acache.put(record._dn,record._addr,record._ttl,False)
    elif record._type == RR.TYPE_CNAME:
        cnamecache.put(record._dn,record._cname,record._ttl)
    elif record._type == RR.TYPE_NS:
        nscache.put(record._dn,record._nsdn,record._ttl ,True)

def findMoreCnames(cname):

    """
    Finds more cnames from cache if given a single cname

    """

    temp = cname
    cnames = []
    while cnamecache.contains(temp):        
        # if cnamecache.contains(temp):
            newCname = cnamecache.getCanonicalName(temp)
            cnames.append(RR_CNAME(temp,cnamecache.getCanonicalNameExpiration(temp),newCname))
            temp = newCname

    return cnames

def packRecords(records):

    """
    Utility function for packing records list to binary
    """

    recordBin = b''
    for record in records:
        recordBin += record.pack()

    return recordBin

def recursiveLookup(data,address):

    """
    Main recursive function - does everything
    """

    answers = []
    addresses = []
    nameservers = []
    cnames = []


    originalHeader,originalQuery,originalRecords = deconstructData(data)

    # If query took more than 50 seconds, returns server fail
    if int(time()) - newQueryTime > 50:
        """
        50 seconds on a safer side for timeout, returning SERV_FAIL RCODE in Header
        """
        print("TOOK A LOT OF TIME")
        originalHeader._rcode = Header.RCODE_SRVFAIL
        originalHeader._ra = 1
        return originalHeader.pack() + originalQuery.pack() + packRecords(originalRecords)

    #If answer already in cache, extract from cache

    if acache.contains(originalQuery._dn):
        
        finalRecords = b''
        answers = getAddressFromCache(acache, originalQuery._dn)
        
        #If length of answers is not zero, get from cache, else resolve manually
        if len(answers) > 0: 
            
            nameservers,additionals = getNameserversFromCache(nscache,acache,originalQuery._dn)

            """
            Adjust header answer count for sending client back answer
            """
            
            originalHeader._ancount = len(answers)

            if len(nameservers) > 0:
                answers.extend(nameservers)
            if len(answers) > 0:
                answers.extend(additionals)
            for record in answers:
                """
                Packing records into binary
                """
                try:
                    # print(record)
                    finalRecords += record.pack()
                except (struct.error , Exception) as e:
                    pp.pprint(e)
                    continue


            """
            Adjust header attirbutes accordingly for sending client back answer
            """
            originalHeader._nscount = len(nameservers)
            originalHeader._arcount = len(additionals)
            originalHeader._qr = 1
            originalHeader._aa = 0
            originalHeader._ra = 1

            
            return originalHeader.pack() + originalQuery.pack() + finalRecords
            
    # Manual resolving code
    cs.sendto(data,(address,53))
    try:
        # Send to new address and get data back
        (serverData,serverAddress) = cs.recvfrom(512)
    except (timeout,error):
        #If timeout (greater than default timeout of 5 seconds of dig) , returns None 
        return None
    
    header,question_entry,resource_records = deconstructData(serverData)

    if header._qdcount > 1:
        print("CAN'T RESOLVE MULTIPLE QUERIES, EXITING...")
        """
        Can't resolve multiple queries as mentioned in negative requirements
        """
        return data

    if(header._ancount > 0):
        """
        Answer(s) exists already, no need to go further
        """
        for i in range(header._ancount):
            answers.append(resource_records[i])
        for i in range(header._ancount,len(resource_records)):
            if resource_records[i]._type == RR.TYPE_NS:
                nameservers.append(resource_records[i])
                putInCache(resource_records[i])
            elif resource_records[i]._type == RR.TYPE_A:
                addresses.append(resource_records[i])
                putInCache(resource_records[i])

        
        
        answer_record = resource_records[0]
        if answer_record._type == RR.TYPE_A:
            """
            If address, return binary packed server data
            """
           
            return serverData
        elif answer_record._type == 5:
            """
            If type is CNAME, resolve the cname again from ROOT_DNS
            """
            if cnamecache.contains(answer_record._dn) and cnamecache.getCanonicalNameExpiration(answer_record._dn) >= int(time()) - now:
                # pass
                cname = cnamecache.getCanonicalName(answer_record._dn)
                furtherCnames = findMoreCnames(cname)
                cname_addresses = []
                if len(furtherCnames) == 0:
                    """
                    Only single CNAME, so just find addresses of the CNAME
                    """
                    cname_addresses.extend(getAddressFromCache(acache,cname))
                    if len(cname_addresses) > 0:
                        cname_addresses.insert(0,answer_record)
                        
                        cname_nameservers,cname_additionals = getNameserversFromCache(nscache,acache,cname)
                        cname_cache_bin = getRecords(cname_addresses,cname_additionals,cname_nameservers,data)

                        originalHeader._ancount = len(cname_addresses)
                        originalHeader._nscount = len(cname_nameservers)
                        originalHeader._arcount = len(cname_additionals)
                        originalHeader._qr = 1
                        originalHeader._aa = 0
                        originalHeader._ra = 1
                        originalHeader._rd = 0

                        return originalHeader.pack() + originalQuery.pack() + cname_cache_bin

                    else:
                        """
                        If we could not find any addresses for cnames, resolve manually
                        """
                        pass

                else:
                    """
                    CNAME itself has cnames(s), so get all CNAMES and use those
                    """
                    try:

                        cflag = 0
                        cname_addresses.extend(furtherCnames)

                        """
                        Get answers, nameservers and additionals
                        """
                        cname_addresses.extend(getAddressFromCache(acache,cname))
                        cname_nameservers,cname_additionals = getNameserversFromCache(nscache,acache,cname)

                        for furtherCname in furtherCnames:

                            # print("LOOK FOR THE CNAME",cname,"FOR ADDRESSES")
                            if(len(getAddressFromCache(acache,furtherCname._cname)) > 0):
                                """
                                Extra condition to make sure addresses of cnames haven't expired yet
                                If length of list of addresses of cname is zero, then resolve cnames again 
                                """
                                cflag = 1

                            # else:
                            #     qec = furtherCnames[-1]._dn
                            #     query = constructQuery(originalHeader,qec,QE.TYPE_A) + EMPTY_RESOURCE_RECORD
                            #     cnameCacheData = recursiveLookup(query,ROOTNS_IN_ADDR)
                            #     ch,cq,crr = deconstructData(cnameCacheData)
                            #     ch._ancount += len(furtherCnames)
                            #     crr_bin = b''
                            #     for furtherCname in furtherCnames:
                            #         crr_bin += furtherCname.pack()
                            #     for cr in crr:
                            #         crr_bin += cr.pack()

                            #     return ch.pack() + cq.pack() + crr_bin
                            """
                            Add all additional and glue records into pre-exisiting records to report 
                            all possible high-level authorities for each CNAME
                            """
                            cname_addresses.extend(getAddressFromCache(acache,furtherCname._cname))
                            cname_nameservers_temp,cname_additionals_temp = getNameserversFromCache(nscache,acache,furtherCname._cname)
                            cname_additionals.extend(cname_additionals_temp)
                            cname_nameservers.extend(cname_nameservers_temp)


                        cname_addresses.insert(0,answer_record)
                        # print("FINAL CNAME ADDRS ARE",cname_addresses)
                        cname_cache_bin = getRecords(cname_addresses,cname_additionals,cname_nameservers,data)

                        """
                        Adjust header attributes accordingly for returning answer
                        """
                        originalHeader._ancount = len(cname_addresses)
                        originalHeader._nscount = len(cname_nameservers)
                        originalHeader._arcount = len(cname_additionals)
                        originalHeader._qr = 1
                        originalHeader._aa = 0
                        originalHeader._ra = 1
                        originalHeader._rd = 0

                        if cflag == 1:
                            return originalHeader.pack() + originalQuery.pack() + cname_cache_bin
                        else:
                            """
                            If the addresses expired, need to find address of CNAME manually
                            """
                            # print("NEED TO SEARCH SOME CNAME")
                            pass

                    except (struct.error,error,Exception) as e:
                        pass


            else:
                """
                CNAME not in cache, resolve CNAME manually
                """
                putInCache(answer_record)
            # print("Canonical record detected:",answer_record)
            address_to_search = str(answer_record._cname)
            # print(address_to_search)

            cnameData = constructQuery(header=Header.fromData(data),
                                        domain_name=DomainName(address_to_search),type=QE.TYPE_A) + EMPTY_RESOURCE_RECORD 

            """
            Recursive call for CNAME
            """
            cnameServerData = recursiveLookup(cnameData,ROOTNS_IN_ADDR)

            if cnameServerData is not None:
                anscount = arcount = nscount = 0
                cnameHeader,cnameQuestionEntry,cnameResourceRecords = deconstructData(cnameServerData)
    
                cnameResourceRecordsBin = b''
                cnameResourceRecordsBin += answer_record.pack()
                anscount += 1
               
                cnt = 0
                for cnameRecord in cnameResourceRecords:
                    """
                    Pack cnames in binary
                    """
                    
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
                    
                """
                Pack authorities and glue records in binary
                """
                rem = cnameResourceRecords[cnt:]
                # print("REMAINING RECORDS PLEASE",rem)
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
                # print("New data returned should be:")
                # printDeconstructOutgoing(newCnameServerData)

                return newCnameServerData

            else:
                print("ERROR - NO CANNONICAL RECORD FOUND, RETURNING...")
                return None
                                
    else:
        """
        No answers found, start searching glue records
        """
        flag = 0
        ns = []
        add = []
        """
        Utility for loops for grouping records into ns(nameservers) list and add(addresses) lisr
        """
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
                
                new_address = str(InetAddr.fromNetwork(record._addr))
                """---------------------------RECURSIVE CALL-------------------------------)"""
                newServerData = recursiveLookup(data, new_address)
                if(newServerData is not None):
                    """
                    Get header (in h), question entry (in q) and records (in rr)
                    for sending back to client for resolved answer
                    """
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
                    
                    """
                    Utility code for additional glue records and authorities
                    """
                    addresses.append(record)
                    for nameserver in ns:
                        putInCache(nameserver)
                        if str(record._dn) == str(nameserver._nsdn):
                            if nameserver not in nameservers:
                                nameservers.append(nameserver)
                            break

                    print("Success! Sending response to Client")
                    """
                    Set the header appropriately w.r.t its attributes for returning final answer
                    """
                    flag = 1
                    h._ancount = len(answers)
                    h._nscount = len(nameservers)
                    h._arcount = len(addresses)
                    h._aa = 0
                    h._ra = 1
                    h._qr = 1
                    h._rd = 1
                    rr_bin = getRecords(answers,addresses,nameservers,newServerData)
                    # pp.pprint(answers)
                    # printDeconstructOutgoing(h.pack() + question_entry.pack() + rr_bin)
                    return h.pack() + question_entry.pack() + rr_bin
                    # return newServerData
                else:
                    print("DIDNT GET ANYTHING BACK, continue")
                    continue

            if flag == 1:
                break
 
        if flag == 0:
            """
            NO glue records as well, resolve authority(ies) and then resolve 
            original question entry
            """
            for record in resource_records:
                if(record._type == RR.TYPE_NS):
                    putInCache(record)
                    # nameservers.append(record)
                    new_address = str(record._nsdn)
                    # print("SEARCH FOR", new_address)
                    nsData = constructQuery(header= Header.fromData(data),
                                            domain_name=DomainName(new_address),type=QE.TYPE_A) + EMPTY_RESOURCE_RECORD
                    """-----------------------NS RECURSIVE CALL----------------)"""
                    nsServerData = recursiveLookup(nsData,ROOTNS_IN_ADDR)
                    if nsServerData is not None:
                        # print("Got from root")
                        # printDeconstructOutgoing(nsServerData)
                        nsHeader,nsQuestionEntry,nsResourceRecords = deconstructData(nsServerData)
                        if(len(nsResourceRecords) == 0):
                            """
                            Didnt find any answers for the authority, 
                            continue resolving another authority
                            """
                            continue
                        if(nsResourceRecords[0]._type==RR.TYPE_SOA):
                            """
                            Not supposed to have SOA, so return None
                            """
                            # print("SOA detected")
                            return None 
                        nsIpAddress = ROOTNS_IN_ADDR
                        if nsHeader._ancount == 0:
                            """
                            Didnt find any answers for the authority, 
                            continue resolving another authority
                            """
                            continue
                        else:
                            """
                            Extract ip address of answer record got in resolving authority  
                            """
                            nsIpAddress = str(InetAddr.fromNetwork(nsResourceRecords[0]._addr))
                            # print("Success! Sending response to Client")
                        # nsIpAddress = str(InetAddr.fromNetwork(nsResourceRecords[0]._addr))
                        
                            
                        # print("Data to resolve")
                        # printDeconstructOutgoing(data)
                        # print("Resolved NS IP, now resolve:",question_entry,"using",nsIpAddress)
                        """----------------RECURSIVE CALL TO RESOLVE ORIGINAL QUESTION----------------"""
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
                            """
                            Set the header appropriately w.r.t its attributes for returning final answer
                            """
                            h._ancount = len(answers)
                            h._nscount = len(nameservers)
                            h._arcount = len(addresses)
                            h._aa = False
                            h._ra = True
                            h._qr = 1
                            h._rd = 1
                            rr_bin = getRecords(answers,addresses,nameservers,newServerData)
                            # pp.pprint(answers)
                            # printDeconstructOutgoing(h.pack() + question_entry.pack() + rr_bin)
                            return h.pack() + question_entry.pack() + rr_bin
                            # return newServerData
                            
                            # print("Success! Sending response to Client")
                            # printDeconstructOutgoing(newServerData)
                            # return newServerData
                        
                        else:
                            """
                            If we couldt do anything for this authority,
                            then try the next one
                            """
                            continue
                elif(record._type == RR.TYPE_SOA):
                    """
                    Handling SOA by returning just the original data
                    """
                        # print("SOA detected, returning...")
                    
                    return serverData
                else:   
                    continue

    print("Literally nothing can be done")
    """
    Server tried everything but failed to resolve, return SERV_FAIL RCODE in Header
    """
    returnRecord = EMPTY_RESOURCE_RECORD
    header._rcode = Header.RCODE_SRVFAIL
    return header.pack() + question_entry.pack() + returnRecord

# This is a simple, single-threaded server that takes successive
# connections with each iteration of the following loop:
while 1:
    recurseCount = 0
    count += 1
    (data, client_address,) = ss.recvfrom(512) # DNS limits UDP msgs to 512 bytes
    
    if not data:
        logger.error("client provided no data")
        print("ERROR - NO DATA PROVIDED")
        continue
    print("Client address is",client_address)
    print("Query received from client is:\n%s" %(hexdump(data)))
    
    EMPTY_RESOURCE_RECORD = getEmptyRecord(data)

    """
    Time for checking 60 seconds timeout before each query
    """
    newQueryTime = int(time())
    """
    Clean up caches 
    """
    try:
        acache.deleteExpiredRecords(now)
        cnamecache.deleteExpiredRecords(now)
    except (Exception,struct.error):
        pass
    except:
        pass
    """
    Call recursiveLookup method with root address for resolving query
    """
    try:
        serverData = recursiveLookup(data,ROOTNS_IN_ADDR)
    except (Exception,struct.error,error) as e:
        recurseCount += 1
        if recurseCount == 3:
            header,question_entry,resource_records = deconstructData(data)
            header._rcode = Header.RCODE_SRVFAIL
            serverData = header.pack() + question_entry.pack() + EMPTY_RESOURCE_RECORD
        else:
            serverData = recursiveLookup(data,ROOTNS_IN_ADDR)
    # print("Data returned is")
    # printDeconstructOutgoing(serverData)


    """
    Reply back
    """
    reply = serverData
    print("My reply is")
    printDeconstructOutgoing(serverData)
    if not reply:
        print("NO DATA FOUND")
        header,question_entry,resource_records = deconstructData(data)
        header._rcode = Header.RCODE_SRVFAIL
        serverData = header.pack() + question_entry.pack() + EMPTY_RESOURCE_RECORD
        ss.sendto(serverData,client_address)
    else:    
        logger.log(DEBUG2, "our reply in full:")
        logger.log(DEBUG2, hexdump(reply))
        ss.sendto(reply, client_address)
    # print("Count is",count)
    
