#!/usr/bin/python

import pprint
import threading
import pyinotify
import iptc
import time
import sys
import os
import re
import json
import ConfigParser
import logging
from websocket_server import WebsocketServer


CONFIG_FILE = "config"
# TODO: 
DEBUG = False

BAN = 0
UNBAN = 1
BANTIMER = 300  # in seconds. How long to BAN
THRESHOLDFAILEDATTEMPTS = 3 # Total Failed attempts within FAILEDATTEMPTSINTERVAL before IP gets BANNED 
FAILEDATTEMPTSINTERVAL = 600 # in seconds.  
TIMEOUT = 5000
LASTRUNTIME = time.time()

#Enums
AUTHENTICATE = 0  
GETBANNEDIPs = 1
GETFAILEDATTEMPTs = 2
AUTHSUCCESS = 3
AUTHFAIL = 4
BANNEDIP = 5
UNBANNEDIP = 6
FAILEDATTEMPT = 7
UNBANIPs = 8
CHANGECONFIG = 9

server = None

MODULAR_CONFIG = {}
failedAttempts = {}
bannedIPs = {}
services = {}

def ConfigSectionMap(section):
    dict1 = {}
    options = Config.options(section)
    for option in options:
        try:
            dict1[option] = Config.get(section, option)
            if dict1[option] == -1:
                DebugPrint("skip: %s" % option)
        except:
            print("exception on %s!" % option)
            dict1[option] = None
    return dict1

def banIP(IP, dport, service, timer = BANTIMER):
    """Returns 1 if IP is already BANNED/UNBANNED
       Returns 0 if BANNED/UNBANNED successfully
    """

    print 'banIP:'
    if (IP, service) in bannedIPs:
        print 'IP:' + IP + 'is already BANNED'
        logging.info('IP:' + IP + 'is already BANNED')
        return 1
    else:
        ip = bannedIP(IP, time.time(), service, timer)
        chain = iptc.Chain(iptc.Table(iptc.Table.FILTER), "INPUT")
        ip.rule = iptc.Rule(chain=chain)
        ip.rule.src = ip.IP + "/255.255.255.255"
        ip.rule.protocol = "tcp"
        ip.rule.target = iptc.Target(ip.rule, "REJECT")
        ip.rule.target.reject_with = "icmp-admin-prohibited"
        match = iptc.Match(ip.rule,"tcp")
        match.dport = dport
        ip.rule.add_match(match)
        bannedIPs[(ip.IP, service)] = ip
        chain.insert_rule(ip.rule)
        print 'IP:' + ip.IP + ' BANNED at ' + time.strftime("%b %d %H:%M:%S")
        logging.info('IP:' + ip.IP + ' BANNED at ' + time.strftime("%b %d %H:%M:%S"))
        resp = {"action": BANNEDIP, "data":{"IP":ip.IP, "time":time.strftime("%b %d %H:%M:%S", time.localtime(ip.time)), "timer":ip.timer, "service":ip.service}}
        server.send_message_to_all(json.dumps(resp))

def unbanIP(IP, service):
    
        print 'unbanIP:'
        if (IP, service) not in bannedIPs:
            print 'IP:' + IP + 'is already UNBANNED'
            logging.info('IP:' + IP + 'is already UNBANNED')
            return 0
        else:
            chain = iptc.Chain(iptc.Table(iptc.Table.FILTER), "INPUT")
            chain.delete_rule(bannedIPs[IP, service].rule)
            print 'IP:' + IP + ' UNBANNED at ' + time.strftime("%b %d %H:%M:%S")
            logging.info('IP:' + IP + ' UNBANNED at ' + time.strftime("%b %d %H:%M:%S"))
            del(bannedIPs[(IP, service)])
        
def unbanIPcallback(arg):
     
     if DEBUG:
     	 print 'callback:'

     for bannedIP in bannedIPs.values():
         #print 'bannedIP is ' + bannedIP.IP
         if time.time() - bannedIP.time >= bannedIP.timer :
             print 'Unbanning IP: ' + bannedIP.IP
             chain = iptc.Chain(iptc.Table(iptc.Table.FILTER), "INPUT")
             chain.delete_rule(bannedIP.rule)
             print 'IP:' + bannedIP.IP + ' UNBANNED at ' + time.strftime("%b %d %H:%M:%S")
             del(bannedIPs[(bannedIP.IP, bannedIP.service)])
	     resp = {"action": UNBANNEDIP, "data":{"IP":bannedIP.IP, "service":bannedIP.service}}
	     server.send_message_to_all(json.dumps(resp))
     
def changeConfig(bantimer, nofailedattempts, failinterval,service):
    print 'Changing configuration:' 
    logging.info('Changing configuration:')
    
    try:
        ibantimer = int(bantimer)if bantimer else None
        inofailedattempts = int(nofailedattempts) if nofailedattempts else None
        ifailinterval = int(failinterval)if failinterval else None
    except Exception as e:
        print "Failed converting to int:", e, ". So, not updating"
        #logging.info("Failed converting to int:", e, ". So, not updating")
        return

    service.updateValues(ibantimer,inofailedattempts,ifailinterval)

class service():
    def __init__(self, name, port, 
                 tfa=THRESHOLDFAILEDATTEMPTS, fai=FAILEDATTEMPTSINTERVAL, banTimer = BANTIMER):
        self.name = name
        self.port = port
        self.pattern = None
        self.thresholdFailedAttempts = tfa
        self.failedAttemptsInterval = fai
        self.banTimer =  banTimer
    def updateValues(self,bantimer, thresholdFailedAttempts, failedAttemptsInterval):
        self.banTimer = bantimer if bantimer else self.banTimer
        self.thresholdFailedAttempts = thresholdFailedAttempts if thresholdFailedAttempts else self.thresholdFailedAttempts
        self.failedAttemptsInterval = failedAttemptsInterval if failedAttemptsInterval else self.failedAttemptsInterval
        print "Updated values for %s: timer(%d), thresholdFailedAttempts(%d), failedAttemptsInterval(%d)" %(self.name, self.banTimer, self.thresholdFailedAttempts, self.failedAttemptsInterval)

class IP(object):
    def __init__(self, IP, time):
        self.IP = IP
        self.time = time

class bannedIP(IP):
    def __init__(self, IP, time, service, timer = BANTIMER):
        super(bannedIP, self).__init__(IP, time)
        self.timer = timer
        self.rule = None
        self.service = service

class failedAttemptIP(IP):
    def __init__(self, IP, time, service):
        super(failedAttemptIP, self).__init__(IP, time)
        self.rate = None
        self.service = service 

class EventHandler(pyinotify.ProcessEvent):
    def my_init(self, monitoredf=None):
        self.files = {}
        for pathname in monitoredf:
	    self.files[pathname] = open(pathname, "r")
	    self.files[pathname].seek(0, os.SEEK_END)
            
    def process_IN_MODIFY(self, event):
        print "Modified:", event.pathname
        lines = self.files[event.pathname].readlines()
        for line in lines:
            for service in services.values():
                m = re.search(service.pattern,line)
                if m:
                    ip = m.group('HOST')
                    ftime = m.group('TIME')
                    print service.name, ': Failed attempt from ', ip, ' at ', ftime
                    #logging.info(service.name, ': Failed attempt from ', ip, ' at ', ftime)
                    # Determine to ban or not to ban
                    # If to ban, clear all failed attempts in failedAttempts from this IP  
                    # Else if not to ban, append this failed attempt from this IP to attempt list for this IP in failedAttempts
                    fip = failedAttemptIP(ip, time.time(), service.name)
                    fip.rate = 1

                    # Rate of failed attempts should not be more than thresholdfailedAttempts  within
                    # failedAttemptInterval seconds
                    if (fip.IP, fip.service) in failedAttempts:
                        fipAttempts = failedAttempts[(fip.IP, fip.service)]
                    # Every failed attempt has its start and end interval
                    # If this fip failed attempt falls within such interval of a failed attempt,
                    # it also falls in interval of subsequent failed attempts.
                    # So, increment rates of all such failed attempts.
                    # If this fip does not fall in interval of a failed attempt, remove that failed attempt.  
                        ban = 0
                        length = len(fipAttempts)
                        while length > 0:
                                if fip.time > fipAttempts[0].time + service.failedAttemptsInterval:
                                    print 'Clear failed attempts whose time interval has expired'
                                    fipAttempts.pop()
                                    length -= 1
                                    continue
                                for j in range(0, len(fipAttempts)):
                                    fipAttempts[j].rate+=1
                                    if fipAttempts[j].rate >= service.thresholdFailedAttempts:
                                        print 'Failed attempt rate exceeded for IP:' + fip.IP + '. BAN'
                                        banIP(fip.IP, service.port, service.name, service.banTimer)
                                        resp = {"action": FAILEDATTEMPT, "data":{"IP":fip.IP, "time":time.strftime("%b %d %H:%M:%S", time.localtime(fip.time)), "service":fip.service}}
                                        server.send_message_to_all(json.dumps(resp))
                                        del(failedAttempts[(fip.IP, fip.service)])
                                        ban = 1
                                        break
                                break
                                
                        if not ban : 
                            print 'Append this failed attempt'
                            failedAttempts[(fip.IP, fip.service)].append(fip)
                            resp = {"action": FAILEDATTEMPT, "data":{"IP":fip.IP, "time":time.strftime("%b %d %H:%M:%S", time.localtime(fip.time)), "service":fip.service}}
                            server.send_message_to_all(json.dumps(resp))

                    else:
                        print "First failed attempt from IP: " + fip.IP
                        if service.thresholdFailedAttempts <= 1:
                            print "Threshold for serivce:" + service.name + 'is 1. BAN' 
                            banIP(fip.IP, service.port, service.name, service.banTimer)
                        else:
                            print  'Append this attempt to failedAttempts'
                            fip.rate = 1
                            failedAttempts[(fip.IP, service.name)] = [fip]
                            resp = {"action": FAILEDATTEMPT, "data":{"IP":fip.IP, "time":time.strftime("%b %d %H:%M:%S", time.localtime(fip.time)), "service":fip.service}}
                            server.send_message_to_all(json.dumps(resp))


def webServer():
    
    usersfd = open("users.json", "r") 
    users = json.load(usersfd)
    usersfd.close()

    def new_client(client, server):
        print("New client connected and was given id %d" % client['id'])

    def client_left(client, server):
        print("Client(%d) disconnected" % client['id'])

    def message_received(client, server, message):
        #print("received message from client id %d " %  client['id'])
        #logging.info("received message from client id %d " %  client['id'])
        msg = json.loads(message)

        if msg["action"] == AUTHENTICATE:
            print 'msg is AUTHENTICATE' 
            resp = {"action": AUTHENTICATE, "data": None}
            username = msg["data"].get("username") if msg["data"].has_key("username") else None
            password = msg["data"].get("password") if msg["data"].has_key("password") else None

            if username and password and users.has_key(username) and password == users[username]:
                print "AUTHSUCCESS"
                resp["data"] = AUTHSUCCESS
            else:
                print "AUTHFAIL"
                resp["data"] = AUTHFAIL
                
            server.send_message(client, json.dumps(resp) )
            
        elif msg["action"] == GETBANNEDIPs:
            #print 'msg is GETBANNEDIPs' 
            #logging.info('msg is GETBANNEDIPs')
            resp = {"action": GETBANNEDIPs, "data": []}
            username = msg["data"].get("username") if msg["data"].has_key("username") else None
            password = msg["data"].get("password") if msg["data"].has_key("password") else None

            if username and password and users.has_key(username) and password == users[username]:
                for bannedIP in bannedIPs.values():
                    ip = {}
                    ip["IP"] = bannedIP.IP
                    ip["time"] = time.strftime("%b %d %H:%M:%S", time.localtime(bannedIP.time))
                    ip["timer"] = bannedIP.timer - (time.time() - bannedIP.time)
                    ip["service"] = bannedIP.service
                    resp["data"].append(ip)
                server.send_message(client, json.dumps(resp))
            else:
                print "AUTHFAIL"
                resp["data"] = AUTHFAIL
                server.send_message(client, json.dumps(resp))
        
        elif msg["action"] == GETFAILEDATTEMPTs:
            print 'msg is GETFAILEDATTEMPTs' 
            resp = {"action": GETFAILEDATTEMPTs, "data": []}
            username = msg["data"].get("username") if msg["data"].has_key("username") else None
            password = msg["data"].get("password") if msg["data"].has_key("password") else None
            if username and password and users.has_key(username) and password == users[username]:
                for failedAttempt in failedAttempts:
                    print "in FA"
                    print "FA=" + str(failedAttempt)
                    ip = {}
                    ip["IP"] = failedAttempt[0]
                    ip["attempts"] = []
                    ip["service"] = failedAttempt[1] 
                    for attempt in failedAttempts[failedAttempt]:
                        ip["attempts"].append(time.strftime("%b %d %H:%M:%S", time.localtime(attempt.time)))
                        
                    resp["data"].append(ip)

                server.send_message(client, json.dumps(resp))
            else:
                print "AUTHFAIL"
                resp["data"] = AUTHFAIL
                server.send_message(client, json.dumps(resp))

        elif msg["action"] == UNBANIPs:
            print 'msg is UNBANIPs'
            resp = {"action": UNBANIPs, "data": {}}
            username = msg["data"].get("username") if msg["data"].has_key("username") else None
            password = msg["data"].get("password") if msg["data"].has_key("password") else None
            if username and password and users.has_key(username) and password == users[username]:
	        unbanIP(msg["data"]["IP"], msg["data"]["service"])
	        resp["data"]["IP"] = msg["data"]["IP"]
	        resp["data"]["service"] = msg["data"]["service"]
                server.send_message(client, json.dumps(resp))
            else:
                print "AUTHFAIL"
                resp["data"] = AUTHFAIL
                server.send_message(client, json.dumps(resp))
	elif msg["action"] == CHANGECONFIG:
	    print 'msg is CHANGECONFIG'
            #changeconfig(bantimer,nofailedattempts,failinterval)
            data = msg["data"]
            for service in services.values():
                if service.name.lower() == data.get("service").lower():
                    changeConfig(data.get("bantimer"), data.get("threshold"), data.get("interval"), service)
            #server.send_message(client, json.dumps(resp))
	    


    
    global server        
    PORT=9001
    server = WebsocketServer(PORT, host='0.0.0.0')
    server.set_fn_new_client(new_client)
    server.set_fn_client_left(client_left)
    server.set_fn_message_received(message_received)
    server.run_forever()
    

logging.basicConfig(filename='ips.log',level=logging.DEBUG)
Config = ConfigParser.ConfigParser()
Config.read(CONFIG_FILE)
for eachsection in Config.sections():
   try:
       MODULAR_CONFIG[eachsection] = {}
       MODULAR_CONFIG[eachsection]["path"] = ConfigSectionMap(eachsection)["path"]
       MODULAR_CONFIG[eachsection]["port"] = ConfigSectionMap(eachsection)["port"]
       MODULAR_CONFIG[eachsection]["pattern"] = ConfigSectionMap(eachsection)["pattern"]
   except Exception as e:
       print "Error reading config file:", e
       logging.error("Error reading config file")
       sys.exit(0)

print "Configuration read."
#pprint.pprint (MODULAR_CONFIG)
pathstowatch = []
for eachserv in MODULAR_CONFIG:
    s = service(eachserv, MODULAR_CONFIG[eachserv]["port"])
    s.pattern = re.compile(MODULAR_CONFIG[eachserv]["pattern"])
    services[s.name] = s
    # Add all unique paths to watch
    if not MODULAR_CONFIG[eachserv]["path"] in pathstowatch:
        pathstowatch.append(MODULAR_CONFIG[eachserv]["path"])

wm = pyinotify.WatchManager()
mask = pyinotify.IN_MODIFY


handler = EventHandler(monitoredf = pathstowatch)
notifier = pyinotify.Notifier(wm, handler, timeout = TIMEOUT)
wdd = wm.add_watch(pathstowatch, mask, rec=False)
t = threading.Thread(name='webserver', target=webServer)
t.setDaemon(True)
t.start()
iptc.Chain(iptc.Table(iptc.Table.FILTER), "INPUT").flush()
notifier.loop(callback = unbanIPcallback)



