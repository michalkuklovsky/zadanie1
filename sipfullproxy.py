
#    Copyright 2014 Philippe THIRION
#
#    This program is free software: you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation, either version 3 of the License, or
#    (at your option) any later version.

#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.

#    You should have received a copy of the GNU General Public License
#    along with this program.  If not, see <http://www.gnu.org/licenses/>.
# 
#    Code edited by: Michal Kuklovský

import socketserver
import re
import string
import socket
#import threading
import sys
import time
from datetime import datetime
import logging
from weakref import CallableProxyType


rx_register = re.compile("^REGISTER")
rx_invite = re.compile("^INVITE")
rx_ack = re.compile("^ACK")
rx_prack = re.compile("^PRACK")
rx_cancel = re.compile("^CANCEL")
rx_bye = re.compile("^BYE")
rx_options = re.compile("^OPTIONS")
rx_subscribe = re.compile("^SUBSCRIBE")
rx_publish = re.compile("^PUBLISH")
rx_notify = re.compile("^NOTIFY")
rx_info = re.compile("^INFO")
rx_message = re.compile("^MESSAGE")
rx_refer = re.compile("^REFER")
rx_update = re.compile("^UPDATE")
rx_from = re.compile("^From:")
rx_cfrom = re.compile("^f:")
rx_to = re.compile("^To:")
rx_cto = re.compile("^t:")
rx_tag = re.compile(";tag")
rx_contact = re.compile("^Contact:")
rx_ccontact = re.compile("^m:")
rx_uri = re.compile("sip:([^@]*)@([^;>$]*)")
rx_addr = re.compile("sip:([^ ;>$]*)")
#rx_addrport = re.compile("([^:]*):(.*)")
rx_code = re.compile("^SIP/2.0 ([^ ]*)")
# rx_invalid = re.compile("^192\.168")
# rx_invalid2 = re.compile("^10\.")
#rx_cseq = re.compile("^CSeq:")
rx_callid = re.compile("Call-ID: (.*)$")
#rx_rr = re.compile("^Record-Route:")
rx_request_uri = re.compile("^([^ ]*) sip:([^ ]*) SIP/2.0")
rx_route = re.compile("^Route:")
rx_contentlength = re.compile("^Content-Length:")
rx_ccontentlength = re.compile("^l:")
rx_via = re.compile("^Via:")
rx_cvia = re.compile("^v:")
rx_branch = re.compile(";branch=([^;]*)")
rx_rport = re.compile(";rport$|;rport;")
rx_contact_expires = re.compile("expires=([^;$]*)")
rx_expires = re.compile("^Expires: (.*)$")

rx_200ok = re.compile("^SIP/2.0 200 Ok$")
rx_busy = re.compile("^SIP/2.0 486 Busy here$")
rx_decline = re.compile("^SIP/2.0 603 Decline$")

# global dictionnary
recordroute = ""
topvia = ""
registrar = {}
calls = {}

# response codes
resp = {
    "100 Trying" : "100 Skusam",
    "180 Ringing" : "180 Volam",
    "200 OK" : "200 V pohode",
    "200 Ok" : "200 V pohode",
    "400 Bad Request" : "400 Zly dopyt",
    "406 Not Acceptable" : "406 Neakceptovane",
    "480 Temporarily Unavailable" : "480 Nedostupne",
    "486 Busy here" : "486 Zaneprazdnene",
    "488 Not Acceptable Here" : "488 Neakceptovane",
    "500 Internal Server Error" : "500 Chyba servera",
    "603 Decline" : "603 Odmietnute"
}

LINE = 0


def hexdump( chars, sep, width ):
    while chars:
        line = chars[:width]
        chars = chars[width:]
        line = line.ljust( width, '\000' )

def quotechars( chars ):
	return ''.join( ['.', c][c.isalnum()] for c in chars )


class UDPHandler(socketserver.BaseRequestHandler):   
    
    def changeRequestUri(self):
        # change request uri
        md = rx_request_uri.search(self.data[LINE])
        if md:
            method = md.group(1)
            uri = md.group(2)
            if uri in registrar:
                uri = "sip:%s" % registrar[uri][0]
                self.data[LINE] = "%s %s SIP/2.0" % (method,uri)
        
    def removeRouteHeader(self):
        # delete Route
        data = []
        for line in self.data:
            if not rx_route.search(line):
                data.append(line)
        return data
    
    def addTopVia(self):
        branch= ""
        data = []
        for line in self.data:
            if rx_via.search(line) or rx_cvia.search(line):
                md = rx_branch.search(line)
                if md:
                    branch=md.group(1)
                    via = "%s;branch=%sm" % (topvia, branch)
                    data.append(via)
                # rport processing
                if rx_rport.search(line):
                    text = "received=%s;rport=%d" % self.client_address
                    via = line.replace("rport",text)   
                else:
                    text = "received=%s" % self.client_address[0]
                    via = "%s;%s" % (line,text)
                data.append(via)
            else:
                data.append(line)
        return data
                
    def removeTopVia(self):
        data = []
        for line in self.data:
            if rx_via.search(line) or rx_cvia.search(line):
                if not line.startswith(topvia):
                    data.append(line)
            else:
                data.append(line)
        return data
        
    def checkValidity(self,uri):
        addrport, socket, client_addr, validity = registrar[uri]
        now = int(time.time())
        if validity > now:
            return True
        else:
            del registrar[uri]
            logging.warning("registration for %s has expired" % uri)
            return False
    
    def getSocketInfo(self,uri):
        addrport, socket, client_addr, validity = registrar[uri]
        return (socket,client_addr)
        
    def getDestination(self):
        destination = ""
        for line in self.data:
            if rx_to.search(line) or rx_cto.search(line):
                md = rx_uri.search(line)
                if md:
                    destination = "%s@%s" %(md.group(1),md.group(2))
                break
        return destination
                
    def getOrigin(self):
        origin = ""
        for line in self.data:
            if rx_from.search(line) or rx_cfrom.search(line):
                md = rx_uri.search(line)
                if md:
                    origin = "%s@%s" %(md.group(1),md.group(2))
                break
        return origin

    def getID(self):
        id = ""
        for line in self.data:
            if rx_callid.search(line):
                md = rx_callid.search(line)
                if md:
                    id = "%s" %(md.group(1))
                break
        return id
        
    def sendResponse(self,code):
        request_uri = "SIP/2.0 " + code
        self.data[LINE]= request_uri
        index = 0
        data = []
        for line in self.data:
            data.append(line)
            if rx_to.search(line) or rx_cto.search(line):
                if not rx_tag.search(line):
                    data[index] = "%s%s" % (line,";tag=123456")
            if rx_via.search(line) or rx_cvia.search(line):
                # rport processing
                if rx_rport.search(line):
                    text = "received=%s;rport=%d" % self.client_address
                    data[index] = line.replace("rport",text) 
                else:
                    text = "received=%s" % self.client_address[0]
                    data[index] = "%s;%s" % (line,text)      
            if rx_contentlength.search(line):
                data[index]="Content-Length: 0"
            if rx_ccontentlength.search(line):
                data[index]="l: 0"
            index += 1
            if line == "":
                break
        data.append("")
        text = "\r\n".join(data)
        self.socket.sendto(text.encode("utf-8"),self.client_address)
        
    def processRegister(self):
        fromm = ""
        contact = ""
        contact_expires = ""
        header_expires = ""
        expires = 0
        validity = 0
        authorization = ""
        index = 0
        auth_index = 0
        data = []
        size = len(self.data)
        for line in self.data:
            if rx_to.search(line) or rx_cto.search(line):
                md = rx_uri.search(line)
                if md:
                    fromm = "%s@%s" % (md.group(1),md.group(2))
            if rx_contact.search(line) or rx_ccontact.search(line):
                md = rx_uri.search(line)
                if md:
                    contact = md.group(2)
                else:
                    md = rx_addr.search(line)
                    if md:
                        contact = md.group(1)
                md = rx_contact_expires.search(line)
                if md:
                    contact_expires = md.group(1)
            md = rx_expires.search(line)
            if md:
                header_expires = md.group(1)
        
        if len(contact_expires) > 0:
            expires = int(contact_expires)
        elif len(header_expires) > 0:
            expires = int(header_expires)
            
        if expires == 0:
            if fromm in registrar:
                del registrar[fromm]
                self.sendResponse(resp['200 OK'])
                return
        else:
            now = int(time.time())
            validity = now + expires
            
        registrar[fromm]=[contact,self.socket,self.client_address,validity]
        self.sendResponse(resp['200 OK'])

    def logInvite(self, logdata):
        callID = self.getID()
        callFrom = self.getOrigin()
        callTo = self.getDestination()
        
        if callID not in calls:
            calls[callID] = {   
                "participants": [],
                "called_at": time.strftime("(%H:%M:%S)", time.localtime()),
                "picked_up": None,
                "video": False
            }
            calls[callID]["participants"].append(callFrom)
            calls[callID]["participants"].append(callTo)
            logging.info("Call started\n                  call ID: %s\n                  from: %s\n                  to: %s\n" % (callID, callFrom, callTo))
        else:
            if callFrom not in calls[callID]["participants"]:
                calls[callID]["participants"].append(callFrom)
                logging.info("Call had new participant\n                  call ID: %s\n                  new: %s\n" % (callID, callFrom))
            if callTo not in calls[callID]["participants"]:
                calls[callID]["participants"].append(callTo)      
                logging.info("Call had new participant\n                  call ID: %s\n                  new: %s\n" % (callID, callTo)) 
            for line in logdata:
                if "video" in line:
                    if "video 0" in line and calls[callID]["video"]:
                        calls[callID]["video_ended_at"] = time.strftime("(%H:%M:%S)", time.localtime())
                        duration = datetime.strptime(calls[callID]["video_ended_at"], '(%H:%M:%S)') - datetime.strptime(calls[callID]["video_started_at"], '(%H:%M:%S)')
                        logging.info("Video call ended\n                  call ID: %s\n                  video duration: %s\n" % (callID, str(duration)))
                        calls[callID]["video"] = False
                    else:
                        calls[callID]["video_started_at"] = time.strftime("(%H:%M:%S)", time.localtime())
                        logging.info("Video call started\n                  call ID: %s\n" % (callID)) 
                        calls[callID]["video"] = True
                    break

    def processInvite(self):
        origin = self.getOrigin()
        if len(origin) == 0 or not origin in registrar:
            self.sendResponse(resp['400 Bad Request'])
            return
        destination = self.getDestination()
        if len(destination) > 0:
            if destination in registrar and self.checkValidity(destination):
                socket,claddr = self.getSocketInfo(destination)
                self.data = self.addTopVia()
                data = self.removeRouteHeader()
                #insert Record-Route
                data.insert(1,recordroute)
                text = "\r\n".join(data)
                socket.sendto(text.encode("utf-8") , claddr)
                self.logInvite(data)
            else:
                self.sendResponse(resp['480 Temporarily Unavailable'])
        else:
            self.sendResponse(resp['500 Internal Server Error'])
                
    def processAck(self):
        destination = self.getDestination()
        if len(destination) > 0:
            if destination in registrar:
                socket,claddr = self.getSocketInfo(destination)
                self.data = self.addTopVia()
                data = self.removeRouteHeader()
                #insert Record-Route
                data.insert(1,recordroute)
                text = "\r\n".join(data)
                socket.sendto(text.encode("utf-8"),claddr)

    def logBye(self, data):
        id = self.getID()

        if id in calls:
            if calls[id]["picked_up"] is True:
                calls[id]["ended_at"] = time.strftime("(%H:%M:%S)", time.localtime())
                duration = datetime.strptime(calls[id]["ended_at"], '(%H:%M:%S)') - datetime.strptime(calls[id]["picked_up_at"], '(%H:%M:%S)')
                logging.info("Call ended by %s\n                  call ID: %s\n                  call duration: %s\n" % (self.getOrigin(), id, str(duration)))

    def processNonInvite(self):
        origin = self.getOrigin()
        if len(origin) == 0 or not origin in registrar: 
            self.sendResponse(resp['400 Bad Request'])
            return
        destination = self.getDestination()
        if len(destination) > 0:
            if destination in registrar and self.checkValidity(destination): 
                socket,claddr = self.getSocketInfo(destination)
                self.data = self.addTopVia()
                data = self.removeRouteHeader()

                if rx_bye.search(data[LINE]):
                    self.logBye(data)

                #insert Record-Route
                data.insert(1,recordroute)
                text = "\r\n".join(data)
                socket.sendto(text.encode("utf-8") , claddr)
            else:
                self.sendResponse(resp['406 Not Acceptable'])
        else:
            self.sendResponse(resp['500 Internal Server Error'])

    def logCode(self, data):
        id = self.getID()
        if rx_200ok.search(data[LINE]):
            if id in calls:
                if calls[id]["picked_up"] is None:
                    calls[id]["picked_up"] = True
                    calls[id]["picked_up_at"] = time.strftime("(%H:%M:%S)", time.localtime())
                    logging.info("Call picked up by %s\n                  call ID: %s\n" % (self.getDestination(), id))
                if "ended_at" in calls[id]:
                    if calls[id]["picked_up"] is True and calls[id]["ended_at"] is not None:
                        calls[id]["end_confirmed_at"] = time.strftime("(%H:%M:%S)", time.localtime())
                else:
                    calls[id]["last_200ok"] = time.strftime("(%H:%M:%S)", time.localtime())

        if rx_busy.search(data[LINE]):
            if id in calls:
                if calls[id]["picked_up"] is None:
                    calls[id]["picked_up"] = False
                    logging.info("Call was not picked up\n                  call ID: %s\n" % (id))
                
        if rx_decline.search(data[LINE]):
            if id in calls:
                if calls[id]["picked_up"] is None:
                    calls[id]["picked_up"] = False
                    logging.info("Call was declined by %s\n                  call ID: %s\n" % (self.getDestination(), id))

    def processCode(self):
        origin = self.getOrigin()
        if len(origin) > 0:
            if origin in registrar:
                socket,claddr = self.getSocketInfo(origin)
                self.data = self.removeRouteHeader()
                data = self.removeTopVia()

                self.logCode(data)                

                for before, after in resp.items():
                    data[LINE] = data[LINE].replace(before, after)

                text = "\r\n".join(data)
                socket.sendto(text.encode("utf-8"),claddr)
                
                
    def processRequest(self):
        if len(self.data) > 0:
            request_uri = self.data[LINE]
            print(request_uri)
            if rx_register.search(request_uri):
                self.processRegister()
            elif rx_invite.search(request_uri):
                self.processInvite()
            elif rx_ack.search(request_uri):
                self.processAck()
            elif rx_bye.search(request_uri):
                self.processNonInvite()
            elif rx_cancel.search(request_uri):
                self.processNonInvite()
            elif rx_options.search(request_uri):
                self.processNonInvite()
            elif rx_info.search(request_uri):
                self.processNonInvite()
            elif rx_message.search(request_uri):
                self.processNonInvite()
            elif rx_refer.search(request_uri):
                self.processNonInvite()
            elif rx_prack.search(request_uri):
                self.processNonInvite()
            elif rx_update.search(request_uri):
                self.processNonInvite()
            elif rx_subscribe.search(request_uri):
                self.sendResponse(resp['200 OK'])
            elif rx_publish.search(request_uri):
                self.sendResponse(resp['200 OK'])
            elif rx_notify.search(request_uri):
                self.sendResponse(resp['200 OK'])
            elif rx_code.search(request_uri):
                self.processCode()
            else:
                logging.error("request_uri %s" % request_uri)          
    
    def handle(self):
        try:
            data = self.request[0].decode("utf-8")
            self.data = data.split("\r\n")
            self.socket = self.request[1]
            request_uri = self.data[LINE]
            if rx_request_uri.search(request_uri) or rx_code.search(request_uri):
                self.processRequest()
            else:
                if len(data) > 4:
                    logging.warning("---\n>> server received [%d]:" % len(data))
                    hexdump(data,' ',16)
                    logging.warning("---")
        except:
            pass
            
