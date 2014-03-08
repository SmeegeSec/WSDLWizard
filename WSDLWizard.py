"""
Name:           WSDL Wizard
Version:        1.02
Date:           3/07/2014
Author:         Smeege
Contact:        SmeegeSec@gmail.com

Description:    WSDL Wizard is a Burp Suite plugin written in Python to detect current and discover new WSDL (Web Service Definition Language) files.
                This plugin searches the current site map of a user defined host for URLs with the ?wsdl extension while also building a list
                of viable URLs to fuzz for 'hiding' WSDL files.  Two different methods are available to check for ?wsdl files, using urllib2
                or Burp's API.  When comparing efficiency urllib2 was about 30 percent better however the user can simply switch between 
                methods by running the appropriate function if they choose.  All found WSDL files are added to the existing site map and printed out in the 
                Extender tab output section.

Notes:          In certain situations when web applications require authentication it is better to use the Burp API function to fuzz for WSDL files
                rather than urllib2 which will fail as 401 Unauthorized.
"""

from burp import IBurpExtender
from burp import IContextMenuFactory
from burp import IHttpRequestResponse
from burp import IMessageEditorController
from java.lang import RuntimeException
from java.net import URL
from javax.swing import JMenuItem
import string
import urllib2
from urlparse import urlparse

# Scan first 1 KB of messages
MESSAGE_LIMIT = 1024 

class BurpExtender(IBurpExtender, IContextMenuFactory):
    
    # Implement IBurpExtender
    def	registerExtenderCallbacks(self, callbacks):

        self.printHeader()

        # Set extension name
        callbacks.setExtensionName("WSDL Wizard")

        # Callbacks object
        self._callbacks = callbacks

        # Helpers object
        self._helpers = callbacks.getHelpers()

        # Register a factory for custom context menu items
        callbacks.registerContextMenuFactory(self)

        return

    # Create a menu item if the appropriate section of the UI is selected
    def createMenuItems(self, invocation):
        
        menu = []

        # Which part of the interface the user selects
        ctx = invocation.getInvocationContext()

        # Message Viewer Req/Res, Site Map Table, and Proxy History will show menu item if selected by the user
        if ctx == 2 or ctx == 3 or  ctx == 4 or ctx == 5 or ctx == 6:
            menu.append(JMenuItem("Scan for WSDL Files", None, actionPerformed=lambda x, inv=invocation: self.wsdlScan(inv)))

        return menu if menu else None

    def wsdlScan(self, invocation):

        # Check initial message for proper request/response and set variables - Burp will not return valid info otherwise
        try:
            invMessage = invocation.getSelectedMessages()
            message = invMessage[0]
            originalHttpService = message.getHttpService()
            self.originalMsgProtocol = originalHttpService.getProtocol()
            self.originalMsgHost = originalHttpService.getHost()
            self.originalMsgPort = originalHttpService.getPort()
            self.originalMsgUrl = self.originalMsgProtocol + '://' + self.originalMsgHost
            print 'Valid request and response found.  Scanning %s for wsdl files.\n' % self.originalMsgHost
        except:
            e = sys.exc_info()[0]
            print "Error: Please start the scan from a request with a valid response.\n"
            raise RuntimeException(e)

        # Get site map of the host selected by the user
        self.siteMap = self._callbacks.getSiteMap(self.originalMsgUrl)

        self.wsdlKeywordList = ['xmlns:soap', 'xmlns:wsoap', 'xmlns:wsdl', '<wsdl:', '<soap:']

        self.detectedUrlList = []
        self.fuzzedWsdlList = []
        self.foundWsdlList = []

        # Loop through each message, check for a valid 200 response, and send the message to checkMessage function
        for siteMapMessage in self.siteMap:
            if siteMapMessage.getRequest():
                if 'Connection: close' not in self._helpers.bytesToString(siteMapMessage.getRequest()) and str(self._helpers.analyzeResponse(siteMapMessage.getResponse()).getStatusCode()) == '200':
                    self.checkMessage(siteMapMessage)

        if self.foundWsdlList:
            print '%s wsdl file(s) found.\n' % len(self.foundWsdlList)
            for foundWsdl in self.foundWsdlList:
                print '\t' + foundWsdl + '\n'
        else:
            print 'No wsdl files found.\n'
        
        try:
            # There are two methods of fuzzing for wsdl files, using python's urllib2 module or Burp API
            self.fuzzUrls()
            #self.fuzzUrlsAPI()
        except:
            e = sys.exc_info()[0]
            print "Error: %s" % e

        if self.fuzzedWsdlList:
            print '%s wsdl file(s) fuzzed.\n' % len(self.fuzzedWsdlList)
            for fuzzedWsdl in self.fuzzedWsdlList:
                print '\t' + fuzzedWsdl + '\n'
        else:
            print 'No wsdl files fuzzed.\n'

    # Take each message and check for a wsdl extension or adds the URL to fuzz later
    def checkMessage(self, siteMapMessage):
        # Get the request, request method, 1kb of the response, and full URL
        requestString = self._helpers.bytesToString(siteMapMessage.getRequest())
        requestMethod = self._helpers.analyzeRequest(siteMapMessage.getRequest()).getMethod()
        responseString = self._helpers.bytesToString(siteMapMessage.getResponse())[0:MESSAGE_LIMIT]
        messageUrl = str(self._helpers.analyzeRequest(siteMapMessage).getUrl())
        messageUrlLowerExt = messageUrl[:-4] + messageUrl[-4:].lower()
        
        # Check if ?wsdl is in the URL
        if '?wsdl' in messageUrl.lower() or '.wsdl' in messageUrl.lower() and messageUrlLowerExt not in self.foundWsdlList:
            self.foundWsdlList.append(messageUrlLowerExt)
        else:
            # Check if parameters are in the URL
            if "=" not in messageUrl:
                self.detectedUrlList.append(messageUrl)
            else:
                # Parse out the host and path of the URL, leaving out any parameters (wsdl files don't follow parameters)
                parsedURL = urlparse(messageUrl)
                noParamsURL = parsedURL.scheme + '://' + parsedURL.netloc + parsedURL.path
                if noParamsURL not in self.detectedUrlList:
                    self.detectedUrlList.append(noParamsURL)
        
    # Use Python urllib2
    # Generates URLs with ?wsdl extension based on valid site map URLs and tests them for valid wsdl responses
    def fuzzUrls(self):
        print 'Fuzzing %s viable URLs with a wsdl extension\n' % len(self.detectedUrlList)
        for detectedUrl in self.detectedUrlList:
            wsdlSuffixUrl = detectedUrl + '?wsdl'
            if wsdlSuffixUrl not in self.foundWsdlList:
                try:
                    # Try to open created wsdl url and read the response
                    wsdlSuffixUrlResponse = urllib2.urlopen(wsdlSuffixUrl)
                    wsdlSuffixUrlResponseData = wsdlSuffixUrlResponse.read()
                    # Loop through the keywords and check if one of them are in the response (very good indicator of wsdl or similar file)
                    for wsdlKeyword in self.wsdlKeywordList:
                        if wsdlKeyword in wsdlSuffixUrlResponseData:
                            # wsdl file found from created URL, add to fuzzed list
                            self.fuzzedWsdlList.append(wsdlSuffixUrl)
                            # Build a request and response based on the found wsdl URL and add them to the Burp site map
                            wsdlJavaURL = URL(wsdlSuffixUrl)
                            newRequest = self._helpers.buildHttpRequest(wsdlJavaURL)
                            requestResponse = self._callbacks.makeHttpRequest(self._helpers.buildHttpService(str(wsdlJavaURL.getHost()), int(wsdlJavaURL.getPort()), wsdlJavaURL.getProtocol() == "https"), newRequest)
                            self._callbacks.addToSiteMap(requestResponse)
                            break
                except: 
                    # wsdl URL was not valid, skip it
                    pass

    # Use Burp API 'makeHttpRequest'
    # Generate URLs with ?wsdl extension based on valid site map URLs and tests them for valid wsdl responses
    def fuzzUrlsAPI(self):
        print 'Fuzzing %s viable URLs with a wsdl extension\n' % len(self.detectedUrlList)
        for messageUrl in self.detectedUrlList:
            wsdlSuffixUrl = messageUrl + '?wsdl'
            if wsdlSuffixUrl not in self.fuzzedWsdlList and wsdlSuffixUrl not in self.foundWsdlList:
                # Build full HTTP URL with port
                fullUrl = self.originalMsgUrl + ':' + str(self.originalMsgPort)

                # Build the URL path without domain to be used in the GET request
                requestWsdlUrl = wsdlSuffixUrl[len(fullUrl):]

                # Build HTTP request string to be used with Burp API
                requestString = """GET %s HTTP/1.1\nHost: %s\r\n\r\n""" % (requestWsdlUrl, self.originalMsgHost)

                # Make request of the generated wsdl URL using Burp API
                response = self._callbacks.makeHttpRequest(self.originalMsgHost, self.originalMsgPort, self.originalMsgProtocol == "https", self._helpers.stringToBytes(requestString))
                wsdlSuffixUrlResponseData = self._helpers.bytesToString(response)

                # Check if response is valid
                if self._helpers.analyzeResponse(response).getStatusCode() == 200:
                    for wsdlKeyword in self.wsdlKeywordList:
                        # Loop through the keywords and check if one of them are in the response (very good indicator of wsdl or similar file)
                        if wsdlKeyword in wsdlSuffixUrlResponseData:
                            # wsdl file found from created URL, add to fuzzed list
                            self.fuzzedWsdlList.append(wsdlSuffixUrl)
                            # Build a request and response based on the found wsdl URL and add them to the Burp site map
                            wsdlJavaURL = URL(wsdlSuffixUrl)
                            newRequest = self._helpers.buildHttpRequest(wsdlJavaURL)
                            requestResponse = self._callbacks.makeHttpRequest(self._helpers.buildHttpService(str(self.originalMsgHost), int(self.originalMsgPort), self.originalMsgProtocol == "https"), newRequest)
                            self._callbacks.addToSiteMap(requestResponse)
                            break


    def printHeader(self):
        print '-------------------\nWSDL Wizard Plugin\nSmeegeSec@gmail.com\n-------------------\n\n'