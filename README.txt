Name:           WSDL Wizard
Version:        1.0
Date:           4/19/2013
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