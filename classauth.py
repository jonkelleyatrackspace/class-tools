#!/usr/bin/python2
import classlog

# You should probably put these in a config file somewhere.
AUTH_US_URL         = "https://identity.api.rackspacecloud.com/v2.0/tokens"
AUTH_US_USER        = ''
AUTH_US_KEY         = ''
AUTH_US_PCKL_FILE   = '/tmp/authkey.us.pckl'

AUTH_UK_URL         = "https://lon.identity.api.rackspacecloud.com/v2.0/tokens"
AUTH_UK_USER        = ''
AUTH_UK_KEY         = ''
AUTH_UK_PCKL_FILE   = '/tmp/authkey.uk.pckl'

import time                     # Because time is time, man.
import pickle                   # Used for file-base serialized object access.
import requests, os, json       # Obviously for network. Fixed that dumb non-refactor the requests
                                # author made by changing r.json object from a dict to a method. Grr.
import time, dateutil.parser    # Used heavily in tokenexpired() to validate if token expired based on access['expires']

class AuthException(Exception):
    """ Used in cases when the parent module could try again """
    def __init__(self, value):
        classlog.instance.logger.error('EXCEPTION_HANDLER!!:' + str(value) )
        self.parameter = value
    def __str__(self):
        return repr(self.parameter)

class AuthExceptionCritical(Exception):
    """ Used in cases when the parent module should give up, it's hopeless this can recover """
    def __init__(self, value):
        classlog.instance.logger.error('EXCEPTION_HANDLER!!:' + str(value) )
        self.parameter = value
    def __str__(self):
        return repr(self.parameter)

class RSAuth:
    """A reusable class for retrieving auth info. It just goes out and grabs, nothing more, nothing less."""
    """ Congratulations, you found the hidden documentation on how to call upon RSAuth directly for auth data.
        We don't suggest you use this, because the identity class caches the data to disk for faster operation!!
        if __name__ == "__main__":
            auth = RSAuth('USA')
            print auth.get_token()                             # Prints a token
            print auth.get_endpoint('cloudFiles', 'DFW')     # Gets and endpoint
            print auth.rawobject                               # Prints the full json object.
    """
    def __init__(self,region):
        if region == 'USA':
            username        = AUTH_US_USER
            apikey          = AUTH_US_KEY
            auth_endpointurl=AUTH_US_URL
        if region == 'LON':
            username        = AUTH_UK_USER
            apikey          = AUTH_UK_KEY
            auth_endpointurl=AUTH_UK_URL
        if region == '':
            emsg="Region is null, why isn't region defined?"
            classlog.instance.logger.error( emsg )

        self.token = None
        self.expiration = None
        self.tenant_id = None
        self.headers = {'Content-Type': 'application/json', 'x-jonkelley' : 'waz_here_for_api_testing', 'x-hi' : 'venu/ravi'}
        self.authurl = auth_endpointurl
        self.service_catalog = None

        # Does it!!
        self.authenticate(username, apikey, auth_endpointurl)

    # authenticate() will be called for us when we create an object, but we want to make it callable on it's own
    def authenticate(self, username, apikey, auth_endpointurl, retries=0):
        print("rsauth.authenticate called")
        if retries >= 5:
            raise AuthExceptionCritical("Couldnt make request! Tried 5 times via requests lib and exausted.")
        else:
            auth_payload = {
                "auth": {
                   "RAX-KSKEY:apiKeyCredentials": {  
                      "username": username,  
                      "apiKey": apikey
                   }
                }
            }
            try:
                r = requests.post(auth_endpointurl, data=json.dumps(auth_payload), headers=self.headers)
                classlog.instance.logger.debug ( "Auth url: " + str( auth_endpointurl ))
                classlog.instance.logger.debug ( "Auth payload: " + str( json.dumps(auth_payload) ))
                classlog.instance.logger.debug ( "Auth response: " + str( r.json()))
                self.check_http_response_status(r)
            except:
                emsg="Our outbound request to auth encountered an exception. We're going to re-try auth. Current retrycount:" + str(retries)
                classlog.instance.logger.error(emsg)
                retries+=1
                self.authenticate(username, apikey, auth_endpointurl, retries)
            try:
                authresponse = r.json()
                self.token = authresponse['access']['token']['id']
                classlog.instance.logger.debug('self.token = ' + str(self.token))
                self.expiration = authresponse['access']['token']['expires']
                classlog.instance.logger.debug('self.expiration = ' + str(self.expiration))
                self.tenant_id = authresponse['access']['token']['tenant']['id']
                classlog.instance.logger.debug('self.tenant_id = ' + str(self.tenant_id))
#                 set our headers with the token!
#                self.headers['X-Auth-Token'] = self.token
                self.service_catalog = authresponse['access']['serviceCatalog']
                classlog.instance.logger.debug('self.service_catalog = ' + str(self.service_catalog))
                self.rawobject = authresponse
                self.status_code = r
                classlog.instance.logger.debug('self.status_code = ' + str(self.status_code))
            except KeyError:
                emsg="try:except exception for dicts Current retrycount:" + str(retries)
                classlog.instance.logger.debug(emsg)
                retries+=1
                self.authenticate(username, apikey, auth_endpointurl, retries)

    def get_token(self):
        return self.token
    
    def get_tenant_id(self):
        return self.tenant_id


    def get_endpoint(self, service, region):
        for item in self.service_catalog:
            if item['name'] == service:
                for endpoint in item['endpoints']:
                    try: # If region key exists...
                        if endpoint['region'] == region:
                            return endpoint['publicURL']
                    except KeyError: # Region support just isnt there.
                            return endpoint['publicURL']

    def check_http_response_status(self, result):
        if result.status_code == 200 or result.status_code == 203:
            pass
        else:
            emsg="AUTH status_code: " + str(result.status_code) + " Expected [200 or 203]"
            classlog.instance.logger.error(emsg)
            raise AuthException(emsg)

class service:
    """Helper class to store all the various proper names of the various services"""
    clouddatabases = "cloudDatabases"
    cloudservers = "cloudServers"
    cloudfilescdn = "cloudFilesCDN"
    clouddns = "cloudDNS"
    cloudfiles = "cloudFiles"
    cloudloadbalancers= "cloudLoadBalancers"
    cloudmonitoring = "cloudMonitoring"
    cloudserversopenstack = "cloudServersOpenStack"

class region:
    dfw = "DFW"
    ord = "ORD"
    lon = "LON"

class identity:
    """ This is the coolest feature in the authentication library.
        I've done some database testing and storing this in a pickle serialized object file is
        by far the fastest in the land.
    """

    def __init__(self,region,isforce=None):
        __writtenby__ = 'Jon.Kelley@rackspace.com'
        if region == 'ord':      # B
            self.region = 'USA'  # A 
        elif region == 'dfw':    # N 
            self.region = 'USA'  # D   A
        elif region == 'lon':    #     I
            self.region = 'LON'  #     D


        if self.region == "LON":
             self.picklefile = AUTH_UK_PCKL_FILE
        else:
            self.picklefile = AUTH_US_PCKL_FILE

        
        classlog.instance.logger.debug("region="     + str(self.region))
        classlog.instance.logger.debug("region="     + str(region))
        classlog.instance.logger.debug("picklefile=" + str(self.picklefile))

        if isforce: # If someone forces a new token, I presume we must oblige.
            self.remote() # Reload pickle to disk.
            classlog.instance.logger.info("A new token was forcibly called for.")

    def tokenexpired(self, iso):
        """Takes ISO 8601 format(string) and converts into epoch time, then determines
            if the token has expired by comparing it to current epoch.
            Returns TRUE if it's expired.
            This was a nightmare.
        """

        auth_expire = dateutil.parser.parse(iso)    # Gets iso into datetime object.
        #self.logger.debug("Auth Expire_Timestamp: \t" + str(auth_expire))
        auth_expiry_epoch = time.mktime(auth_expire.timetuple())
        #self.logger.debug("Auth Expire_Epoch: \t" + str(auth_expiry_epoch))
        time_now_epoch    = time.time()
        #self.logger.debug("Time Current_Epoch: \t" + str(time_now_epoch))
        token_time_left = auth_expiry_epoch - time_now_epoch  # How much time is left?
        #self.logger.debug("Token time left: \t" + str(token_time_left))

        if token_time_left <= 0:
            classlog.instance.logger.info("AUTH.EXPIRED at " + str(str(auth_expire)))
            return True
        else:
            classlog.instance.logger.info("AUTH.VALID for another " + str(token_time_left) + "(seconds) expiring on " + str(auth_expire))
            return False

    def remote(self):
        """ Gets called only when we need to issue new external auth request and serialize it to disk. """
        auth     = RSAuth(self.region)
        authjson = auth.rawobject # json in
        
        try:
            file = open(self.picklefile, "w") # Open file aquisition lock, man
            pickle.dump(authjson, file) # Dump in pickle format
            file.close()
        except IOError:
            raise AuthExceptionCritical('Could not open pickle file due to ioerror. Permissions maybe.')

    def getdict(self):
        """ Retrieves the cached auth object from disk. 
            If object token is expired, it re-retrieves.
        """
        if not os.path.isfile(self.picklefile):
            classlog.instance.logger.error("Auth.Identity Pickle file is missing: " + str(self.picklefile) + " -> I'm pinging IDENTITY to create this file.")
            self.remote()

        access = os.access(self.picklefile, os.W_OK)
        if access == True: # If file is readable...
            file = open(self.picklefile, 'rb') # Opens pickle from disk 
            try:
                mypickle = pickle.load(file)  # Loads pickle into dictionary
                file.close()
            except EOFError:
                classlog.instance.logger.error( "===============================================================================")
                classlog.instance.logger.error( "Pickle serialized obje is broke! Delete file \n" + str(file) )
                classlog.instance.logger.error( "===============================================================================" )

            try:
                expiration = mypickle['access']['token']['expires']
            except UnboundLocalError:
                classlog.instance.logger.error( "===============================================================================" )
                classlog.instance.logger.error( "Can't decode token from file! Dont know why...  \n" + str(file) )
                classlog.instance.logger.error( "===============================================================================" )

            if self.tokenexpired(expiration):
                self.remote()
                self.getdict()

            return mypickle
        else:
            raise AuthExceptionCritical('Auth.Identity cannot read: ' + str(self.picklefile))

    def get_token(self):
        """ Returns a str of your auth token """
        mypickle = self.getdict()
        return mypickle['access']['token']['id']

    def get_tenantid(self):
        """ Returns an int of your tenant id """
        mypickle = self.getdict()
        return int(mypickle['access']['token']['tenant']['id'])

    def get_expires(self):
        """ Returns a str of when token expires """
        mypickle = self.getdict()
        return mypickle['access']['token']['expires']

    def get_serviceCatalog(self):
        """ Returns the entire servicecatalog to you, for your own parsing I presume."""
        mypickle = self.getdict()
        return mypickle['access']['serviceCatalog']

    def get_info_token_expires_in(self):
        """ Returns the amount of seconds this tokens life still has."""
        mypickle = self.getdict()
        expires = mypickle['access']['token']['expires']
        expires = dateutil.parser.parse(expires)    # Gets iso into datetime object.
        auth_expiry_epoch = time.mktime(expires.timetuple())
        time_now_epoch    = time.time()
        seconds = auth_expiry_epoch - time_now_epoch  # How much time is left?
        return seconds

    def get_fullresponse(self):
        """ Returns the entire cached auth object so you can do your own work with the auth dictionary """
        mypickle = self.getdict()
        return mypickle

    def get_endpoint(self, service, region=None):
        """ Returns the endpoints from service catalog.
        Do not provide region arguement if the service has no region. """
        mypickle = self.get_serviceCatalog()
        for item in mypickle:
            if item['name'] == service:
                for endpoint in item['endpoints']:
                    try: # If region key exists...
                        if endpoint['region'] == region:
                            return endpoint['publicURL']
                    except KeyError: # Region support just isnt there.
                            return endpoint['publicURL']

    def get_endpoint_tenantid(self, service, region=None):
        """ Returns the endpoints from service catalog.
        Do not provide region arguement if the service has no region. """
        mypickle = self.get_serviceCatalog()
        for item in mypickle:
            if item['name'] == service:
                for endpoint in item['endpoints']:
                    try: # If region key exists...
                        if endpoint['region'] == region:
                            return endpoint['tenantId']
                    except KeyError: # Region support just isnt there.
                            return endpoint['tenantId']

    def get_json(self):
        """ Returns the entire cached auth object so you can do your own work with the auth dictionary """
        mypickle = self.getdict()
        myjson   = json.dumps(mypickle,sort_keys = False, indent = 3)
        return myjson

    #header = {}
    #header['X-Auth-Token'] = self.token
if __name__ == '__main__':

    """ Just an example of how to properly use this module.
        This module handles auth for you, and easily grabs the token, tenantid, or service endpoint for a particular service.
        
        Although if you call it as a module your code would look more like this:
            a = classauth.identity('USA')
            print a.get_token()
    """
    print "---------------------------------------------------------------"
    print "Secret Auth Benchmark Easter Egg"
    print "This is what this library does."
    print "\n"
    print "---------------------------------------------------------------"
    print "CACHED AUTH LIBRARY RESULT DEMONSTRATION:"
    print "---------------------------------------------------------------"
    beforedemo = time.time()  # Sets up way to calculate demo time.
    # >>>> Demo functions for this module:
    # --- ---  --- ---  --- ---  --- ---  --- ---  --- ---  --- ---  --- ---  --- ---  --- ---  --- --- 
    auth  = identity('dfw')
    print "Auth Token:\t\t" + auth.get_token()                            # Auth token
    print "Auth Tenant:\t\t" +  str(auth.get_tenantid())                       # Tenant id
    print "Auth Expires:\t\t"  +  auth.get_expires()                       # Expiration if you want it

    print "CloudDNS  Endpoint:\t" + auth.get_endpoint('cloudDNS') # If the endpoint has no region (ie clouddns, cloudservers) leave off the second arg
    print "Databases Endpoint:\t" + auth.get_endpoint('cloudDatabases','ORD') # If the endpoint has a region, define region as SECOND arg.
    print "Databases TenantID:\t" + auth.get_endpoint_tenantid('cloudDatabases','ORD') # Grabs a products tenant ID.

    # print "Auth Servicecatalog:\t"  + str(auth.get_serviceCatalog())  # Prints entire service catalog as object.
    # print auth.get_json()  # Prints pretty json for entire object.    # Prints entire auth object as pretty json.
    # --- ---  --- ---  --- ---  --- ---  --- ---  --- ---  --- ---  --- ---  --- ---  --- ---  --- --- 
    # >>>> END DEMO SNIPLET
    afterdemo = time.time() # Sets up way to calculate demo time.
    
    math = afterdemo - beforedemo
    print "\n\nTOTAL TIME TAKEN WITH CACHE:\t " + str(math) + "(seconds)\n\n"

    print "---------------------------------------------------------------"
    print "DEMO OF FORCING A REMOTE TOKEN PULL."
    print "Only useful if you want to force a new serialized object to disk cache."
    print "But this class handles that for you... so... look how slow it is."
    print "---------------------------------------------------------------"

    beforedemo = time.time()  # Sets up way to calculate demo time.
    # >>>> Demo functions while FORCING a new token:
    # --- ---  --- ---  --- ---  --- ---  --- ---  --- ---  --- ---  --- ---  --- ---  --- ---  --- --- 
    reAuth  = identity('dfw','force')
    print "Auth Token:\t" + reAuth.get_token()
    print "Auth Expires:\t\t"  +  auth.get_expires()                       # Expiration if you want it
    # --- ---  --- ---  --- ---  --- ---  --- ---  --- ---  --- ---  --- ---  --- ---  --- ---  --- --- 
    # >>>> END DEMO SNIPLET
    afterdemo = time.time() # Sets up way to calculate demo time.

    math = afterdemo - beforedemo  
    print "\n\nTOTAL TIME TAKEN WITH OUTBOUND TO IDENTITY API:\t " + str(math) + "(seconds)\n\n"

