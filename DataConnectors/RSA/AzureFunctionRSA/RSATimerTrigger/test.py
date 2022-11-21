import json
import logging
import re
from datetime import datetime, timedelta
import time
import sys
import requests
import jwt

log_type = "admin"

class SecurIDCloud():
    def __init__(self, log_type, securid_host, securid_api_key_file, page_size):
        """
        Initialize SecurID Cloud 
        """
        self.log_type = log_type
        self.securid_host = securid_host
        self.securid_api_key_

        # Only admin and user log types are supported
        if log_type.lower() == "admin": 
            self.log_type = "admin"           
            self.url2 = "/AdminInterface/restapi/v1/adminlog/exportlogs"
            self.entry_name = "elements"
        elif log_type.lower() == "user": 
            self.log_type = "user"           
            self.url2 = "/AdminInterface/restapi/v1/usereventlog/exportlogs"
            self.entry_name = "userEventLogExportEntries"
        else:
            print("Missing or invalid log_type, defaulting to admin")
            self.log_type = "admin"
            self.url2 = "/AdminInterface/restapi/v1/adminlog/exportlogs"
            self.entry_name = "elements"
          
        self.logger.info("Starting RSA SecurID Cloud API fetch driver for %s", self.log_type)

        # Initialize empty array of log messages
        self.logs = []

        # Ensure url parameter is defined
        if "url" in options:
            self.url = options["url"]
            self.logger.info("Initializing driver against URL %s", self.url)
        else:
            self.logger.error("Missing url configuration option for %s", self.log_type)
            self.exit = True
            return False

        # Ensure RSA SecurID key is uploaded to Azure Blob
        if "rsa_key" in options:
            self.rsa_key = options["rsa_key"]
            self.logger.debug("Initializing driver with rsa_key %s for %s", \
                self.rsa_key, self.log_type)
        else:
            self.logger.error("Missing rsa_key path configuration option for %s", self.log_type)
            self.exit = True
            return False

        # Set page size if defined
        self.page_size = 100       
       
        # Get the current datetime in UTC to avoid timezone fun
        self.start_time = self.to_rsa_timestamp(datetime.utcnow())

        #READ CSV
        self.start_time = self.persist["last_read"]
        self.start_time = self.to_rsa_timestamp(datetime.utcnow())
        
        self.logger.info("Driver initialization complete, fetch window starts at %s", \
            self.start_time)

        return True


    def fetch(self):
        """
        Return a log message by pulling from the internal list or pulling from the RSA SecurID Cloud API
        
        """

        # Retrieve log messages from memory if present
        if self.logs:
            log = self.logs.pop(0)
            msg = self.parse_log(log)
            return msg

        # Get current datetime
        self.end_time = self.to_rsa_timestamp(datetime.utcnow())

        # UTL to retrieve log messages from RSA SecurID Cloud API
        subscription_url = self.url + self.url2 + \
            "?startTimeAfter=" + self.start_time + \
                "&endTimeOnOrBefore=" + self.end_time + \
                    "&pageSize=" + str(self.page_size)

        # Headers for request
        headers =  {"Content-Type":"application/application-json", \
            "Accept":"application/json", "Authorization": "Bearer %s" \
            % self.bearer_token}

        # Perform HTTP request
        response = requests.get(subscription_url, headers=headers)

        # Ingore 504 errors
        if response.status_code == 504:
            self.logger.info("Gateway Timeout from RSA SecurID Cloud")
            return "Gateway Timeout"

        # Ingore 400 errors
        if response.status_code == 400:
            self.logger.info("Bad Error Request : %s", subscription_url)
            return "Bad Request"

        # If the API call returns successfully, parse the retrieved json data
        if response.status_code == 200:

            try:
                result = response.json()
                total_records = result['totalElements']
                total_pages = result['totalPages']
                current_page = result['currentPage']

                # Set internal log buffer to all returned events
                self.logs = result[self.entry_name]
                self.logger.debug("%i events available", total_records)

            except Exception as e_all:
                return "%s - access failure : %s\n%s", \
                    self.url, e_all, response.text

            # If there are more pages of events to process
            while current_page < total_pages:

                # increment page counter
                current_page = current_page + 1

                # URL to retrieve log messages from RSA SecurID Cloud API
                subscription_url = self.url + self.url2 + \
                    "?startTimeAfter=" + self.start_time + \
                        "&endTimeOnOrBefore=" + self.end_time + \
                            "&pageSize=" + str(self.page_size) + \
                                "&pageNumber=" + str(current_page)

                headers =  {"Content-Type":"application/application-json", \
                    "Accept":"application/json", "Authorization": "Bearer %s" \
                    % self.bearer_token}

                # Perform HTTP request
                response = requests.get(subscription_url, headers=headers)

                # If we're successful, parse the json result
                if response.status_code == 200:
                    try:
                        result = response.json()
                    except Exception as e_all:
                        return "%s - access failure : %s\n%s", \
                            self.url, e_all, response.text

                    # Add each event to our internal logs list
                    for entry in result[self.entry_name]:
                        self.logs.append(entry)

                # If something went wrong with the query
                else:
                    return "%s - %s access failure:\n%s", \
                        self.url, self.log_type, response.text

            # Set start time to end time
            self.start_time = self.end_time

            # If there are new logs
            if self.logs:
                # Process each log message
                log = self.logs.pop(0)
                msg = self.parse_log(log)
                return msg

            # If there aren't new logs
            #update csv with self.end_time
            return "No new events available"

        # If the bearer token is invalid
        if response.status_code == 403:
            self.logger.error("Bearer token invalid or expired")
            return "bearer token expired or invalid"

        # If the response code isn't 504 or 200 (or isn't even set)
        return "%s - access failure:\n%s", \
            self.url, response.text


    def open(self):
        """
        Retrieve bearer token for RSA SecurID Cloud        
        """

        # Auth token is needed for all API requests
        self.logger.info("Retreiving bearer token for RSA SecurID Cloud for %s", self.log_type)
        self.bearer_token = self.generate_token()

        # Critical failure if we're unable to generate an auth token
        if self.bearer_token is False:
            self.logger.error("Unable to acquire auth token")
            return False

        return True

    def to_rsa_timestamp(self, stamp):
        """
        Converts a datetime object to a string format used by RSA SecurID Cloud
        """

        tseconds = int(int(stamp.strftime("%f")) / 1000)
        timestamp = stamp.strftime("%Y-%m-%dT%H:%M:%S.") + str(tseconds) + "-00:00"
        return timestamp


    def parse_log(self, log):
        """
        Parse an event into a syslog LogMessage
        (custom function for message parsing)
        """        
        msg = json.dumps(log)
        # Return LogMessage
        return msg


    def parse_key(self):
        """
        Parse the contents of the RSA SecurID Cloud Admin API key file
        """

        # Open key and verify all required values are set
        try:
            with open(self.rsa_key, "r") as keyFile:
                key = json.load(keyFile)
                if "adminRestApiUrl" not in key:
                    self.logger.error("Failed to parse adminRestApiUrl from the RSA SecurID Cloud Admin API key")
                    self.exit = True
                    return False
                if "accessID" not in key:
                    self.logger.error("Failed to parse accessID from the RSA SecurID Cloud Admin API key")
                    self.exit = True
                    return False
                if "accessKey" not in key:
                    self.logger.error("Failed to parse accessKey from the RSA SecurID Cloud Admin API key")
                    self.exit = True
                    return False
                return key

        except IOError as e:
                self.logger.error("Encountered error attempting to parse the RSA SecurID Cloud Admin API key: '{0}'\n".format(self.rsa_key))
                self.logger.info(str(e) + "\n")
                self.exit = True
                return False


    def generate_token(self):
        """
        Generate JWT token based off Admin API key file
        """

        # Get contents of key as dict
        key = self.parse_key()

        # Initialize to the max valid period for a jwt of 60 minutes
        exp = time.time() + 60 * 60

        # Build out jwt claim for auth token
        jwt_claims = {
            "iat": time.time(), # Set issued at time to the current time.
            "exp": exp, # Set expiration time
            "aud": key["adminRestApiUrl"],  # Audience of the claim.
            "sub": key["accessID"], # Access ID from the Admin API Key.
        }

        # Use the accessKey from the Admin API key file and the RS256 algorithm to generate the JWT
        try:
            jwt_token = jwt.encode(
                payload=jwt_claims,
                key=key["accessKey"],
                algorithm="RS256"
            )
        except Exception as ex:
            self.logger.error("Unable to generate jwt token from %s : %s", self.rsa_key, ex)

        return jwt_token

def main():
    securIDCloud = SecurIDCloud()
    securIDCloud.fetch()