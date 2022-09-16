import urllib.parse
import requests
import json

appId = "bc277e37-75da-4d63-985c-a8d90db2faf8"
appSecret = "StC8Q~5zwDtudBjirDiaE2kNNm~kx99s~4EQnciB"
TenantId = "5f1060f2-d9a4-4f59-bf9c-1dd8f3604a4b"
DcrImmutableId = ""
DceURI = "https://mycustomlogsapiingestion-lcm5.westus2-1.ingest.monitor.azure.com"

uri = "https://login.microsoftonline.com/"+ TenantId +"/oauth2/v2.0/token"
scope = urllib.parse.quote_plus("https://monitor.azure.com//.default")
body = "client_id=" + appId + "&scope=" + scope + "&client_secret=" + appSecret + "&grant_type=client_credentials"
headers = {
            'content-type': "application/x-www-form-urlencoded"            
        }
response = requests.post(uri, data=body, headers=headers)
g = json.loads(response.content)
bearerToken = g["access_token"]