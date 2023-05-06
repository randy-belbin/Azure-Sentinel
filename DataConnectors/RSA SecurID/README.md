# Ingest DocuSign Security Events
**Author: Sreedhar Ande**

RSA SecurID connector ingests   
	1. Ingest the audit log events  
		- /AdminInterface/restapi/v1/adminlog/exportlogs  
		- https://community.rsa.com/t5/securid-cloud-authentication/cloud-administration-event-log-api/ta-p/623069
	2. Ingest the user event logs  
	   - /AdminInterface/restapi/v1/usereventlog/exportlogs  
	   - https://community.rsa.com/t5/securid-cloud-authentication/cloud-administration-user-event-log-api/ta-p/623082

**Note**  
The APIs mentioned above will retrieve records from the point where the previous call ended, in order to prevent duplication of records.

## **Pre-requisites**
1. The Cloud Administration REST APIs must authenticate themselves by including a JSON Web Token (JWT) in each request.   
   - https://community.rsa.com/t5/securid-cloud-authentication/manage-the-cloud-administration-api-keys/ta-p/623066  


## Configuration Steps to Deploy Function App
1. Click on Deploy to Azure (For both Commercial & Azure GOV)  
[![Deploy to Azure](https://aka.ms/deploytoazurebutton)](https://aka.ms/sentinel-docusignconnector-azuredeploy)
  

2. Select the preferred **Subscription**, **Resource Group** and **Location**  
   **Note**  
   Best practice : Create new Resource Group while deploying - all the resources of your custom Data connector will reside in the newly created Resource 
   Group
   
3. Provide values in the ARM template  
	
	
## Post Deployment Steps
1. **Important**  
   **After successful deployment, Navigate to Resource Group and search for storage account, named - `<<FunctionAppName>><<uniqueid>>` and upload previously saved file **"RSA_Credentials.key"** to "RSASecurID" container**  

2. Workspace Key will be placed as "Secrets" in the Azure KeyVault `<<FunctionAppName>><<uniqueid>>` with only Azure Function access policy. If you want to see/update these secrets,

	```
		a. Go to Azure KeyVault "<<FunctionAppName>><<uniqueid>>"
		b. Click on "Access Policies" under Settings
		c. Click on "Add Access Policy"
			i. Configure from template : Secret Management
			ii. Key Permissions : GET, LIST, SET
			iii. Select Prinicpal : <<Your Account>>
			iv. Add
		d. Click "Save"

	```
	After granting permissions, If you want to update/change value for any Secrets
	** Step 1 : Update existing Secret Value **
	```
		a. Go to Azure KeyVault "<<FunctionAppName>><<uniqueid>>"
		b. Click on "Secrets" and select "Secret Name"
		c. Click on "New Version" to create a new version of the existing secret.
		d. Copy "Secret Identifier"
	```
	
	** Step 2 : Update KeyVault Reference in Azure Function **
	```
	   a. Go to your Resource Group --> Click on Function App `<<FunctionAppName>><<uniqueid>>`
	   b. Click on Function App "Configuration" under Settings 
	   c. Click on envionment variable that has value in KeyVault under "Application Settings"
	   d. Update value @Microsoft.KeyVault(SecretUri=<<Step 1 copied Secret Identifier URI>>).
	   e. Before clicking OK, make sure the status is "Resolved"
    ```

3. The `TimerTrigger` makes it incredibly easy to have your functions executed on a schedule. The default **Time Interval** is set to pull the last ten (10) minutes of data. If the time interval needs to be modified, it is recommended to change the Function App Timer Trigger accordingly update environment variable **"Schedule**" to prevent overlapping data ingestion.
   ```
   a.	Go to your Resource Group --> Click on Function App `<<FunctionAppName>><<uniqueid>>`
   b.	Click on Function App "Configuration" under Settings 
   c.	Click on "Schedule" under "Application Settings"
   d.	Update your own schedule using cron expression.
   ```
   **Note: For a `TimerTrigger` to work, you provide a schedule in the form of a [cron expression](https://en.wikipedia.org/wiki/Cron#CRON_expression)(See the link for full details). A cron expression is a string with 6 separate expressions which represent a given schedule via patterns. The pattern we use to represent every 10 minutes is `0 */10 * * * *`. This, in plain text, means: "When seconds is equal to 0, minutes is divisible by 10, for any hour, day of the month, month, day of the week, or year".**

4. Parameterized event duration using environment variable "EventTimeInterval". Value must be in minutes.  
   **Note**  
   The values for the Azure Function trigger Schedule and EventTimeInterval must match each other.  
   
   Ex: If you want to trigger function every 10 min then values must be  
   EventTimeInterval=10  
   Schedule=0 */10 * * * *