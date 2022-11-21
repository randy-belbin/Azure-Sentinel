<#  
    Title:          SecureID cloud-administration-event-log-api
    Language:       PowerShell
    Version:        1.0
    Author:         Sreedhar Ande
    Last Modified:  11/11/2022
    Comment:        The Cloud Administration Event Log API is a REST-based web services interface that allows audit log events to be retrieved from the Cloud Authentication Service.
    Note:Above API's resumes getting records from the spot where the previous call left off to avoid duplication of records in RSACloudAdministrationEventLogs_CL Log Analytics Workspace custom tables

    DESCRIPTION
    This Function App calls the SecureID Cloud administration REST API (AdminInterface/restapi/v1/adminlog/exportlogs) to pull the events. 
    The response from the REST API is recieved in JSON format. This function will build the signature and authorization header 
    needed to post the data to the Log Analytics workspace via the HTTP Data Connector API.
#>

# Input bindings are passed in via param block.
param($Timer)

# Get the current universal time in the default string format.
$currentUTCtime = (Get-Date).ToUniversalTime()

if ($Timer.IsPastDue) {
    Write-Host "RSA-CloudAdministrationEventLogs: Azure Function triggered at: $currentUTCtime - timer is running late!"
}
else{
    Write-Host "RSA-CloudAdministrationEventLogs: Azure Function triggered at: $currentUTCtime - timer is ontime!"
}

# Main
if ($env:MSI_SECRET -and (Get-Module -ListAvailable Az.Accounts)){
    Connect-AzAccount -Identity
}


$AzureWebJobsStorage = $env:AzureWebJobsStorage
$RSAAdminUserGUID = $env:RSAAdminUserGUID
$RSAAccountAPIID = $env:RSAAccountAPIID
$RSAEnvironment = $env:RSAEnvironment
$workspaceId = $env:WorkspaceId
$workspaceKey = $env:WorkspaceKey
$storageAccountContainer = "RSA-monitor"
$storageAccountTableName = "RSAexecutions"
$LATableDSMAPI = $env:LATableDSMAPI
$LATableDSUsers = $env:LATableDSUsers
$LAURI = $env:LAURI
$RSAUserInfoBaseURI = $env:RSAUserInfoBaseURI

$currentStartTime = (get-date).ToUniversalTime() | get-date  -Format yyyy-MM-ddTHH:mm:ss:ffffffZ
Write-Output "LAURI : $LAURI"

if($LAURI.Trim() -notmatch 'https:\/\/([\w\-]+)\.ods\.opinsights\.azure.([a-zA-Z\.]+)$')
{
    Write-Error -Message "RSA-CloudAdministrationEventLogs: Invalid Log Analytics Uri." -ErrorAction Stop
	Exit
}

Function Write-OMSLogfile {
    <#
    .SYNOPSIS
    Inputs a hashtable, date and workspace type and writes it to a Log Analytics Workspace.
    .DESCRIPTION
    Given a  value pair hash table, this function will write the data to an OMS Log Analytics workspace.
    Certain variables, such as Customer ID and Shared Key are specific to the OMS workspace data is being written to.
    This function will not write to multiple OMS workspaces.  BuildSignature and post-analytics function from Microsoft documentation
    at https://docs.microsoft.com/azure/log-analytics/log-analytics-data-collector-api
    .PARAMETER DateTime
    date and time for the log.  DateTime value
    .PARAMETER Type
    Name of the logfile or Log Analytics "Type".  Log Analytics will append _CL at the end of custom logs  String Value
    .PARAMETER LogData
    A series of key, value pairs that will be written to the log.  Log file are unstructured but the key should be consistent
    withing each source.
    .INPUTS
    The parameters of data and time, type and logdata.  Logdata is converted to JSON to submit to Log Analytics.
    .OUTPUTS
    The Function will return the HTTP status code from the Post method.  Status code 200 indicates the request was received.
    .NOTES
    Version:        2.0
    Author:         Travis Roberts
    Creation Date:  7/9/2018
    Purpose/Change: Crating a stand alone function    
    #>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory = $true, Position = 0)]
        [datetime]$dateTime,
        [parameter(Mandatory = $true, Position = 1)]
        [string]$type,
        [Parameter(Mandatory = $true, Position = 2)]
        [psobject]$logdata,
        [Parameter(Mandatory = $true, Position = 3)]
        [string]$CustomerID,
        [Parameter(Mandatory = $true, Position = 4)]
        [string]$SharedKey
    )
    Write-Verbose -Message "DateTime: $dateTime"
    Write-Verbose -Message ('DateTimeKind:' + $dateTime.kind)
    Write-Verbose -Message "Type: $type"
    write-Verbose -Message "LogData: $logdata"   

    # Supporting Functions
    # Function to create the auth signature
    Function BuildSignature ($CustomerID, $SharedKey, $Date, $ContentLength, $Method, $ContentType, $Resource) {
        $xheaders = 'x-ms-date:' + $Date
        $stringToHash = $Method + "`n" + $contentLength + "`n" + $contentType + "`n" + $xHeaders + "`n" + $Resource
        $bytesToHash = [text.Encoding]::UTF8.GetBytes($stringToHash)
        $keyBytes = [Convert]::FromBase64String($SharedKey)
        $sha256 = New-Object System.Security.Cryptography.HMACSHA256
        $sha256.key = $keyBytes
        $calculateHash = $sha256.ComputeHash($bytesToHash)
        $encodeHash = [convert]::ToBase64String($calculateHash)
        $authorization = 'SharedKey {0}:{1}' -f $CustomerID, $encodeHash
        return $authorization
    }
    # Function to create and post the request
    Function PostLogAnalyticsData ($CustomerID, $SharedKey, $Body, $Type) {
        $method = "POST"
        $contentType = 'application/json'
        $resource = '/api/logs'
        $rfc1123date = ($dateTime).ToString('r')
        $ContentLength = $Body.Length
        $signature = BuildSignature `
            -customerId $CustomerID `
            -sharedKey $SharedKey `
            -date $rfc1123date `
            -contentLength $ContentLength `
            -method $method `
            -contentType $contentType `
            -resource $resource
        $LAURI = $LAURI.Trim() + $resource + "?api-version=2016-04-01"
		Write-Output "LAURI : $LAURI"
        $headers = @{
            "Authorization"        = $signature;
            "Log-Type"             = $type;
            "x-ms-date"            = $rfc1123date
            "time-generated-field" = $dateTime
        }
        $response = Invoke-WebRequest -Uri $LAURI.Trim() -Method $method -ContentType $contentType -Headers $headers -Body $Body -UseBasicParsing
        Write-Verbose -message ('Post Function Return Code ' + $response.statuscode)
        return $response.statuscode
    }   

    # Check if time is UTC, Convert to UTC if not.
    # $dateTime = (Get-Date)
    if ($dateTime.kind.tostring() -ne 'Utc') {
        $dateTime = $dateTime.ToUniversalTime()
        Write-Verbose -Message $dateTime
    }
    #Build the JSON file
    $logMessage = ($logdata | ConvertTo-Json -Depth 20)
    
    #Submit the data
    $returnCode = PostLogAnalyticsData -CustomerID $CustomerID -SharedKey $SharedKey -Body $logMessage -Type $type
    Write-Verbose -Message "Post Statement Return Code $returnCode"
    return $returnCode
}

Function SendToLogA ($eventsData, $eventsTable) {    	
	#Test Size; Log A limit is 30MB
    $tempdata = @()
    $tempDataSize = 0
    
    if ((($eventsData |  Convertto-json -depth 20).Length) -gt 25MB) {        
		Write-Host "Upload is over 25MB, needs to be split"									 
        foreach ($record in $eventsData) {            
            $tempdata += $record
            $tempDataSize += ($record | ConvertTo-Json -depth 20).Length
            if ($tempDataSize -gt 25MB) {
                $postLAStatus = Write-OMSLogfile -dateTime (Get-Date) -type $eventsTable -logdata $tempdata -CustomerID $workspaceId -SharedKey $workspaceKey
                write-Host "Sending data = $TempDataSize"
                $tempdata = $null
                $tempdata = @()
                $tempDataSize = 0
            }
        }
        Write-Host "Sending left over data = $Tempdatasize"
        $postLAStatus = Write-OMSLogfile -dateTime (Get-Date) -type $eventsTable -logdata $eventsData -CustomerID $workspaceId -SharedKey $workspaceKey
    }
    Else {          
        $postLAStatus = Write-OMSLogfile -dateTime (Get-Date) -type $eventsTable -logdata $eventsData -CustomerID $workspaceId -SharedKey $workspaceKey        
    }

    return $postLAStatus
}

$timestamp = [int][double]::Parse((Get-Date (Get-Date).ToUniversalTime() -UFormat %s))

$storageAccountContext = New-AzStorageContext -ConnectionString $AzureWebJobsStorage
$checkBlob = Get-AzStorageBlob -Blob "RSA_Key.key" -Container $storageAccountContainer -Context $storageAccountContext
if($null -ne $checkBlob){
    Get-AzStorageBlobContent -Blob "RSA_Key.key" -Container $storageAccountContainer -Context $storageAccountContext -Destination "$($cwd)home\site\RSA_Key.key" -Force
    $privateKeyPath = "$($cwd)home\site\RSA_Key.key"
}
else{
    Write-Error "No RSA_Key.key file, exiting"
    #exit
}

# Step 1. Read SecurID API Key file
$RSAKeyJson = Get-Content "C:\DemoADX\041a4bc6-fa5d-45b3-a0ba-13f5e1b7d295.key" -Raw | ConvertFrom-Json

# Step 2. Create a JWT

$exp = $timestamp + 7200

$RSAJwtPayLoad = [ordered]@{    
    'sub'   = $RSAKeyJson.accessID;
    'iat'   = $timestamp;
    'exp'   = $exp;
    'aud'   = $RSAKeyJson.adminRestApiUrl    
} | ConvertTo-Json -Compress

$encJwtHeaderBytes = [System.Text.Encoding]::UTF8.GetBytes($RSAJwtHeader)
$encJwtHeader = [System.Convert]::ToBase64String($encJwtHeaderBytes) -replace '\+', '-' -replace '/', '_' -replace '='

$encJwtPayLoadBytes = [System.Text.Encoding]::UTF8.GetBytes($RSAJwtPayLoad)
$encJwtPayLoad = [System.Convert]::ToBase64String($encJwtPayLoadBytes) -replace '\+', '-' -replace '/', '_' -replace '='

$jwtToken = "$encJwtHeader.$encJwtPayLoad"

# Step 3. Format Endpoint Admin/User
$RSA_Log_Type = "Admin"
If ($RSA_Log_Type.ToLower() -eq "admin") {
    $RSA_API_End_Point = "$($RSAKeyJson.adminRestApiUrl)v1/adminlog/exportlogs"
    $RSA_LogA_Table ="AdminEventLogExportEntries"
} 
elseif ($RSA_Log_Type.ToLower() -eq "user") {
    $RSA_API_End_Point = "$($RSAKeyJson.adminRestApiUrl)v1/usereventlog/exportlogs"
    $RSA_LogA_Table ="UserEventLogExportEntries"
}

# Step 4. Call the Endpoint
try {	
	#Setup uri Headers for requests to DSM API & User API
	$RSAAPIHeaders = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
	$RSAAPIHeaders.Add("Content-Type", "application/json")
	$RSAAPIHeaders.Add("Authorization", "Bearer $jwtToken")

	<#$StorageTable = Get-AzStorageTable -Name $storageAccountTableName -Context $storageAccountContext -ErrorAction Ignore
	if($null -eq $StorageTable.Name){  
		New-AzStorageTable -Name $storageAccountTableName -Context $storageAccountContext
		$RSATimeStampTbl = (Get-AzStorageTable -Name $storageAccountTableName -Context $storageAccountContext.Context).cloudTable    
		Add-AzTableRow -table $RSATimeStampTbl -PartitionKey "RSAmonitor" -RowKey "lastRunEndCursor" -property @{"lastCursorValue"=""} -UpdateExisting		
	}
	Else {
		$RSATimeStampTbl = (Get-AzStorageTable -Name $storageAccountTableName -Context $storageAccountContext.Context).cloudTable
	}
	# retrieve the last execution values
	$lastExeEndCursor = Get-azTableRow -table $RSATimeStampTbl -partitionKey "RSAmonitor" -RowKey "lastRunEndCursor" -ErrorAction Ignore	
	$lastRunEndCursorValue = $lastExeEndCursor.lastCursorValue#>
		
	$iterations=0
	DO{
		$iterations++	
		try{			
			$apiResponse = $null			
			Write-Output "Calling RSA API"
			$apiResponse = Invoke-RestMethod -Uri $RSA_API_End_Point -Method 'GET' -Headers $RSAAPIHeaders	
			
            $postReturnCode = SendToLogA -EventsData $apiResponse.elements -EventsTable $RSA_LogA_Table
            $CloudAdministrationEventLogsCount = $apiResponse.totalElements
            if($postReturnCode -eq 200)
            {
                Write-Output ("$CloudAdministrationEventLogsCount - RSA Security Events have been ingested into Azure Log Analytics Workspace Table --> $LATableDSMAPI")
            }       			       
		}
		catch{			
			write-host "Error : $_.ErrorDetails.Message"
			write-host "Command : $_.InvocationInfo.Line"			
		} 

	} While ($iterations -lt $apiResponse.total_pages )
	
	#users Export
	Add-AzTableRow -table $RSATimeStampTbl -PartitionKey "RSAmonitor" -RowKey "lastRunEndCursor" -property @{"lastCursorValue"=$lastRunEndCursorValue} -UpdateExisting                           
	Remove-Item $privateKeyPath -Force
	Write-Output "Done."

}
catch {	
	write-host "Error : $_.ErrorDetails.Message"
	write-host "Command : $_.InvocationInfo.Line"
}

