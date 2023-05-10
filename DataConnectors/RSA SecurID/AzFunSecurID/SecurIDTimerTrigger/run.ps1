<#  
    Title:          SecureID cloud-administration-event-log-api
    Language:       PowerShell
    Version:        1.0
    Author:         Sreedhar Ande
    Last Modified:  5/5/2023
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
    Write-Host "Azure Function triggered at: $currentUTCtime - timer is running late!"
}
else{
    Write-Host "Azure Function triggered at: $currentUTCtime - timer is ontime!"
}

$AzureWebJobsStorage = $env:AzureWebJobsStorage
$workspaceId = $env:WorkspaceId
$workspaceKey = $env:WorkspaceKey
$firstStartTimeRecord = $env:firstStartTimeRecord
$RSA_Log_Type = $env:LogType
$LAURI = $env:LAURI
$RSA_LogA_Table = $env:LATableName
$EventTimeInterval = $env:EventTimeInterval
$storageAccountContainer = "rsasecurid"

$AzFunDrive = (Get-Location).Drive.Root
$CheckpointFile = "$($AzFunDrive)home\site\RSACheckpoint.csv"
$RSACredentialsPath = "$($AzFunDrive)home\site\RSA_Credentials.key"
$RSAPrivateKeyToSignPath = "$($AzFunDrive)home\site\RSA_PrivateKey.key"



if($logAnalyticsUri.Trim() -notmatch 'https:\/\/([\w\-]+)\.ods\.opinsights\.azure.([a-zA-Z\.]+)$')
{
    Write-Error -Message "Invalid Log Analytics Uri." -ErrorAction Stop
    Exit
}

# Main
if ($env:MSI_SECRET -and (Get-Module -ListAvailable Az.Accounts)){
    Connect-AzAccount -Identity
}

Function Read-PrivateCerti {
    $storageAccountContext = New-AzStorageContext -ConnectionString $AzureWebJobsStorage
    $checkBlob = Get-AzStorageBlob -Blob "RSA_Credentials.key" -Container $storageAccountContainer -Context $storageAccountContext
    if($null -ne $checkBlob){
        Get-AzStorageBlobContent -Blob "RSA_Credentials.key" -Container $storageAccountContainer -Context $storageAccountContext -Destination $RSACredentialsPath -Force    
        #Read SecurID API Key file
        $RSAKeyJson = Get-Content $RSACredentialsPath -Raw | ConvertFrom-Json
        Set-Content -Path $RSAPrivateKeyToSignPath -Value $RSAKeyJson.accessKey
        return $RSAKeyJson
    } else {
        Write-Error "No RSA_Credentials.key file, exiting"
        Exit
    }   
}

Function Get-SignedJWTToken {            
    # Step 1. Create a JWT
    $timestamp = [int][double]::Parse((Get-Date (Get-Date).ToUniversalTime() -UFormat %s))

    $RSAJwtHeader = [ordered]@{
        'typ' = 'JWT';
        'alg' = 'RS256'
    } | ConvertTo-Json -Compress

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

    try{
        Add-Type -Path "$($AzFunDrive)home\site\wwwroot\Modules\DerConverter.dll"
        Add-Type -Path "$($AzFunDrive)home\site\wwwroot\Modules\PemUtils.dll"
        
        $keyStream = [System.IO.File]::OpenRead($RSAPrivateKeyToSignPath)    
        $pemReader = [PemUtils.PemReader]::new($keyStream)
        $rsaKey = $pemReader.ReadRsaKey()	
        $rsa = [System.Security.Cryptography.RSA]::Create($rsaKey)

        $tokenBytes = [System.Text.Encoding]::ASCII.GetBytes($jwtToken)
        $signedToken = $rsa.SignData(
            $tokenBytes,
            [System.Security.Cryptography.HashAlgorithmName]::SHA256,
            [System.Security.Cryptography.RSASignaturePadding]::Pkcs1)

        $signedBase64Token = [System.Convert]::ToBase64String($signedToken) -replace '\+', '-' -replace '/', '_' -replace '='

        $jwtToken = "$encJwtHeader.$encJwtPayLoad.$signedBase64Token"

        $keyStream.Close()
        $keyStream.Dispose()
    }
    catch {
        Write-Output "Please check you have DerConverter.dll and PemUtils.dll under $($AzFunDrive)home\site\wwwroot\Modules\"
        $keyStream.Close()
        $keyStream.Dispose()
    }

    return $jwtToken
}


Function Write-OMSLogfile { 
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
        try {
            $response = Invoke-WebRequest -Uri $LAURI.Trim() -Method $method -ContentType $contentType -Headers $headers -Body $Body
            Write-Verbose -message ('Post Function Return Code ' + $response.statuscode)
            return $response.statuscode
        }
        catch {
            Write-Error "An error occurred: $($_.Exception.Message)"
        }
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
    try {
        $returnCode = PostLogAnalyticsData -CustomerID $CustomerID -SharedKey $SharedKey -Body $logMessage -Type $type
        return $returnCode
    }
    catch {
        Write-Error "An error occurred: $($_.Exception.Message)"
    }
    
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

# Function to retrieve the checkpoint start time of the last successful API call for a given logtype. Checkpoint file will be created if none exists
function GetStartTime($CheckpointFile) {
    if ([System.IO.File]::Exists($CheckpointFile) -eq $false) {        
        if ($null -eq $firstStartTimeRecord) {
            $firstStartTimeRecord = (Get-Date).ToString("yyyy-MM-ddTHH:mm:ss.fffzzz")
        } else {
            Write-Host "Requested Start Time Record :" $firstStartTimeRecord    
            $dt = Get-Date("$firstStartTimeRecord")
            $firstStartTimeRecord = $dt.ToString("yyyy-MM-ddTHH:mm:ss.fffzzz")
            Write-Host "Requested Start Time Record :" $firstStartTimeRecord
        }
        $CheckpointLog = @{}
        $CheckpointLog.Add('LastSuccessfulTime', $firstStartTimeRecord)
        $CheckpointLog.GetEnumerator() | Select-Object -Property Key,Value | Export-CSV -Path $CheckpointFile -NoTypeInformation
        return $firstStartTimeRecord
    }
    else {
        $GetLastRecordTime = Import-Csv -Path $CheckpointFile
        $startTime = $GetLastRecordTime | ForEach-Object {
                        if($_.Key -eq 'LastSuccessfulTime') {
                            $_.Value
                        }
                    }
        
        $IntEventTimeInterval = [int]$EventTimeInterval
        $startTime = [DateTime]::ParseExact($startTime, "yyyy-MM-ddTHH:mm:ss.fffzzz", $null)
        $startTime = $startTime.AddMinutes(-$IntEventTimeInterval).ToString("yyyy-MM-ddTHH:mm:ss.fffzzz")        
        
        return $startTime
    }
}

# Function to update the checkpoint time with the last successful API call end time
function UpdateCheckpointTime($CheckpointFile, $LastSuccessfulTime){
    $checkpoints = Import-Csv -Path $CheckpointFile
    $checkpoints | ForEach-Object{ if($_.Key -eq 'LastSuccessfulTime'){$_.Value = $LastSuccessfulTime}}
    $checkpoints | Select-Object -Property Key,Value | Export-CSV -Path $CheckpointFile -NoTypeInformation
}

function Get-RSASecurIDEvent {
    $RSAKeyJson = Read-PrivateCerti
    $EventStartTime = GetStartTime -CheckpointFile $CheckPointFile
    $EventStartTime = $EventStartTime.replace('+', '%2B')
    # Format Endpoint Admin/User
    If ($RSA_Log_Type.ToLower() -eq "admin") {
        $RSA_API_End_Point = "$($RSAKeyJson.adminRestApiUrl)v1/adminlog/exportlogs?startTimeAfter=$($EventStartTime)"  
        Write-Host $RSA_API_End_Point  
    } 
    elseif ($RSA_Log_Type.ToLower() -eq "user") {
        $RSA_API_End_Point = "$($RSAKeyJson.adminRestApiUrl)v1/usereventlog/exportlogs?startTimeAfter=$($EventStartTime)"        
        Write-Host $RSA_API_End_Point
    }
    # Call the Endpoint
    try {	        
        $signedBase64Token = Get-SignedJWTToken
        $RSAAPIHeaders = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
        $RSAAPIHeaders.Add("Content-Type", "application/json")
        $RSAAPIHeaders.Add("Authorization", "Bearer $signedBase64Token")
                
        $iterations=1        
        DO{            
            try{			
                $apiResponse = $null			
                Write-Output "Calling RSA API"
                $apiResponse = Invoke-RestMethod -Uri $RSA_API_End_Point -Method 'GET' -Headers $RSAAPIHeaders
                Write-Host "$($apiResponse.elements.Length)"
                if ($($apiResponse.totalElements) -gt 0) {                
                    $responseCode = SendToLogA -EventsData $($apiResponse.elements) -EventsTable $RSA_LogA_Table
                
                    if ($responseCode -ne 200){
                        Write-Error -Message "ERROR: Log Analytics POST, Status Code: $responseCode, unsuccessful."
                    }
                    else {
                        if ($($apiResponse.totalPages) -gt 1) {
                            $iterations++
                            If ($RSA_Log_Type.ToLower() -eq "admin") {
                                $RSA_API_End_Point = "$($RSAKeyJson.adminRestApiUrl)v1/adminlog/exportlogs?startTimeAfter=$($EventStartTime)&page=$iterations"        
                            } 
                            elseif ($RSA_Log_Type.ToLower() -eq "user") {
                                $RSA_API_End_Point = "$($RSAKeyJson.adminRestApiUrl)v1/usereventlog/exportlogs?startTimeAfter=$($EventStartTime)&page=$iterations"        
                            }            
                        }       
                        
                    }   
                } else {
                    $endTime = (Get-Date).ToString("yyyy-MM-ddTHH:mm:ss.fffzzz")
                    Write-Host "No records found between $EventStartTime and $endTime" -ForegroundColor Red
                    Exit
                }                 			       
            }
            catch{			
                Write-Error "An error occurred: $($_.Exception.Message)"		
            }                   
        } While ($iterations -le $apiResponse.totalPages )

        $endTime = (Get-Date).ToString("yyyy-MM-ddTHH:mm:ss.fffzzz")
        if ($responseCode -eq 200) {
            Write-Host "SUCCESS: $($apiResponse.totalElements) records found between $EventStartTime and $endTime and posted to Log Analytics" -ForegroundColor Green
        }
        UpdateCheckpointTime -CheckpointFile $checkPointFile -LastSuccessfulTime $endTime

        Remove-Item $RSACredentialsPath -Force
        Remove-Item $RSAPrivateKeyToSignPath -Force
    }
    catch {	
        Write-Error "An error occurred: $($_.Exception.Message)"
    }
}

Get-RSASecurIDEvent


