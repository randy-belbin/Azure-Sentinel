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
$logAnalyticsUri = $env:LAURI
$RSA_LogA_Table = $env:LATableName
$EventTimeInterval = $env:EventTimeInterval
$storageAccountContainer = "rsasecurid"

$AzFunDrive = (Get-Location).Drive.Root
$CheckpointFile = "$($AzFunDrive)home\site\RSACheckpoint.csv"
$RSACredentialsPath = "$($AzFunDrive)home\site\RSA_Credentials.key"
$CheckpointFile = "$($AzFunDrive)home\site\RSACheckpoint.csv"


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
        Get-AzStorageBlobContent -Blob "RSA_Credentials.key" -Container $storageAccountContainer -Context $storageAccountContext -Destination $RSAPrivateKeyToSignPath -Force    
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

# Function to POST the data payload to a Log Analytics workspace
function Post-LogAnalyticsData($customerId, $sharedKey, $body, $logType) {
    $method="POST"
    $contentType = "application/json"
    $resource = "/api/logs"
    $rfc1123date = [DateTime]::UtcNow.ToString("r")
    $logAnalyticsUri = $logAnalyticsUri + $resource + "?api-version=2016-04-01"
    $body = $body | ConvertTo-Json
    $contentLength = $body.Length
    $signature = Build-Signature `
        -customerId $customerId `
        -sharedKey $sharedKey `
        -date $rfc1123date `
        -contentLength $contentLength `
        -method $method `
        -contentType $contentType `
        -resource $resource

    
    $LAheaders = @{
        "Authorization" = $signature;
        "Log-Type" = $logType;
        "x-ms-date" = $rfc1123date;
        "time-generated-field" = $TimeStampField
    }
    
    #Test Size; Log A limit is 30MB
    $tempdata = @()
    $tempDataSize = 0
    
    if ((($body |  Convertto-json -depth 20).Length) -gt 25MB) {        
		Write-Host "Upload is over 25MB, needs to be split"									 
        foreach ($record in $body) {            
            $tempdata += $record
            $tempDataSize += ($record | ConvertTo-Json -depth 20).Length
            if ($tempDataSize -gt 25MB) {                
                $response = Invoke-WebRequest -Body $tempdata -Uri $logAnalyticsUri -Method $method -ContentType $contentType -Headers $LAheaders
                write-Host "Sending data = $TempDataSize"
                $tempdata = $null
                $tempdata = @()
                $tempDataSize = 0
            }
        }
        Write-Host "Sending left over data = $Tempdatasize"
        $response = Invoke-WebRequest -Body $body -Uri $logAnalyticsUri -Method $method -ContentType $contentType -Headers $LAheaders
        
    }
    Else {        
        $response = Invoke-WebRequest -Body $body -Uri $logAnalyticsUri -Method $method -ContentType $contentType -Headers $LAheaders
    }
    
    return $response.StatusCode
}

# Function to build the authorization signature to post to Log Analytics
Function Build-Signature ($customerId, $sharedKey, $date, $contentLength, $method, $contentType, $resource) {
    $xHeaders = "x-ms-date:" + $date
    $stringToHash = $method + "`n" + $contentLength + "`n" + $contentType + "`n" + $xHeaders + "`n" + $resource
    $bytesToHash = [Text.Encoding]::UTF8.GetBytes($stringToHash)
    $keyBytes = [Convert]::FromBase64String($sharedKey)
    $sha256 = New-Object System.Security.Cryptography.HMACSHA256
    $sha256.Key = $keyBytes
    $calculatedHash = $sha256.ComputeHash($bytesToHash)
    $encodedHash = [Convert]::ToBase64String($calculatedHash)
    $authorization = 'SharedKey {0}:{1}' -f $customerId,$encodedHash
    return $authorization
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
    # Format Endpoint Admin/User
    If ($RSA_Log_Type.ToLower() -eq "admin") {
        $RSA_API_End_Point = "$($RSAKeyJson.adminRestApiUrl)v1/adminlog/exportlogs?startTimeAfter=$($EventStartTime)"        
    } 
    elseif ($RSA_Log_Type.ToLower() -eq "user") {
        $RSA_API_End_Point = "$($RSAKeyJson.adminRestApiUrl)v1/usereventlog/exportlogs?startTimeAfter=$($EventStartTime)"        
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
                if ($($apiResponse.totalElements) -gt 0) {                
                    $responseCode = Post-LogAnalyticsData -customerId $workspaceId -sharedKey $workspaceKey -body $apiResponse.elements -logType $RSA_LogA_Table
                
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
                    Write-Host "No records found between $EventStartTime and $endTime" -ForegroundColor Red
                    Exit
                }                 			       
            }
            catch{			
                write-host "Error : $_.ErrorDetails.Message"
                write-host "Command : $_.InvocationInfo.Line"			
            }                   
        } While ($iterations -le $apiResponse.totalPages )

        $endTime = (Get-Date).ToString("yyyy-MM-ddTHH:mm:ss.fffzzz")
        Write-Host "SUCCESS: $($apiResponse.totalElements) records found between $EventStartTime and $endTime and posted to Log Analytics" -ForegroundColor Green
        UpdateCheckpointTime -CheckpointFile $checkPointFile -LastSuccessfulTime $endTime

        Remove-Item $RSACredentialsPath -Force
        Remove-Item $RSAPrivateKeyToSignPath -Force
    }
    catch {	
        write-host "Error : $_.ErrorDetails.Message"
        write-host "Command : $_.InvocationInfo.Line"
    }
}

Get-RSASecurIDEvent


