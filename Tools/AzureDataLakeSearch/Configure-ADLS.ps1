<#       
  	THE SCRIPT IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
	FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
	LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SCRIPT OR THE USE OR OTHER DEALINGS IN THE
	SOFTWARE.

    .SYNOPSIS
        The new Federated Search feature gives Microsoft Sentinel users the ability to search external data that is stored in an Azure Data Lake gen2 (ADLS v2). 
        You can now use the same Sentinel Search UI to create a Search job on external data repositories and use the search results in investigation and hunting queries.
    .DESCRIPTION
        It performs the following actions:
            1. Update Workspace to Use System Assigned Identity
            2. Grant Reader Permissions to the Workspace in the Storage Account
            3. Create an External Table in the Workspace
    
    .PARAMETER LogAnalyticsWorkSpaceName
        Enter the Log Analytics workspace name (required)
    
    .PARAMETER LogAnalyticsResourceGroupName
        Enter the Resource Group name of Log Analytics workspace (required)

    
    .NOTES
        AUTHOR: Sreedhar Ande
        LASTEDIT: 18 Jan 2023

    .EXAMPLE
        .Configure-ADLS.ps1 
#>

#region UserInputs

param(
    [parameter(Mandatory = $true, HelpMessage = "Enter your Tenant Id")] [string] $TenantID    
) 

#endregion UserInputs
      
#region HelperFunctions

function Write-Log {
    <#
    .DESCRIPTION 
    Write-Log is used to write information to a log file and to the console.
    
    .PARAMETER Severity
    parameter specifies the severity of the log message. Values can be: Information, Warning, or Error. 
    #>

    [CmdletBinding()]
    param(
        [parameter()]
        [ValidateNotNullOrEmpty()]
        [string]$Message,
        [string]$LogFileName,
 
        [parameter()]
        [ValidateNotNullOrEmpty()]
        [ValidateSet('Information', 'Warning', 'Error')]
        [string]$Severity = 'Information'
    )
    # Write the message out to the correct channel											  
    switch ($Severity) {
        "Information" { Write-Host $Message -ForegroundColor Green }
        "Warning" { Write-Host $Message -ForegroundColor Yellow }
        "Error" { Write-Host $Message -ForegroundColor Red }
    } 											  
    try {
        [PSCustomObject]@{
            Time     = (Get-Date -f g)
            Message  = $Message
            Severity = $Severity
        } | Export-Csv -Path "$PSScriptRoot\$LogFileName" -Append -NoTypeInformation -Force
    }
    catch {
        Write-Error "An error occurred in Write-Log() method" -ErrorAction SilentlyContinue		
    }    
}

function Get-RequiredModules {
    <#
    .DESCRIPTION 
    Get-Required is used to install and then import a specified PowerShell module.
    
    .PARAMETER Module
    parameter specifices the PowerShell module to install. 
    #>

    [CmdletBinding()]
    param (        
        [parameter(Mandatory = $true)] $Module        
    )
    
    try {
        $installedModule = Get-InstalledModule -Name $Module -ErrorAction SilentlyContinue       

        if ($null -eq $installedModule) {
            Write-Log -Message "The $Module PowerShell module was not found" -LogFileName $LogFileName -Severity Warning
            #check for Admin Privleges
            $currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())

            if (-not ($currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator))) {
                #Not an Admin, install to current user            
                Write-Log -Message "Can not install the $Module module. You are not running as Administrator" -LogFileName $LogFileName -Severity Warning
                Write-Log -Message "Installing $Module module to current user Scope" -LogFileName $LogFileName -Severity Warning
                
                Install-Module -Name $Module -Scope CurrentUser -Repository PSGallery -Force -AllowClobber
                Import-Module -Name $Module -Force
            }
            else {
                #Admin, install to all users																		   
                Write-Log -Message "Installing the $Module module to all users" -LogFileName $LogFileName -Severity Warning
                Install-Module -Name $Module -Repository PSGallery -Force -AllowClobber
                Import-Module -Name $Module -Force
            }
        }
        else {
            if ($UpdateAzModules) {
                Write-Log -Message "Checking updates for module $Module" -LogFileName $LogFileName -Severity Information
                $currentVersion = [Version](Get-InstalledModule | Where-Object {$_.Name -eq $Module}).Version
                # Get latest version from gallery
                $latestVersion = [Version](Find-Module -Name $Module).Version
                if ($currentVersion -ne $latestVersion) {
                    #check for Admin Privleges
                    $currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())

                    if (-not ($currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator))) {
                        #install to current user            
                        Write-Log -Message "Can not update the $Module module. You are not running as Administrator" -LogFileName $LogFileName -Severity Warning
                        Write-Log -Message "Updating $Module from [$currentVersion] to [$latestVersion] to current user Scope" -LogFileName $LogFileName -Severity Warning
                        Update-Module -Name $Module -RequiredVersion $latestVersion -Force
                    }
                    else {
                        #Admin - Install to all users																		   
                        Write-Log -Message "Updating $Module from [$currentVersion] to [$latestVersion] to all users" -LogFileName $LogFileName -Severity Warning
                        Update-Module -Name $Module -RequiredVersion $latestVersion -Force
                    }
                }
                else {
                    # Get latest version
                    $latestVersion = [Version](Get-Module -Name $Module).Version               
                    Write-Log -Message "Importing module $Module with version $latestVersion" -LogFileName $LogFileName -Severity Information
                    Import-Module -Name $Module -RequiredVersion $latestVersion -Force
                }
            }
            else {
                # Get latest version
                $latestVersion = [Version](Get-Module -Name $Module).Version               
                Write-Log -Message "Importing module $Module with version $latestVersion" -LogFileName $LogFileName -Severity Information
                Import-Module -Name $Module -RequiredVersion $latestVersion -Force
            }
        }
        # Install-Module will obtain the module from the gallery and install it on your local machine, making it available for use.
        # Import-Module will bring the module and its functions into your current powershell session, if the module is installed.  
    }
    catch {
        Write-Log -Message "An error occurred in Get-RequiredModules() method - $($_)" -LogFileName $LogFileName -Severity Error        
    }
}

#endregion

#region MainFunctions

function Get-LATables {	
	
	$TablesArray = New-Object System.Collections.Generic.List[System.Object]
	
	try {       
        Write-Log -Message "Retrieving tables from $LogAnalyticsWorkspaceName" -LogFileName $LogFileName -Severity Information
        $WSTables = Get-AllTables       
        $TablesArray = $WSTables | Sort-Object -Property TableName | Select-Object -Property TableName, IngestionPlan  | Out-GridView -Title "Select Table (For Multi-Select use CTRL)" -PassThru            
    }
    catch {
        Write-Log -Message $_ -LogFileName $LogFileName -Severity Error
        Write-Log -Message "An error occurred in querying table names from $LogAnalyticsWorkspaceName" -LogFileName $LogFileName -Severity Error         
        exit
    }
	
	return $TablesArray	
}

function Get-AllTables {	
    	
	$AllTables = @()	
    $TablesApi = $APIEndpoint + "subscriptions/$SubscriptionId/resourcegroups/$LogAnalyticsResourceGroup/providers/Microsoft.OperationalInsights/workspaces/$LogAnalyticsWorkspaceName/tables" + "?api-version=2022-09-01-privatepreview"								
	    		
    try {        
        $TablesApiResult = Invoke-RestMethod -Uri $TablesApi -Method "GET" -Headers $LaAPIHeaders           			
    } 
    catch {                    
        Write-Log -Message "Get-AllTables $($_)" -LogFileName $LogFileName -Severity Error		                
    }

    If ($TablesApiResult.StatusCode -ne 200) {
        $searchPattern = '(_RST|_SRCH|_EXT)'                
        foreach ($ta in $TablesApiResult.value) { 
            try {
                if($ta.name.Trim() -notmatch $searchPattern) {                    
                    $AllTables += [pscustomobject]@{
						TableName=$ta.name.Trim();
						IngestionPlan=$ta.properties.Plan.Trim();                                
                    }  
                }
            }
            catch {
                Write-Log -Message "Error adding $ta to collection" -LogFileName $LogFileName -Severity Error
            }
            	
        }
    }
	
    return $AllTables
}

function Update-SystemAssignedIdentity {

    $IdentityEndPoint = $APIEndpoint + "subscriptions/$SubscriptionId/resourceGroups/$LogAnalyticsResourceGroup/providers/microsoft.operationalinsights/workspaces/$LogAnalyticsWorkspaceName" + "?api-version=2022-10-01"
    $IdentityBody = @"
                    {
                        "location": "$LogAnalyticsLocation",
                        "identity": {
                            "type": "SystemAssigned"
                        },
                        "properties": {
                            "sku": {
                                "name": "pergb2018"
                            }
                        }
                    }
"@
    try {        
        Invoke-RestMethod -Uri $IdentityEndPoint -Method "PUT" -Headers $LaAPIHeaders -Body $IdentityBody
        Write-Log -Message "Successfully updated MSI" -LogFileName $LogFileName -Severity Information
    } 
    catch {        
        Write-Log -Message "An error occurred in updating Workspace to use system assigned MSI" -LogFileName $LogFileName -Severity Error            
        Write-Log -Message $($_.Exception.Response.StatusCode.value__) -LogFileName $LogFileName -Severity Error                            
        Write-Log -Message $($_.Exception.Response.StatusDescription) -LogFileName $LogFileName -Severity Error
    } 

}

function Create-ExternalTables {
	[CmdletBinding()]
    param (  
        [parameter(Mandatory = $true)] $StorageContainerClient,      
        [parameter(Mandatory = $true)] $SelectedBlobs,
        [parameter(Mandatory = $true)] $StgAccountName,
        [parameter(Mandatory = $true)] $StgContainerName
	)
    	
	foreach($SelectedBlob in $SelectedBlobs) {
        $source_blob_client = $StorageContainerClient.CloudBlobContainer.GetBlockBlobReference($SelectedBlob.Name)

        #download the blob as text into memory
        $download_file = $source_blob_client.DownloadText()
        $TableSchemaJson = FixJsonIndentation -jsonOutput $download_file        
        $ExternalTableName = "$($SelectedBlob.Name.subString(0, $SelectedBlob.Name.lastIndexOf('.')))_EXT"
        $TablesApi = $APIEndpoint + "subscriptions/$SubscriptionId/resourcegroups/$LogAnalyticsResourceGroup/providers/Microsoft.OperationalInsights/workspaces/$LogAnalyticsWorkspaceName/tables/$ExternalTableName" + "?api-version=2022-09-01-privatepreview"								
        $PartitionName = "DayBin"
        $SourceColumn = "TimeGenerated"
        $TransformCriteria = "bin1d"
        $PathFormat = "datetime_pattern('{yyyy}-{MM}-{dd}', $PartitionName)"

		$ExternalTableBody = @"
        {
            "properties": {
                "externalDefinition": { 
                    "sourceType": "StorageAccount",
                    "storageAccount": { 
                        "blobFolders": [ 
                            { 
                                "path": "https://$StgAccountName.blob.core.windows.net/$StgContainerName"  
                            }
                        ], 
                        "partitions": [   
                            { 
                                "name": "$PartitionName", 
                                "type": "datetime", 
                                "sourceColumn": "$SourceColumn", 
                                "transform": "$TransformCriteria"
                            } 
                        ], 
                        "pathFormat": "$PathFormat",
                        "dataFormat": "Json"
                    } 
                },				
                "schema": { 
                    "name": "$($ExternalTableName)", 
                    "columns": $TableSchemaJson
                }
            }
        }
"@
        try {        
            $ExternalTableApiResult = Invoke-WebRequest -Uri $TablesApi -Method "PUT" -Headers $LaAPIHeaders -Body $ExternalTableBody			
            Write-Log -Message "External Table $($ExternalTableName) Status $($ExternalTableApiResult.StatusCode)" -LogFileName $LogFileName -Severity Information
        } 
        catch {                    
            Write-Log -Message "Create-ExternalTables $($_)" -LogFileName $LogFileName -Severity Error		                
        }

    } #forloop closing
    return $ExternalTableApiResult
}

Function FixJsonIndentation ($jsonOutput) {
    Try {
        $currentIndent = 0
        $tabSize = 4
        $lines = $jsonOutput.Split([Environment]::NewLine)
        $newString = ""
        foreach ($line in $lines)
        {
            # skip empty line
            if ($line.Trim() -eq "") {
                continue
            }

            # if the line with ], or }, reduce indent
            if ($line -match "[\]\}]+\,?\s*$") {
                $currentIndent -= 1
            }

            # add the line with the right indent
            if ($newString -eq "") {
                $newString = $line
            } else {
                $spaces = ""
                $matchFirstChar = [regex]::Match($line, '[^\s]+')
                
                $totalSpaces = $currentIndent * $tabSize
                if ($totalSpaces -gt 0) {
                    $spaces = " " * $totalSpaces
                }
                
                $newString += [Environment]::NewLine + $spaces + $line.Substring($matchFirstChar.Index)
            }

            # if the line with { or [ increase indent
            if ($line -match "[\[\{]+\s*$") {
                $currentIndent += 1
            }
        }
        return $newString
    }
    catch {
        Write-Log -Message "Error occured in FixJsonIndentation :$($_)" -LogFileName $LogFileName -Severity Error
    }
}
function Get-TableSchema {
	[CmdletBinding()]
    param (        
        [parameter(Mandatory = $true)] $LATable
	)
	
	Write-Log -Message "Retrieving schema and mappings for $LATable" -LogFileName $LogFileName -Severity Information
    $query = $LATable + ' | getschema | project ColumnName, DataType'
	$output = (Invoke-AzOperationalInsightsQuery -WorkspaceId $LogAnalyticsWorkspaceId -Query $query).Results
	    
    $SchemaArray = New-Object -TypeName System.Collections.ArrayList
	foreach ($record in $output) {
		if ($record.DataType -eq 'System.DateTime') {
			$dataType = 'datetime'			
		} 
		else {
			$dataType = 'string'			
		}
		
        $KeyValuePair = [PSCustomObject] [ordered] @{
            "name" = $record.ColumnName
            "type" = $dataType
        }        
        $null = $SchemaArray.Add($KeyValuePair)
	}
    $TableSchemaJson = ConvertTo-Json $SchemaArray -depth 4
	
    return $TableSchemaJson
	
}
#endregion

#region DriverProgram
$AzModulesQuestion = "Do you want to update required Az Modules to latest version?"
$AzModulesQuestionChoices = New-Object Collections.ObjectModel.Collection[Management.Automation.Host.ChoiceDescription]
$AzModulesQuestionChoices.Add((New-Object Management.Automation.Host.ChoiceDescription -ArgumentList '&Yes'))
$AzModulesQuestionChoices.Add((New-Object Management.Automation.Host.ChoiceDescription -ArgumentList '&No'))

$AzModulesQuestionDecision = $Host.UI.PromptForChoice($title, $AzModulesQuestion, $AzModulesQuestionChoices, 1)

if ($AzModulesQuestionDecision -eq 0) {
    $UpdateAzModules = $true
}
else {
    $UpdateAzModules = $false
}

Get-RequiredModules("Az.Accounts")
Get-RequiredModules("Az.OperationalInsights")

$TimeStamp = Get-Date -Format yyyyMMdd_HHmmss 
$LogFileName = '{0}_{1}.csv' -f "ADLS_Search", $TimeStamp

# Check Powershell version, needs to be 5 or higher
if ($host.Version.Major -lt 5) {
    Write-Log "Supported PowerShell version for this script is 5 or above" -LogFileName $LogFileName -Severity Error    
    exit
}

#disconnect exiting connections and clearing contexts.
Write-Log "Clearing existing Azure connection" -LogFileName $LogFileName -Severity Information
    
$null = Disconnect-AzAccount -ContextName 'MyAzContext' -ErrorAction SilentlyContinue
    
Write-Log "Clearing existing Azure context `n" -LogFileName $LogFileName -Severity Information
    
get-azcontext -ListAvailable | ForEach-Object{$_ | remove-azcontext -Force -Verbose | Out-Null} #remove all connected content
    
Write-Log "Clearing of existing connection and context completed." -LogFileName $LogFileName -Severity Information
Try {
    #Connect to tenant with context name and save it to variable
    $MyContext = Connect-AzAccount -Tenant $TenantID -ContextName 'MyAzContext' -Force -ErrorAction Stop
        
    #Select subscription to build
    $CurrentSubscription = Get-AzSubscription -TenantId $TenantID | Where-Object {($_.state -eq 'enabled') } | Out-GridView -Title "Select Subscription to Use" -OutputMode Single      
}
catch {    
    Write-Log "Error When trying to connect to tenant : $($_)" -LogFileName $LogFileName -Severity Error
    exit    
}

$AzureAccessToken = (Get-AzAccessToken).Token            
$LaAPIHeaders = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
$LaAPIHeaders.Add("Content-Type", "application/json")
$LaAPIHeaders.Add("Authorization", "Bearer $AzureAccessToken")



$APIEndpoint = $MyContext.Context.Environment.ResourceManagerUrl

Try 
    {
        #Set context for subscription being built
        $null = Set-AzContext -Subscription $CurrentSubscription.id
        $SubscriptionId = $CurrentSubscription.id
        Write-Log "Working in Subscription: $($CurrentSubscription.Name)" -LogFileName $LogFileName -Severity Information

        $SelectedLAW = Get-AzOperationalInsightsWorkspace | Where-Object { $_.ProvisioningState -eq "Succeeded" } | Select-Object -Property Name, ResourceGroupName, Location, CustomerId | Out-GridView -Title "Select Log Analytics workspace" -OutputMode Single
        if($null -eq $SelectedLAW) {
            Write-Log "No Log Analytics workspace found..." -LogFileName $LogFileName -Severity Error 
        }
        else {
            Write-Log "Listing Log Analytics workspace" -LogFileName $LogFileName -Severity Information
                
            $LogAnalyticsWorkspaceName = $SelectedLAW.Name
            $LogAnalyticsWorkspaceId = $SelectedLAW.CustomerId
            $LogAnalyticsResourceGroup = $SelectedLAW.ResourceGroupName
            $LogAnalyticsLocation = $SelectedLAW.Location

            #region Update Workspace to Use System Assigned Identity

            $IdentityQuestion = "Do you want to update Workspace to Use System Assigned Identity for Log Analytics workspace: $($LogAnalyticsWorkspaceName)"
            $IdentityQuestionChoices = New-Object Collections.ObjectModel.Collection[Management.Automation.Host.ChoiceDescription]
            $IdentityQuestionChoices.Add((New-Object Management.Automation.Host.ChoiceDescription -ArgumentList '&Yes'))
            $IdentityQuestionChoices.Add((New-Object Management.Automation.Host.ChoiceDescription -ArgumentList '&No'))

            $IdentityQuestionDecision = $Host.UI.PromptForChoice($title, $IdentityQuestion, $IdentityQuestionChoices, 1)

            If ($IdentityQuestionDecision -eq 0) {
                $MSIStatus = Update-SystemAssignedIdentity
                If ($MSIStatus.StatusCode -eq 200) {
                    Write-Log -Message "Workspace updated to use system assigned MSI" -LogFileName $LogFileName -Severity Information
                } else {
                    Write-Log -Message "Error in updating Workspace to use system assigned MSI" -LogFileName $LogFileName -Severity Error
                }
            }

            #endregion
            #$SelectedTables = Get-LATables
            $StorageAccount = Get-AzResource -ResourceType 'Microsoft.Storage/storageAccounts'| Out-GridView -Title "Select ADLS Account" -OutputMode Single
            $StorageAccountKey = (Get-AzStorageAccountKey -ResourceGroupName $StorageAccount.ResourceGroupName -Name $StorageAccount.Name).Value[0]
            $StorageContext = New-AzStorageContext -StorageAccountName $StorageAccount.Name -StorageAccountKey $StorageAccountKey
            $StorageContainer = Get-AzStorageContainer -Context $StorageContext | Out-GridView -Title "Select Container" -OutputMode Single
            # Get all the blobs from the container
            $StorageContainerBlobs = Get-AzStorageBlob -Container $StorageContainer.Name -Context $StorageContext | Out-GridView -Title "Select Blob" -OutputMode Multiple

            #New-AzRoleAssignment -ObjectId $LogAnalyticsWorkspaceId -RoleDefinitionName "Storage Blob Data Reader" -ResourceGroupName $StorageAccount.ResourceGroupName -Scope $StorageAccount.ResourceId
            

            $ExternalTablesStatus = Create-ExternalTables -StorageContainerClient $StorageContainer -SelectedBlobs $StorageContainerBlobs -StgAccountName $StorageAccount.Name -StgContainer $StorageContainer.Name
                         

        } 	
    }
    catch [Exception]
    { 
        Write-Log -Message $_ -LogFileName $LogFileName -Severity Error                         		
    }
#endregion DriverProgram 