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
        AUTHOR: Sreedhar Ande, Snow Kang
        LASTEDIT: 18 Jan 2023

    .EXAMPLE
        .Configure-ADLS.ps1 
#>

#region UserInputs

param(
    [parameter(Mandatory = $true, HelpMessage = "Enter Tenant Id")] [string] $TenantID,
	[parameter(Mandatory = $true, HelpMessage = "Enter Subscription Id")] [string] $SubscriptionId,
	[parameter(Mandatory = $true, HelpMessage = "Enter Log Analytics Workspace Name")] [string] $LogAnalyticsWorkspaceName,
	[parameter(Mandatory = $true, HelpMessage = "Enter Log Analytics Resource Group")] [string] $LogAnalyticsResourceGroup,	
	[Parameter(Mandatory = $true, HelpMessage = "Enter file path for External Table Schema")]
        [ValidateScript({
            if( -Not ($_ | Test-Path) ){
                throw "File or folder does not exist"
            }
            return $true
        })]
        [string]$ExternalTableSchemaFile,
	
	[parameter(Mandatory = $true, HelpMessage = "Enter Storage Account Name")] [string] $StorageAccountName,
	[parameter(Mandatory = $true, HelpMessage = "Enter Storage Account Resource Group Name")] [string] $StorageAccountResourceGroupName,
	[parameter(Mandatory = $true, HelpMessage = "Enter Storage Account Container Name")] [string] $StorageContainerName
	
	#[parameter(Mandatory = $true, HelpMessage = "Enter External Table Partition Name")] [string] $PartitionName,
	#[parameter(Mandatory = $true, HelpMessage = "Enter External Table Source Column Name")] [string] $SourceColumn,
	#[parameter(Mandatory = $true, HelpMessage = "Enter External Table Transform Criteria")] [string] $TransformCriteria,
	#[parameter(Mandatory = $true, HelpMessage = "Enter External Table Path Format")] [string] $PathFormat
        # parameter External table name
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

function Update-SystemAssignedIdentity {
    try {        
        $MSIStatus = Set-AzResource -ResourceId $workspaceClient.ResourceId -Properties @{identity = @{type="SystemAssigned"}} -Force
        Write-Log -Message "Successfully updated MSI" -LogFileName $LogFileName -Severity Information
        return $MSIStatus.Identity.principalId
    } 
    catch {        
        Write-Log -Message "An error occurred in updating Workspace to use system assigned MSI" -LogFileName $LogFileName -Severity Error        
    }    
}

function Create-ExternalTables {
	[CmdletBinding()]
    param (    
        [parameter(Mandatory = $true)] $StgAccountName,
        [parameter(Mandatory = $true)] $StgContainerName
	)
    if ((Get-Item $ExternalTableSchemaFile) -is [system.io.fileinfo]) {        
		$extn = [IO.Path]::GetExtension($ExternalTableSchemaFile)
		if ($extn -ieq ".csv") {
			$json_records = Get-Content $dataset | ConvertFrom-Csv | ConvertTo-Json
			$json_payload= $json_records | Convertfrom-json | ConvertTo-Json
		}
		else {
			$json_records = Get-Content $ExternalTableSchemaFile
			$json_payload= $json_records | Convertfrom-json | ConvertTo-Json
		}  	
	
        $TableSchemaJson = FixJsonIndentation -jsonOutput $json_payload        
        $ExternalTableName = "ZPADemo_EXT"
        $TablesApi = $APIEndpoint + "subscriptions/$SubscriptionId/resourcegroups/$LogAnalyticsResourceGroup/providers/Microsoft.OperationalInsights/workspaces/$LogAnalyticsWorkspaceName/tables/$ExternalTableName" + "?api-version=2022-09-01-privatepreview"								
        $PartitionName = "DayBin"
        $SourceColumn = "TimeGenerated"
        $TransformCriteria = "bin1d"
        $PathFormat = "datetime_pattern('{yyyy}-{MM}-{dd}',$PartitionName)"

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
            Invoke-WebRequest -Uri $TablesApi -Method "PUT" -Headers $LaAPIHeaders -Body $ExternalTableBody			
            Start-Sleep -Seconds 10
            
            $ExternalTableApiResult = Invoke-WebRequest -Uri $TablesApi -Method "GET" -Headers $LaAPIHeaders
        } 
        catch {                    
            Write-Log -Message "Create-ExternalTables $($_)" -LogFileName $LogFileName -Severity Error		                
        }

    } #If closing
    return $ExternalTableApiResult.StatusCode
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

Function Get-TableSchema ($filePath) {
	$all_datasets = @()
	foreach ($file in $filePath){
		if ((Get-Item $file) -is [system.io.fileinfo]){
			$all_datasets += (Resolve-Path -Path $file)
		}
		elseif ((Get-Item $file) -is [System.IO.DirectoryInfo]){
			$folderfiles = Get-ChildItem -Path $file -Recurse -Include *.json,*.csv
			$all_datasets += $folderfiles
		}
	}
    return $all_datasets
}

Function Grant-WorkspaceStorageBlobDataReaderRole ($LogAnalyticsIdentity) {
    try {               
        New-AzRoleAssignment -ObjectId $LogAnalyticsIdentity -RoleDefinitionName "Storage Blob Data Reader" -Scope $StorageAccountResourceId -Force
        Write-Log -Message "Successfully assigned Storage Blob Data Reader role to $LogAnalyticsWorkspaceName"
    }
    catch {
        Write-Log -Message "An error occurred in assigning Storage Blob Data Reader role to $LogAnalyticsWorkspaceName" -LogFileName $LogFileName -Severity Error
    }
}


#endregion

#region DriverProgram

# Check Powershell version, needs to be 5 or higher
if ($host.Version.Major -lt 5) {
    Write-Log "Supported PowerShell version for this script is 5 or above" -LogFileName $LogFileName -Severity Error    
    exit
}

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

 
$LogFileName = '{0}_{1}.csv' -f "ADLS_Search", $TimeStamp

#disconnect exiting connections and clearing contexts.
Write-Log "Clearing existing Azure connection" -LogFileName $LogFileName -Severity Information
    
$null = Disconnect-AzAccount -ContextName 'MyAzContext' -ErrorAction SilentlyContinue
    
Write-Log "Clearing existing Azure context `n" -LogFileName $LogFileName -Severity Information
    
get-azcontext -ListAvailable | ForEach-Object{$_ | remove-azcontext -Force -Verbose | Out-Null} #remove all connected content
    
Write-Log "Clearing of existing connection and context completed." -LogFileName $LogFileName -Severity Information

Try {
    #Connect to tenant with context name and save it to variable
    $MyContext = Connect-AzAccount -Tenant $TenantID -ContextName 'MyAzContext' -Force -ErrorAction Stop        
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

Try {
    $workspaceClient = Get-AzOperationalInsightsWorkspace -Name $LogAnalyticsWorkspaceName -ResourceGroupName $LogAnalyticsResourceGroup
    $LogAnalyticsWorkspaceId = $workspaceClient.CustomerId
    $LogAnalyticsLocation = $workspaceClient.Location
}
Catch {
    Write-Log -Message "Error in retreiving Log Analytics Workspace" -LogFileName $LogFileName -Severity Error
}

Try {
    $storageClient = Get-AzStorageAccount -ResourceGroupName $StorageAccountResourceGroupName -Name $StorageAccountName
    $StorageAccountResourceId = $storageClient.Id
}
Catch {
    Write-Log -Message "Error in retreiving Storage Account Context" -LogFileName $LogFileName -Severity Error
}

Try {      
    #region Update Workspace to Use System Assigned Identity
    $IdentityQuestion = "Do you want to update Workspace to Use System Assigned Identity for Log Analytics workspace: $($LogAnalyticsWorkspaceName)"
    $IdentityQuestionChoices = New-Object Collections.ObjectModel.Collection[Management.Automation.Host.ChoiceDescription]
    $IdentityQuestionChoices.Add((New-Object Management.Automation.Host.ChoiceDescription -ArgumentList '&Yes'))
    $IdentityQuestionChoices.Add((New-Object Management.Automation.Host.ChoiceDescription -ArgumentList '&No'))
    
    $IdentityQuestionDecision = $Host.UI.PromptForChoice($title, $IdentityQuestion, $IdentityQuestionChoices, 1)

    If ($IdentityQuestionDecision -eq 0) {
        $LogAnalyticsSystemAssigned = Update-SystemAssignedIdentity
    }
    #endregion

    #region Storage Account Blob Reader Permissions
    $StorageAcctPermQuestion = "Do you want to grant Workspace to Storage Blob Data Reader: $($LogAnalyticsWorkspaceName)"
    $StorageAcctPermQuestionChoices = New-Object Collections.ObjectModel.Collection[Management.Automation.Host.ChoiceDescription]
    $StorageAcctPermQuestionChoices.Add((New-Object Management.Automation.Host.ChoiceDescription -ArgumentList '&Yes'))
    $StorageAcctPermQuestionChoices.Add((New-Object Management.Automation.Host.ChoiceDescription -ArgumentList '&No'))
    
    $StorageAcctPermQuestionDecision = $Host.UI.PromptForChoice($title, $StorageAcctPermQuestion, $StorageAcctPermQuestionChoices, 1)

    If ($StorageAcctPermQuestionDecision -eq 0) {
        Grant-WorkspaceStorageBlobDataReaderRole -LogAnalyticsIdentity $LogAnalyticsSystemAssigned
    }

    #endregion

    $ExternalTablesStatus = Create-ExternalTables -StgAccountName $StorageAccountName -StgContainer $StorageContainerName
	
    if($ExternalTablesStatus -eq 200) {
        Write-Log -Message "External Table $ExternalTableName created successfully" -LogFileName $LogFileName -Severity Information
    } else {
        Write-Log -Message "Error occured in creating external table - $ExternalTableName" -LogFileName $LogFileName -Severity Information
    }

} 	
catch [Exception]
{ 
    Write-Log -Message $_ -LogFileName $LogFileName -Severity Error                         		
}
#endregion DriverProgram