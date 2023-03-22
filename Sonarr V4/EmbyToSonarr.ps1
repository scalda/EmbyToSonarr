#Requires -Version 3.0
<#=============================================================================
EmbyToSonarr V0.7.4 - 22/03/2023

To update the monitored status of Episodes in Sonaar that have been watched in EmbyServer
Created by PenkethBoy
Edited By Scalda For Sonarr V4
=============================================================================#>
#Script version information
$version = "v0.7.4"

# Script Global Variables
$log = ""
$lock = ""
$embyClientName = "PS-EmbyToSonarr"
$embyDeviceName = "PowerShell"
$embyDeviceId = "010"
$embyApplicationVersion = " - " +$Version
<#-----------------------------------------------------------------------------
Functions
-----------------------------------------------------------------------------#>
# Create log file for this session
Function Create_Log($Log_Path)
{
    $Log_Name = "EmbyToSonarr-"+[datetime]::Now.ToString('yyyy-MM-dd-HH-mm-ss')+".log"
    $Log_Temp = Join-Path "$Log_Path" "$Log_Name"
    $log_New = New-Item $Log_Temp -Force
    Return $log_New
}

# Logging and console output
Function Log($logString, $Silent=$False)
{
    if ($Silent) # dont write to Console
    {
        Write-Output $logString | Tee-Object -filepath $log -append | Out-Null # Out-Null is to stop strings being added to pipeline of function return object(s)
    }
    else
    {
        Write-Output $logString | Tee-Object -filepath $log -append | Out-Null # Out-Null is to stop strings being added to pipeline of function return object(s)
        Write-Host $logString # Write to screen console for user feedback
    }
}

# Prints the current script version header
Function PrintVersion
{
    Log -logString $("--------------------------------------------------------------------------------")
    Log -logString $("Powershell Version being used: $($PSVersionTable.PSVersion) (x64 = $([Environment]::Is64BitProcess))")
    Log -logString $("EmbyToSonaar $Version and EmbyToSonarr_Config $Config_Version")
    Log -logString $("--------------------------------------------------------------------------------")
}

# Create a backup of the Config ps1 file - JIC
Function Create_Backup_ConfigFile
{
    $Cfg_File = Join-Path "$PSScriptRoot" "EmbyToSonarr_Config.ps1"
    Copy-Item $Cfg_File "$Cfg_File.bak"
    Return $Cfg_File
}

# Create lock file (for the purpose of ensuring only one instance of this script is running)
Function Create_Lock_File
{
    $Lock_Path = "$PSScriptRoot"
    $Lock_File = "EmbyToSonarr.lock"
    $Lock = Join-Path "$Lock_Path" "$Lock_File"

    If (Test-Path -LiteralPath $lock)
    {
        $time = Get-Date -Format F
        Log -logString $("[$time] - ERROR: Lock file found, possibly EmbyToSonarr is already running in another instance.")
        Log -logString $("[$time] - If another instance is not running, then manually delete the lock file and try again.")
        Log -logString $("[$time] - Exiting Script")
        $temp = @()
        $temp = $("[$time] - ERROR: Lock file found, possibly EmbyToSonarr is already running in another instance." + "`r`n")
        $temp += $("[$time] - If another instance is not running, then manually delete the lock file and try again." + "`r`n")
        $temp += $("[$time] - Exiting Script")
        # Send-GEmail -Subject 'EmbyToSonarr - ERROR - Lock File Found' -Body $temp
        Exit
    }
    else
    {
    $tempFile = New-Item $Lock
    $time = Get-Date -Format F
    Log -logString $("[$time] - Lock file created.")
    Return $tempfile
    }
}

# Load variables from EmbyToSonarr_Config.ps1
Function Load_Config ($Cfg)
{
    If (Test-Path $Cfg)
    {
        . $Cfg # Load the config file into session
        # Read variables from _Config file into an array
        $Cfgs_Temp = New-Object PsObject -Property @{Config_Version = $Config_Version ; Log_Path = $Log_Path ; EmbyServerUrl = $EmbyServerUrl ; Emby_User_Name = $Emby_User_Name ; Emby_User_Pwd = $Emby_User_Pwd ; SonarrHost = $SonarrHost ; Sonarr_Api_Key = $Sonarr_Api_Key ; Emby_Watch_Period = $Emby_Watch_Period ; Log_Retention = $Log_Retention ; User_Email = $User_Email ; User_Email_Pwd = $User_Email_Pwd}
        
        If ($Cfgs_Temp.Config_Version -ne "v0.7.0")
        {
            Write-Host "ERROR: You appear to be using an incorrect version of the _Config file."
            Write-Host "Please re-downlaod and update you Config file"
            Write-Host "Waiting 5 seconds. Then exiting."
            Start-Sleep -Seconds 5
            Exit
        }
        If (-NOT (Test-Path -LiteralPath $Cfgs_Temp.Log_Path))
        {
            Write-Host "ERROR: Your Log_Path value in the _Config file appears to be invalid."
            Write-Host "Please update you Config file"
            Write-Host "Waiting 5 seconds. Then exiting."
            Start-Sleep -Seconds 5
            Exit
        }
        If (-NOT ($Cfgs_Temp.Log_Retention -match '[-]?[0-9]+$'))
        {
            Write-Host "ERROR: Your Log_Retention value in the _Config file appears to be invalid."
            Write-Host "Please update you Config file"
            Write-Host "Waiting 5 seconds. Then exiting."
            Start-Sleep -Seconds 5
            Exit
        }
        # Return the array of Variables read from _Config file
        Return $Cfgs_Temp
    }
    else
    {
        Write-Host "ERROR: Cannot find $Cfg. Make sure it's in the same directory as this script file."
        Write-Host "Waiting 5 seconds. Then exiting."
        Start-Sleep -Seconds 5
        Exit
    }
    
}

# Clear old log files
Function Clear_Old_Logs
{
    $time = Get-Date -Format F
    Log -logString $("[$time] - Clearing log files over "+$Log_Retention.Substring(1)+" day(s) old")
    $temp = Get-ChildItem -Path $Log_Path | Where-Object {($_.LastWriteTime -lt (Get-Date).AddDays($Log_Retention)) -and ($_.Extension -contains ".log") -and ($_.Name -like "EmbyToSonarr*")}
    $time = Get-Date -Format F
    Log -logString $("[$time] - Log Files found for Deletion: "+$temp.Count.ToString())
    Foreach($R in $Temp)
        {
        Try
            {
            Remove-Item -LiteralPath $R.FullName -Force -ErrorAction Stop
            $time = Get-Date -Format F
            Log -logString $("[$time] - Successfully Removed Log File: $R")
            }
        Catch
            {
            $time = Get-Date -Format F
            Log -logString $("[$time] - ERROR: $R could not be deleted. Full error below.")
            Log -logString $_
            Log -logString $("[$time] - Exiting Script")
            $temp = @()
            $temp = $("[$time] - ERROR: $R could not be deleted. Full error below." + "`r`n")
            $temp += $($_  + "`r`n")
            $temp += $("[$time] - Exiting Script")
            # Send-GEmail -Subject 'EmbyToSonarr - ERROR - Clearing Old Logs' -Body $temp
            Clean_Lock
            Exit
            }
        }
}

# Clean up  the Lock File
Function Clean_Lock
{
    Try
        {
        Remove-Item -LiteralPath $lock -Force -ErrorAction Stop
        $time = Get-Date -Format F
        Log -logString $("[$time] - Successfully Removed Lock File.")
        }
    Catch
        {
        $time = Get-Date -Format F
        Log -logString $("[$time] - ERROR: $lock could not be deleted. Full error below.")
        Log -logString $_
        Log -logString $("[$time] - Exiting Script")
        $temp = @()
        $temp = $("[$time] - ERROR: $lock could not be deleted. Full error below." + "`r`n")
        $temp += $($_ + "`r`n")
        $temp += $("[$time] - Exiting Script")
        # Send-GEmail -Subject 'EmbyToSonarr - ERROR - Clearing Lock File' -Body $temp
        Exit
        }    
}

# Check EmbyServer is running
Function Check_For_EmbyServer
{
    $time = Get-Date -Format F
    Log -logString $("[$time] - Pinging the EmbyServer Host address supplied in the _config file (with 10 second timeout).")
    # Check we can access Emby Server from _Config file info
    try
    {
        $MediaUrl = $EmbyServerUrl + "/system/ping"
        $PingResult = Invoke-WebRequest -TimeOutSec 10 -ErrorAction SilentlyContinue -ErrorVariable Trace -Uri $MediaUrl -Method Post
    }
    catch
    {
        $time = Get-Date -Format F
        Log -logString $("[$time] - ERROR: " + "$_")
    }
        
    if ($PingResult.StatusCode -eq 200)
    {
        $MediaUrl = $EmbyServerUrl + "/system/Info/Public"
        $InfoResult = Invoke-WebRequest -Uri $MediaUrl -Method Get
        $InfoResult = $InfoResult.Content | ConvertFrom-Json
        $time = Get-Date -Format F
        Log -logString $("[$time] - Success - EmbyServer: " + $InfoResult.ServerName +" Emby Server Version: "+ $InfoResult.Version +" Operating System: "+ $InfoResult.OperatingSystem)
        Return $InfoResult
    }
    else 
    {
        $time = Get-Date -Format F
        Log -logString $("[$time] - ERROR: Did not find EmbyServer at host address of $EmbyServerUrl.")
        Log -logString $("Trace Info: " + $Trace[0].InnerException.ToString() +"`r`n"+ $Trace[0].StackTrace.ToString()) -Silent $True
        Log -logString $("[$time] - Exiting Script")
        $temp = @()
        $temp = $("[$time] - ERROR: Did not find EmbyServer at host address of $EmbyServerUrl." + "`r`n")
        $temp += $("Trace Info: " + $Trace[0].InnerException.ToString() +"`r`n"+ $Trace[0].StackTrace.ToString() + "`r`n")
        $temp += $("[$time] - Exiting Script")
        # Send-GEmail -Subject 'EmbyToSonarr - ERROR - Checking for Emby Server' -Body $temp
        Clean_Lock
        Exit
    }
}

# Hash password
Function Get-StringHash([String]$textToHash,$HashName) 
{ 
    $Hasher = [System.Security.Cryptography.HashAlgorithm]::Create($HashName)
    $ToHash = [System.Text.Encoding]::UTF8.GetBytes($textToHash)
    $HashByteArray = $Hasher.ComputeHash($ToHash)
    foreach($byte in $HashByteArray) {$res += $byte.ToString("x2")}
    return $res; 
}

# Get Access Token for supplied User Details
function Get-EmbyAccessToken ($Username, $Pwd)
{
    $AuthUrl = $embyServerUrl + "/Users/AuthenticateByName?format=json"
    $PassSHA1 = Get-StringHash -textToHash $Pwd -HashName "SHA1"
    $PassMD5 = Get-StringHash -textToHash $Pwd -HashName "MD5"
    $Body = @{Username="$username";pw=$Pwd;password=$PassSHA1;passwordMd5=$PassMD5} | ConvertTo-Json
    $Header = @{"Authorization"="Emby Client=`"$embyClientName`", Device=`"$embyDeviceName`", DeviceId=`"$embyDeviceId`", Version=`"$embyApplicationVersion`""}
    $time = Get-Date -Format F
    Log -logString $("[$time] - Logging into the EmbyServer with User: $Username and supplied password.")
    # Check we can login with EmbyUser and EmbyPwd from _Config file info
    try
    {
        $LoginResult = Invoke-WebRequest -ErrorAction SilentlyContinue -ErrorVariable Trace -Uri $AuthUrl -Method POST -Body $Body -ContentType "application/json" -Headers $Header
    }
    Catch
    {
        log -LogString "$_" # basic error string
    }

    If ($LoginResult.StatusCode -eq 200)
    {
        $time = Get-Date -Format F
        $temp = $LoginResult.Content | ConvertFrom-Json
        Log -logString $("[$time] - Success - User Name: " + $temp.User.Name +" Server ID: "+ $temp.User.ServerId + ".")
        Return $LoginResult
    }
    else
    {
        $time = Get-Date -Format F
        Log -logString $("[$time] - ERROR: Could not login with User: $Username and supplied password.")
        Log -logString $("[$time] - ERROR Info: " + $Trace[0].ErrorRecord.Exception.Message + "`r`n" + "Trace Info: " + $Trace[0].InnerException.ToString() +"`r`n"+ $Trace[0].StackTrace.ToString()) -Silent $True
        Log -logString $("[$time] - Exiting Script.")
        $temp = @()
        $temp = $("[$time] - ERROR: Could not login with User: $Username and supplied password." + "`r`n")
        $temp += $("[$time] - ERROR Info: " + $Trace[0].ErrorRecord.Exception.Message + "`r`n" + "Trace Info: " + $Trace[0].InnerException.ToString() +"`r`n"+ $Trace[0].StackTrace.ToString() + "`r`n")
        $temp += $("[$time] - Exiting Script")
        # Send-GEmail -Subject 'EmbyToSonarr - ERROR - Emby Login Failure' -Body $temp
        Clean_Lock
        Exit
    }
}

# Check for a Sonarr process running (NZBDrone)
Function Check_For_Sonarr
{
    $time = Get-Date -Format F
    if (Get-Process Sonarr -ErrorAction SilentlyContinue)
    {
        Log -logString $("[$time] - Found Sonarr Process")
        try
        {
            $TestResult = Invoke-WebRequest -TimeOutSec 20 -ErrorAction SilentlyContinue -ErrorVariable Trace -Uri $GetSonarrSeries -Method Get
        }
        catch
        {
            $time = Get-Date -Format F
            Log -logString $("[$time] - ERROR: " + "$_")
        }
        if ($TestResult.Statuscode -eq 200)
        {
            $time = Get-Date -Format F
            Log -logString $("[$time] - Success - Sonarr Server Connection Test")
        }
        else
        {
            $time = Get-Date -Format F
            Log -logString $("[$time] - ERROR: Could not connect to SonarrServer at host address of $SonarrHost")
            Log -logString $("Trace Info: " + $Trace[0].InnerException.ToString() +"`r`n"+ $Trace[0].StackTrace.ToString()) -Silent $True
            Log -logString $("[$time] - Exiting")
            $temp = @()
            $temp = $("[$time] - ERROR: Could not connect to SonarrServer at host address of $SonarrHost" + "`r`n")
            $temp += $("Trace Info: " + $Trace[0].InnerException.ToString() +"`r`n"+ $Trace[0].StackTrace.ToString() + "`r`n")
            $temp += $("[$time] - Exiting")
            # Send-GEmail -Subject 'EmbyToSonarr - ERROR - Sonarr Get Process - Connection Test Failure' -Body $temp
            Clean_Lock
            Exit
        }
    }
    elseif (Get-Service Sonarr -ErrorAction SilentlyContinue)
    {
        Log -logString $("[$time] - Found Sonarr Service")
        try
        {
            $TestResult = Invoke-WebRequest -TimeOutSec 10 -ErrorAction SilentlyContinue -ErrorVariable Trace -Uri $GetSonarrSeries -Method Get
        }
        catch
        {
            $time = Get-Date -Format F
            Log -logString $("[$time] - ERROR: " + "$_")
        }
        if ($TestResult.Statuscode -eq 200)
        {
            $time = Get-Date -Format F
            Log -logString $("[$time] - Success - Sonarr Server Connection Test")
        }
        else
        {
            $time = Get-Date -Format F
            Log -logString $("[$time] - ERROR: Could not connect to SonarrServer at host address of $SonarrHost")
            Log -logString $("Trace Info: " + $Trace[0].InnerException.ToString() +"`r`n"+ $Trace[0].StackTrace.ToString()) -Silent $True
            Log -logString $("[$time] - Exiting")
            $temp = @()
            $temp = $("[$time] - ERROR: Could not connect to SonarrServer at host address of $SonarrHost" + "`r`n")
            $temp += $("Trace Info: " + $Trace[0].InnerException.ToString() +"`r`n"+ $Trace[0].StackTrace.ToString() + "`r`n")
            $temp += $("[$time] - Exiting")
            # Send-GEmail -Subject 'EmbyToSonarr - ERROR - Sonarr Get Service - Connection Test Failure' -Body $temp
            Clean_Lock
            Exit
        }
    }
    else 
    {
        Log -logString $("[$time] - ERROR: Did not find a Sonarr Process or Service.")
        Log -logString $("[$time] - Exiting Script")
        $temp = @()
        $temp = $("[$time] - ERROR: Did not find a Sonarr Process or Service." + "`r`n")
        $temp += $("[$time] - Exiting Script")
        # Send-GEmail -Subject 'EmbyToSonarr - ERROR - No Sonarr Process or Service Found' -Body $temp
        Clean_Lock
        Exit
    }
}

function Convert-UTCtoLocal
{
param([parameter(Mandatory=$true)][String] $UTCTime)

Return ([datetime]::SpecifyKind($UTCTime,[DateTimeKind]::Utc))
}

# For users without passwords
function Get-AllUsers ($User)
{
    $MediaUrl = $embyServerUrl + "/emby/users" + "?api_key=" + $User.AccessToken

    $Result = Invoke-WebRequest -Uri $MediaUrl -Method Get

    $Result = $Result.Content | ConvertFrom-Json

    $UsersInfo = New-Object System.Data.DataTable
    $UsersInfo.Columns.Add((New-Object System.Data.DataColumn "UserName",([string])))
    $UsersInfo.Columns.Add((New-Object System.Data.DataColumn "ID",([string])))

    For ($i=0; $i -lt $Result.Count; $i++)
    {
        If ($Result[$i].HasPassword -eq $False)
        {
            $time = Get-Date -Format F
            Log -logString $("[$time] - Found User: "+$Result[$i].Name + " who has no password and can be used.")
            $Row = $UsersInfo.NewRow()
            $Row."UserName" = $Result[$i].Name
            $Row."ID" = $Result[$i].ID
            $UsersInfo.Rows.Add($Row)
        }
        else
        {
            $time = Get-Date -Format F
            Log -logString $("[$time] - Found User: "+$Result[$i].Name + " who has a password and can't be used.")
        }
    }
    return $UsersInfo
}

# Send Email - Gmail
function Send-GEmail ($Subject, $Body)
{
    $smtpServer = "smtp.gmail.com" 
    $emailTo = $User_Email
    $emailFrom = $User_Email

    $smtpUsername = $User_Email  
    $smtpPassword = $User_Email_Pwd  

    $smtpClient = New-Object Net.Mail.smtpClient($smtpServer, 587)   
    $smtpClient.EnableSsl = $true   
    $smtpClient.Credentials = New-Object System.Net.NetworkCredential($smtpUsername, $smtpPassword);   
    $test = $smtpClient.Send($emailFrom, $emailTo, $Subject, $Body)
    $test
}
<#=============================================================================
Main Body

=============================================================================#>

    Clear-Host # Clear Console Screen

<#-----------------------------------------------------------------------------
Import user-defined variables from _Config file
-----------------------------------------------------------------------------#>

    # Initial Startup functions
    $Cfg_File = Create_Backup_ConfigFile

    # Load User-Variables from CFG file
    $temp = Load_Config $Cfg_File

    # Set Variables from Config file
    $Log_Path = $temp.Log_Path
    $EmbyServerUrl = $temp.EmbyServerUrl
    $Emby_User_Name = $temp.Emby_User_Name
    $Emby_User_Pwd = $temp.Emby_User_Pwd
    $SonarrHost = $temp.SonarrHost
    $Sonarr_Api_Key = $temp.Sonarr_Api_Key
    $Emby_Watch_Period = $temp.Emby_Watch_Period
    $Log_Retention = $temp.Log_Retention
    $Config_Version = $temp.Config_Version
    $User_Email = $temp.User_Email 
    $User_Email_Pwd = $temp.User_Email_Pwd

    # Sonarr Variables
    $getSonarrSeries    = "$SonarrHost/api/v3/series?&apikey="+$Sonarr_Api_Key
    $getSonarrEpisodes  = "$SonarrHost/api/v3/episode?SeriesId="
	$setSonarrMonitor	= "$SonarrHost/api/v3/episode/monitor?&apikey="+$Sonarr_Api_Key

<#-----------------------------------------------------------------------------
Static variables
-----------------------------------------------------------------------------#>
    # Create New log file
    $log = Create_Log $Log_Path

    #Create Lock File
    $lock = Create_Lock_file
    
    # Print Script Version to New Log file. 
    PrintVersion
<#-----------------------------------------------------------------------------
Check User supplied Emby server details
-----------------------------------------------------------------------------#>
    # Can we find  the EmbyServer Specified
    $ServerDetails = Check_For_EmbyServer
    # Can we find a Sonarr (as NZBDrone) process
    Check_For_Sonarr 
<#-----------------------------------------------------------------------------
Check User has supplied valid login details
-----------------------------------------------------------------------------#>
# User Authorisation - Try and login
    $authResult = Get-EmbyAccessToken -Username $Emby_User_Name -Pwd $Emby_User_Pwd
    $user = $authResult.Content | ConvertFrom-Json
    $UsersInfo = Get-AllUsers $User

<#-----------------------------------------------------------------------------
Begin Processing
-----------------------------------------------------------------------------#>
For ($k=0; $k -lt $UsersInfo.Rows.Count; $k++)
{
    $time = Get-Date -Format F
    $BeginTime = Get-Date
    Log -logString $("[$time] - Querying Emby for TV Series for USER: " +$UsersInfo[$k].UserName)
    $MediaUrl = $embyServerUrl + "/emby/Users/" + $UsersInfo[$k].ID +"/items?Fields=Tags&Recursive=true&SortBy=SortName&SortOrder=Ascending&IncludeItemTypes=Series" + "&api_key=" + $User.AccessToken
    $TVSeriesResult = Invoke-WebRequest -Uri $MediaUrl -Method Get
    $TVSeriesResult = $TVSeriesResult.Content | ConvertFrom-Json
    $EndTime = Get-Date
    $TimeTaken = $EndTime - $BeginTime
    $time = Get-Date -Format F
    Log -logString $("[$time] - TV Series Data - From Emby and Initial Processing completed in a time of: " + $TimeTaken)
    If ($TVSeriesResult.Items.Count -ne 0)
    {
        $MediaDataNo = New-Object System.Data.DataTable
        $MediaDataNo.Columns.Add((New-Object System.Data.DataColumn "SeriesName",([string])))
        $MediaDataNo.Columns.Add((New-Object System.Data.DataColumn "SeriesID",([string])))

        $MediaDataYes = New-Object System.Data.DataTable
        $MediaDataYes.Columns.Add((New-Object System.Data.DataColumn "SeriesName",([string])))
        $MediaDataYes.Columns.Add((New-Object System.Data.DataColumn "SeriesID",([string])))


        # Create List of TV Series with/without Sonarr-No Tag
        for ($i=0; $i -lt $TVSeriesResult.Items.Count; $i++)
        {
            $YesNo = $false
            $Tags = $TVSeriesResult.Items[$i].TagItems
            If ($Tags.Name -eq "Sonarr-No") 
            {
                $YesNo = $true
            }
            elseIf ($Tags.Count -gt 1)
            {
                For ($j=0; $j -lt $Tags.Count; $j++)
                {
                    If ($Tags[$j].Name -eq "Sonarr-No")
                    {
                        $YesNo = $true
                    }
                }
            }
            If ($YesNo) #Sonarr-No
            {
                $Row = $MediaDataNo.NewRow()
                $Row."SeriesName" = $TVSeriesResult.Items[$i].Name
                $Row."SeriesID" = $TVSeriesResult.Items[$i].ID
                $MediaDataNo.Rows.Add($Row)
            }
            else # No Sonarr-No Tag
            {
                $Row = $MediaDataYes.NewRow()
                $Row."SeriesName" = $TVSeriesResult.Items[$i].Name
                $Row."SeriesID" = $TVSeriesResult.Items[$i].ID
                $MediaDataYes.Rows.Add($Row)
            }
        }
    }
    Log -logString $("")
    Log -logString $("TV Series WITHOUT 'Sonarr-No' Tag")
    Log -logString $("=========================")
        For($i = 0; $i -lt $MediaDataYes.Rows.Count; $i++)
            {
                Log -logString $("Series Sonarr Tags -> No."+($i.ToString("###0")).PadLeft(4)+' '+($MediaDataYes.Rows[$i].SeriesName).ToString().PadRight(50))
            }

    Log -logString $("")
    Log -logString $("TV Series WITH 'Sonarr-No' Tag")
    Log -logString $("=========================")

        For($i = 0; $i -lt $MediaDataNo.Rows.Count; $i++)
            {
                Log -logString $("Series Sonarr Tags -> No."+($i.ToString("###0")).PadLeft(4)+' '+($MediaDataNo.Rows[$i].SeriesName).ToString().PadRight(50))
            }

    Log -logString $("")
    Log -logString $("User Defined Period Filter: $Emby_Watch_Period days")
    Log -logString $("")

    $time = Get-Date -Format F
    $BeginTime = Get-Date
    Log -logString $("[$time] - Querying Emby for All TV Episodes which have been played in last " + $Emby_Watch_Period.Substring(1) + " days.")
    $today = Get-Date
    $today = $today.AddDays($Emby_Watch_Period)
    # JIC &MinDateLastSavedForUser="+ $today.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
    $MediaUrl = $embyServerUrl + "/emby/Users/" + $UsersInfo[$k].Id +"/items?Recursive=true&SortBy=SeriesName,ParentIndexNumber,IndexNumber&SortOrder=Ascending&IncludeItemTypes=Episode&IsMissing=False&Filters=IsPlayed" + "&api_key=" + $User.AccessToken
    $TVEpisodeResult = Invoke-WebRequest -Uri $MediaUrl -Method Get
    $TVEpisodeResult = $TVEpisodeResult.Content | ConvertFrom-Json
    $EndTime = Get-Date
    $TimeTaken = $EndTime - $BeginTime
    $time = Get-Date -Format F
    Log -logString $("[$time] - TV Episode Data - From Emby and Initial Processing completed in a time of: " + $TimeTaken)
    Log -logString $("[$time] - Watched Episodes found in Emby: " + $TVEpisodeResult.Items.Count) 

    <# Temp printout episodes retured by Emby
    For ($i=0; $i -lt $TVEpisodeResult.Items.Count; $i++)
    {
        Log -logString $("[$time] - Watched TV Episode Returned by Emby: " + $TVEpisodeResult.Items[$i].SeriesName +", Season "+$TVEpisodeResult.Items[$i].ParentIndexNumber +", Eps "+ $TVEpisodeResult.Items[$i].IndexNumber+", Last Played "+$TVEpisodeResult.Items[$i].UserData.LastPlayedDate)
    }#>


    If ($TVEpisodeResult.Items.Count -ne 0)
    {
        $EpisodeData = New-Object System.Data.DataTable
        $EpisodeData.Columns.Add((New-Object System.Data.DataColumn "SeriesName",([string])))
        $EpisodeData.Columns.Add((New-Object System.Data.DataColumn "ParentIndexNumber",([string])))
        $EpisodeData.Columns.Add((New-Object System.Data.DataColumn "IndexNumber",([string])))
        $EpisodeData.Columns.Add((New-Object System.Data.DataColumn "Name",([string])))
        $EpisodeData.Columns.Add((New-Object System.Data.DataColumn "LastPlayedDate",([datetime])))
        $time = Get-Date -Format F
        Log -logString $("[$time] - Filtering Watched Episodes by Series Sonarr-No Tag and User Defined Period Filter")
        $BeginTime = Get-Date 
        For ($i=0; $i -lt $TVEpisodeResult.Items.Count; $i++)
        {
            For ($j=0; $j -lt $MediaDataNo.Rows.Count; $j++)
            {
                If ($TVEpisodeResult.Items[$i].SeriesName -eq $MediaDataNo.Rows[$j].SeriesName)
                {
                    # To Reduce Episode to Process
                    $TVEpisodeResult.Items[$i].id = "Ignore"
                }
            }
        }

        $today = Get-Date
        For ($i=0; $i -lt $TVEpisodeResult.Items.Count; $i++)
        {
            If ((Convert-UTCtoLocal $TVEpisodeResult.Items[$i].UserData.LastPlayedDate) -gt $today.AddDays($Emby_Watch_Period) -and ($TVEpisodeResult.Items[$i].id -ne "Ignore"))
            {
                $Row = $EpisodeData.NewRow()
                $Row."SeriesName" = $TVEpisodeResult.Items[$i].SeriesName
                $Row."ParentIndexNumber" = $TVEpisodeResult.Items[$i].ParentIndexNumber
                $Row."IndexNumber" = $TVEpisodeResult.Items[$i].IndexNumber
                $Row."Name" = $TVEpisodeResult.Items[$i].Name
                $Row."LastPlayedDate" = $TVEpisodeResult.Items[$i].UserData.LastPlayedDate
                $EpisodeData.Rows.Add($Row)
            }
        }
        $EndTime = Get-Date
        $TimeTaken = $EndTime - $BeginTime
        $time = Get-Date -Format F
        Log -logString $("[$time] - Watched Episode Filtering completed in a time of: " + $TimeTaken)
        Log -logString $("[$time] - Watched Emby Episode Records Selected for Updating in Sonarr: "+ $EpisodeData.Rows.Count)
        
        # Get Series Info from Sonarr
        If ($EpisodeData.Rows.Count -ne 0)
        {
            Log -logString $("[$time] - Querying Sonarr for Series Info.")
            $Sonarr_Series = Invoke-WebRequest -Uri $GetSonarrSeries -Method Get | ConvertFrom-json
            $time = Get-Date -Format F 
            Log -logString $("[$time] - Sonarr Series Records Found: "+$Sonarr_Series.Count)
        }
        If (($Sonarr_Series -ne 0) -and ($EpisodeData.Rows.Count -ne 0))
        {
            For($i = 0; $i -lt $EpisodeData.Rows.Count; $i++)
            {
                $time = Get-Date -Format F
                Log -logString $("[$time] - Episode to be Updated in Sonarr -> No."+$i.ToString("###0").PadLeft(4)+' '+$EpisodeData.Rows.Item($i).SeriesName.PadRight(30)+' ' +'Season ' +$EpisodeData.Rows.Item($i).ParentIndexNumber.PadRight(3)+' Episode '+$EpisodeData.Rows.Item($i).IndexNumber.PadRight(3)+' '+$EpisodeData.Rows.Item($i).Name.PadRight(50)+' Last Played Date: '+($EpisodeData.Rows.Item($i).LastPlayedDate).ToString("dddd, dd MMMM yyyy HH:mm:ss").PadLeft(33))


                # Get Sonarr Series ID
                $Sonarr_SeriesId = $Sonarr_Series | Where-Object -FilterScript {$_.Title -eq $EpisodeData.Rows.Item($i).SeriesName} | Select-Object -ExpandProperty id

                If ($null -ne $Sonarr_SeriesId)
                {
                    $time = Get-Date -Format F
                    Log -logString $("[$time] - Sonarr Series ID Found: "+$Sonarr_SeriesId)

                    # Get Sonarr Episode Id
                    $Sonarr_Episodes = Invoke-WebRequest -Uri $getSonarrEpisodes$Sonarr_SeriesId"&apikey="$Sonarr_Api_Key -Method Get | ConvertFrom-Json
                    $Sonarr_EpisodeId = $Sonarr_Episodes | Where-Object -FilterScript {$_.SeriesId -eq $Sonarr_SeriesId -and $_.SeasonNumber -eq $EpisodeData.Rows.Item($i).ParentIndexNumber -and $_.EpisodeNumber -eq $EpisodeData.Rows.Item($i).IndexNumber} | Select-Object -ExpandProperty id
                    $Sonarr_Monitored = $Sonarr_Episodes | Where-Object -FilterScript {$_.SeriesId -eq $Sonarr_SeriesId -and $_.SeasonNumber -eq $EpisodeData.Rows.Item($i).ParentIndexNumber -and $_.EpisodeNumber -eq $EpisodeData.Rows.Item($i).IndexNumber} | Select-Object -ExpandProperty monitored
            
					If (($null -ne $Sonarr_EpisodeId) -and ($Sonarr_Monitored -eq $true))
                    {
                        $time = Get-Date -Format F
                        Log -logString $("[$time] - Sonarr Episode ID Found: "+$Sonarr_EpisodeId)

                        # Update Sonarr monitored status's
                        # Invoke-RestMethod -Uri $setSonarrMonitor"&apikey="$Sonarr_Api_Key -ContentType 'application/json' -Method Put -Body {'episodeIds':$Sonarr_EpisodeId,'monitored': False}  | Out-Null
						Invoke-RestMethod -Uri $setSonarrMonitor"&apikey="$Sonarr_Api_Key -Method PUT -ContentType 'application/json' -Body '{"episodeIds": [$Sonarr_EpisodeId],"monitored": false}'
                        Log -logString $("[$time] - Sonarr Episode ID: "+$Sonarr_EpisodeId.ToString("#####0").PadRight(6)+" Monitored Status Updated to False.")
                    }
                    elseif ($null -ne $Sonarr_EpisodeId -and $Sonarr_Monitored -eq $false)
                    {
                        $time = Get-Date -Format F
                        Log -logString $("[$time] - Sonarr Episode ID: "+$Sonarr_EpisodeId+" Monitored Status Already: False - Skipping Update")
                    }
                    else 
                    {
                        $time = Get-Date -Format F
                        Log -logString $("[$time] - Episode not found in Sonarr! - Skipping update for this Episode")
                    }
                }
                else 
                {
                    $time = Get-Date -Format F
                    Log -logString $("[$time] - Series not found in Sonarr!- Skipping update for this Episode")
                }
            }
        }
        else 
        {
            $time = Get-Date -Format F
            Log -logString $("[$time] - No Sonarr Episode Records to process!- Closing")
        }
    }
    else 
    {
        $time = Get-Date -Format F
        Log -logString $("[$time] - No Emby Episode Records to process!- Closing")
    }
    $time = Get-Date -Format F
    Log -logString $("[$time] - Finished Querying Emby for TV Series for USER: " +$UsersInfo[$k].UserName)
}
<#=============================================================================
Tidy up and Delete lock file
=============================================================================#>
Clear_Old_Logs
Clean_Lock
$time = Get-Date -Format F
Log -logString $("[$time] - >>>>> Processing Finished <<<<<")
Exit