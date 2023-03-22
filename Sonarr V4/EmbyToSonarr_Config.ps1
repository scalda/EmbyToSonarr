<#=============================================================================
EmbyToSonaar V0.7.0 - Beta - 02/10/2018 #>
$Config_Version = "v0.7.0"
<#
This script stores user-defined variables for use by EmbyToSonarr.ps1.
Created by PenkethBoy 
Edited By Scalda For Sonarr V4
===============================================================================
Dependencies:
PowerShell v3.0+ 

-------------------------------------------------------------------------------
User-defined variables
-------------------------------------------------------------------------------
$logPath = the path you want the log file to save to. Defaults to the script's directory. (no trailing "\")
# If you change the path after a log has been generated the Retention options will only work with the new location.

$EmbyServerUrl = the IP address and Port of your Emby server (for the purpose of accessing the Emby server).
$Emby_User_Name = your Emby Admin user (for the purpose of accessing the Emby server).
Use an Emby Admin user Account that has access to all Libraries. A "limited" User can be used but only data which this user has access to will be processed.

$Emby_User_Pwd = your password for the above user (for the purpose of accessing the Emby server).

$SonarrHost = the IP address and port of your Sonaar server (for the purpose of refreshing its libraries)
$Sonarr_Api_Key = your Sonaar server's Api Key (for the purpose of refreshing its libraries).

$Emby_Watch_Period = The limiting period to search and compare Watched Episodes with Sonarr. Dont forget the minus!
$Log_Retension = How long you want to keep the log files for.

$User_Email = "<fullemalAddress>"  To be used to send error messages etc - assumes Gmail with lower security 
$User_Email_Pwd = "<password>" password of above email address

######
To include a series for the Sonarr update - add a tag to the Series in Emby of "Sonarr-Yes"
- case sensitive
######
-------------------------------------------------------------------------------#>
$Log_Path = "PathToLogsFolder" # $PSScriptRoot is the same place as the EmbyToSonarr.ps1 script file is located. (no trailing "\")

$EmbyServerUrl = "http://IPAddress:8096" # can be localhost or IP address e.g. "http://192.168.1.100:8096" include the quotes.
$Emby_User_Name = "UserName" # include the quotes.
$Emby_User_Pwd = "Password" # If you do not have a pwd then leave as ""

$SonarrHost = "http://IPAddress:8989" # localhost or 127.0.0.1 or if you have bound an IP to Sonarr you can use that e.g "http://192.168.1.101:8989"  include the quotes.
$Sonarr_Api_Key = "APIKey" #In .../Settings/General

$Emby_Watch_Period = "-7" # Period of days to search for Episodes that have been recently Played e.g -7 is over the last week
$Log_Retention = "-7" # Number of days of logs to keep i.e -7 means keep logs less than 7 days old and -0.5 also works :)

$User_Email = "email_address" 
$User_Email_Pwd = "password" 
