## UCLan - AlwaysOn Warden                                                   ##
## Author: M Bradley                                                         ##

## Import Log Module #
#Import-Module "$PSScriptRoot\M-Logger.psm1" -Force

## Profile name ##
$USER_VPN_Profile_Name = "UCLan Network" -replace ' ', '%20'
$DEVICE_VPN_Profile_Name = "UCLan Network (Device)" -replace ' ', '%20'

## Parse XML data as string variable ##
$USER_VPN_Profile_XML = Get-Content "$PSScriptRoot\user_always_on_profile.xml" | Out-String
$DEVICE_VPN_Profile_XML = Get-Content "$PSScriptRoot\device_always_on_profile.xml" | Out-String

## Remove special chars from USER xml string ##
$USER_VPN_Profile_XML = $USER_VPN_Profile_XML -replace '<', '&lt;'
$USER_VPN_Profile_XML = $USER_VPN_Profile_XML -replace '>', '&gt;'
$USER_VPN_Profile_XML = $USER_VPN_Profile_XML -replace '"', '&quot;'

## Remove special chars from DEVICE xml string ##
$DEVICE_VPN_Profile_XML = $DEVICE_VPN_Profile_XML -replace '<', '&lt;'
$DEVICE_VPN_Profile_XML = $DEVICE_VPN_Profile_XML -replace '>', '&gt;'
$DEVICE_VPN_Profile_XML = $DEVICE_VPN_Profile_XML -replace '"', '&quot;'

## Global variables ##
$nodeCSPURI = './Vendor/MSFT/VPNv2'
$namespaceName = "root\cimv2\mdm\dmmap"
$className = "MDM_VPNv2_01"
$domain_name = "ntds.uclan.ac.uk"


# Hashtable of IP addresses or networks where tunnels will deactivate.  i.e '10.1.*' (for subnet) or 10.1.10.32 (for static)
$Excluded_Subnets = @{
}

## Check Functions ##

function Detect_Subnet($hash){
    $ip_ads = Get-NetIPAddress
    foreach($key in $hash.keys){
        if($($ip_ads | Where-Object {$_.IPAddress -like $hash[$key]})){
            return $true
        }
    }
    return $false
}

function Ping_Check($target){
    return $(Test-Connection $target -Count 1 -Quiet)
}

function Ethernet_Check(){
    return [bool]$(Get-NetAdapter | Where-Object {$_.Name -like "*Ethernet*" -and $_.Status -eq "Up"})
}

function Reset_AutoTriggers(){
    Set-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Services\RasMan\Config\ -Name AutoTriggerDisabledProfilesList -Value "" -Type MultiString
}

function Check_AutoTrigger_User($User_SID){
    $AutoTrigger_SID = Get-ItemPropertyValue -Path "HKLM:\SYSTEM\CurrentControlSet\Services\RasMan\Config" -Name "UserSID"
    return [bool]$($User_SID -eq $AutoTrigger_SID)
}

function User_Tunnel_Check($CIM, $WMI){
    return [bool]$($CIM.EnumerateInstances($namespaceName, $className,$WMI))
}

function Device_Tunnel_Check(){
    return [bool]$(Get-VpnConnection -AllUserConnection)
}

function Unauthenticated_Check(){
    return [bool]$(Get-NetConnectionProfile | Where-Object {$_.InterfaceAlias -like "*Unauthenticated*"})
}

## End Check Functions ##

## VPN Tunnel Functions ##

function Get_User_SID(){
    try{
        $LoggedOn_User = Get-WmiObject -Class Win32_ComputerSystem | Select-Object username
        $User_Object = New-Object System.Security.Principal.NTAccount($LoggedOn_User.username)
        return $($User_Object.Translate([System.Security.Principal.SecurityIdentifier])).Value
    }
    catch [Exception]{
        exit 1
    }
}

function Create_User_CIM($SID){
    $Object_Hash = @{}
    $cim_session = New-CimSession
    $options_array = New-Object Microsoft.Management.Infrastructure.Options.CimOperationOptions
    $options_array.SetCustomOption("PolicyPlatformContext_PrincipalContext_Type", "PolicyPlatform_UserContext", $false)
    $options_array.SetCustomOption("PolicyPlatformContext_PrincipalContext_Id", "$SID", $false)
    $Object_Hash.Add("CIM", $cim_session)
    $Object_Hash.Add("WMI", $options_array)
    return $Object_Hash
}

function Remove_User_Tunnel($CIM, $WMI){
    try{
        $CIM.EnumerateInstances($namespaceName,$className,$WMI) | % {
            if($_.InstanceID -eq $USER_VPN_Profile_Name){
                $CIM.DeleteInstance($namespaceName, $_, $WMI)
            }
        }
    }
    catch [Exception]{$null}
}

function Create_User_Tunnel($CIM, $WMI){
    try{
        $CIM_Instance = New-Object Microsoft.Management.Infrastructure.CimInstance $className, $namespaceName
        $Parent_ID = [Microsoft.Management.Infrastructure.CimProperty]::Create("ParentID", "$nodeCSPURI", "String", "Key")
        $Instance_ID = [Microsoft.Management.Infrastructure.CimProperty]::Create("InstanceID", "$USER_VPN_Profile_Name", "String", "Key")
        $Profile_XML = [Microsoft.Management.Infrastructure.CimProperty]::Create("ProfileXML", "$USER_VPN_Profile_XML", "String", "Property")
        $CIM_Instance.CimInstanceProperties.Add($Parent_ID)
        $CIM_Instance.CimInstanceProperties.Add($Instance_ID)
        $CIM_Instance.CimInstanceProperties.Add($Profile_XML)
        $CIM.CreateInstance($namespaceName, $CIM_Instance, $WMI)
    }
    catch [Exception]{$null}
}

function Remove_Device_Tunnel(){
    if(test-path "$env:ProgramData\Microsoft\Network\Connections\Pbk"){
        rm "$env:ProgramData\Microsoft\Network\Connections\Pbk" -Recurse -Force
    }   
}

function Create_Device_Tunnel(){
    $CIM = New-CimSession
    try{
        $CIM_Instance = New-Object Microsoft.Management.Infrastructure.CimInstance $className, $namespaceName
        $Parent_ID = [Microsoft.Management.Infrastructure.CimProperty]::Create("ParentID", "$nodeCSPURI", "String", "Key")
        $Instance_ID = [Microsoft.Management.Infrastructure.CimProperty]::Create("InstanceID", "$DEVICE_VPN_Profile_Name", "String", "Key")
        $Profile_XML = [Microsoft.Management.Infrastructure.CimProperty]::Create("ProfileXML", "$DEVICE_VPN_Profile_XML", "String", "Property")
        $CIM_Instance.CimInstanceProperties.Add($Parent_ID)
        $CIM_Instance.CimInstanceProperties.Add($Instance_ID)
        $CIM_Instance.CimInstanceProperties.Add($Profile_XML)
        $CIM.CreateInstance($namespaceName, $CIM_Instance)
    }
    catch [Exception]{$null}
}

## End VPN Tunnel Functions ##

function main(){
    
    # Reset the auto triggers regsitry entry
    Reset_AutoTriggers

    
    if($(Detect_Subnet $Excluded_Subnets) -and $(Ethernet_Check)){

        ## Destroy the tunnels! ##

        # Remove Device Tunnel
        while($(Device_Tunnel_Check)){
            Remove_Device_Tunnel
        }

	# Load User CIM
    	$USER_SID = $(Get_User_SID)
    	$USER_CIM = Create_User_CIM $USER_SID

        # Remove User Tunnel
        while($(User_Tunnel_Check $($USER_CIM["CIM"]) $($USER_CIM["WMI"]))){
            Remove_User_Tunnel $($USER_CIM["CIM"]) $($USER_CIM["WMI"])
        }

    }
    else{
        ## Create the tunnels! ##

        # Create the Device Tunnel
        while($(Device_Tunnel_Check) -eq $false){
            Create_Device_Tunnel
        }

	# Load User CIM
    	$USER_SID = $(Get_User_SID)
    	$USER_CIM = Create_User_CIM $USER_SID

        # Create the User Tunnel
        while($(User_Tunnel_Check $($USER_CIM["CIM"]) $($USER_CIM["WMI"])) -eq $false){
            Create_User_Tunnel $($USER_CIM["CIM"]) $($USER_CIM["WMI"])
        }

        # Recreate the User Tunnel for New Users
        while($(Check_AutoTrigger_User $USER_SID) -eq $false){
            Remove_User_Tunnel $($USER_CIM["CIM"]) $($USER_CIM["WMI"])
            Create_User_Tunnel $($USER_CIM["CIM"]) $($USER_CIM["WMI"])
        }

        # Unathenticated Check #

        if($(Unauthenticated_Check)){
            ipconfig /release
            ipconfig /renew
        }
        
    }

}

# Entry Point #
main