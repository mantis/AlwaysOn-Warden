# Dump install script

schtasks /delete /tn AlwaysOnWarden /f
if(test-path "$env:ProgramData\Microsoft\Network\Connections\Pbk"){
        rm "$env:ProgramData\Microsoft\Network\Connections\Pbk" -Recurse -Force
}

start-sleep 1

if(-not(test-path C:\Warden\AlwaysOn\Warden_2_0_1)){

	mkdir C:\Warden -force
	mkdir C:\Warden\AlwaysOn -force
	mkdir C:\Warden\AlwaysOn\Warden_2_0_1 -force

}
New-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Services\SstpSvc\Parameters\ -Type DWORD -Name "NoCertRevocationCheck" -Value 1
Copy-Item "$PSScriptRoot\bin\" -Destination "C:\Warden\AlwaysOn\Warden_2_0_1" -recurse -force
schtasks /create /XML "$PSScriptroot\w.xml" /tn AlwaysOnWarden