command = "powershell.exe -nologo -executionpolicy bypass -command C:\Warden\AlwaysOn\Warden_2_0_1\bin\warden.ps1"
set shell = CreateObject("WScript.Shell")
shell.Run command,0