<#
.SYNOPSIS
    Creates Windows Sandbox configuration files
.DESCRIPTION
    Creates Windows Sandbox configuration files (.wsb's). Includes settings for the basic toggles, mapping directories, and running startup commands for installing third party software and system configuration.
.PARAMETER VGPUDisable
	Disable vGPU. Default: Enabled. Note: Enabling can potentially increase the attack surface of the sandbox.
.PARAMETER NetworkDisable
	Disable internett access. Default: Enabled. Note: Enabling can expose untrusted applications to the internal network.
.PARAMETER MapDirs
	Create the following directories and map them as shared, read-write both directions.
.PARAMETER MapDirsRO
	Create the following directories and map them as shared, read-only from within sandobx.
.PARAMETER AudioInputEnable
	Enable audio input. Default: Disabled. Note: There may be security implications of exposing host audio input to the container.
.PARAMETER VideoInputEnable
	Enable video input. Default: Disabled. Note: There may be security implications of exposing host video input to the container.
.PARAMETER ProtectedClientEnable
	Enable Protected Client, running the sandbox in AppContainer Isolation. Default: Disabled. Note: May restrict the user's ability to copy/paste files in and out of the sandbox.
.PARAMETER PrinterSharingEnable
	Enable printer redirection, letting the sandbox access the host printers. Default: Disabled.
.PARAMETER ClipboardSharingDisable
	Disable shared clipboard. Default: Enabled.
.PARAMETER MemoryMB
	The amount of memory to allocate to the sandbox in MB. Minimum 2048MB.
.PARAMETER NoBasicConfig
	Do not make basic config changes, like show file extensions.
.PARAMETER DontInstall7zip
	Do not install 7-zip. Default: Install.
.PARAMETER DontInstallNotepadPlusPlus
	Do not install Notepad++. Default: Install.
.PARAMETER SetupEdge
	Setup Edge with less annoying interface and more analysis-friendly devtools configuration. Default: Don't setup.
.PARAMETER InstallSysinternals
	Install SysInternals suite. Downloads, extracts, and sets EULA to accepted. Requires 7-zip to also be installed (which is default behaviour). Requires SysinternalsSuite.zip to be present in resources/. Default: Don't install.
.PARAMETER InstallPython
	Install Python. Requires python-<version>-amd64.zip to be present in resources/. Default: Don't install.
.PARAMETER InstallOletools
	Install oletools. Default: Don't install.
.PARAMETER InstallLibreoffice
	Install LibreOffice. Requires a LibreOffice MSI installer to be present in resources/. Default: Don't install.
.PARAMETER DontCleanupDownloads
	Do not cleanup Downloads dir. Default: Do cleanup.
.EXAMPLE
	New-SandboxTemplate.ps1 -ProtectedClientEnable -ClipboardSharingDisable -VGPUDisable -NetworkDisable
	# "Paranoid mode" for maximum security
.EXAMPLE
	New-SandboxTemplate.ps1 -AudioInputEnable -NoBasicConfig -DontInstall7zip -DontInstallNotepadPlusPlus -DontCleanupDownloads
	# Setting these flags creates what is essentially an empty config file, and an experience similar to running WSB without a config file
.EXAMPLE
	New-SandboxTemplate.ps1 -MapDirsRO a_dir,b_dir -MapDirs results
	# Create 2 mapped read-only folders: "a_dir" and "b_dir", as well as one folder named "results" which is writable both ways
#>
[CmdletBinding()]
Param(
	
	[Parameter(HelpMessage="Disable vGPU. Default: Enabled. Note: Enabling can potentially increase the attack surface of the sandbox.")]
	[Switch]$VGPUDisable,

	[Parameter(HelpMessage="Disable internett access. Default: Enabled. Note: Enabling can expose untrusted applications to the internal network.")]
	[Switch]$NetworkDisable,

	[Parameter(HelpMessage="Create the following directories and map them as shared, read-write both directions.")]
	[String[]]$MapDirs,

	[Parameter(HelpMessage="Create the following directories and map them as shared, read-only from within sandobx.")]
	[String[]]$MapDirsRO,

	[Parameter(HelpMessage="Enable audio input. Default: Disabled. Note: There may be security implications of exposing host audio input to the container.")]
	[Switch]$AudioInputEnable,

	[Parameter(HelpMessage="Enable video input. Default: Disabled. Note: There may be security implications of exposing host video input to the container.")]
	[Switch]$VideoInputEnable,

	[Parameter(HelpMessage="Enable Protected Client, running the sandbox in AppContainer Isolation. Default: Disabled. Note: May restrict the user's ability to copy/paste files in and out of the sandbox.")]
	[Switch]$ProtectedClientEnable,

	[Parameter(HelpMessage="Enable printer redirection, letting the sandbox access the host printers. Default: Disabled. ")]
	[Switch]$PrinterSharingEnable,

	[Parameter(HelpMessage="Disable shared clipboard. Default: Enabled.")]
	[Switch]$ClipboardSharingDisable,

	[Parameter(HelpMessage="The amount of memory to allocate to the sandbox in MB. Minimum 2048MB.")]
	[Int]$MemoryMB = 2048,

	[Parameter(HelpMessage="Do not make basic config changes, like show file extensions.")]
	[Switch]$NoBasicConfig,

	[Parameter(HelpMessage="Do not install 7-zip. Default: Install.")]
	[Switch]$DontInstall7zip,

	[Parameter(HelpMessage="Do not install Notepad++. Default: Install.")]
	[Switch]$DontInstallNotepadPlusPlus,

	[Parameter(HelpMessage="Setup Edge with less annoying interface and more analysis-friendly devtools configuration. Default: Don't setup.")]
	[Switch]$SetupEdge,

	[Parameter(HelpMessage="Install SysInternals suite. Downloads, extracts, and sets EULA to accepted. Requires 7-zip to also be installed (which is default behaviour). Requires SysinternalsSuite.zip to be present in resources/. Default: Don't install.")]
	[Switch]$InstallSysinternals,

	[Parameter(HelpMessage="Install Python. Requires python-<version>-amd64.zip to be present in resources/. Default: Don't install.")]
	[Switch]$InstallPython,

	[Parameter(HelpMessage="Install oletools. Default: Don't install.")]
	[Switch]$InstallOletools,

	[Parameter(HelpMessage="Install LibreOffice. Requires a LibreOffice MSI installer to be present in resources/. Default: Don't install.")]
	[Switch]$InstallLibreoffice,

	[Parameter(HelpMessage="Do not cleanup Downloads dir. Default: Do cleanup.")]
	[Switch]$DontCleanupDownloads

)

BEGIN {

	# Verify that the allocated memory is within limits
	# We're setting the hard limit at the total physical memory, trusting the user to be reasonable
	$TotalRAM = [System.Math]::Round((Get-CimInstance Win32_ComputerSystem).TotalPhysicalMemory / 1MB)
	if ($MemoryMB -lt 2048 -or $MemoryMB -gt $TotalRAM) {
		throw "Memory allocation must be between 2048 MB and $TotalRAM MB."
	}

	$Template = "<Configuration>`n"
	$LogonCommands = @()
	$NeedExplorerRestart = $false

}

PROCESS {

	if ($VGPUDisable) {
		$Template += "`t<vGPU>Disable</vGPU>`n"
	}

	if ($NetworkDisable) {
		$Template += "`t<Networking>Disable</Networking>`n"
	}

	if (-not $AudioInputEnable) {
		$Template += "`t<AudioInput>Disable</AudioInput>`n"
	}

	if (-not $VideoInputEnable) {
		$Template += "`t<VideoInput>Disable</VideoInput>`n"
	}

	if ($ProtectedClientEnable) {
		$Template += "`t<ProtectedClient>Enable</ProtectedClient>`n"
	}

	if ($PrinterSharingEnable) {
		$Template += "`t<PrinterRedirection>Enable</PrinterRedirection>`n"
	}

	if ($ClipboardSharingDisable) {
		$Template += "`t<ClipboardRedirection>Disable</ClipboardRedirection>`n"
	}

	if ($MemoryMB -ne 2048) {
		$Template += "`t<MemoryInMB>$MemoryMB</MemoryInMB>`n"
	}

	if (-not $DontInstall7zip -or -not $DontInstallNotepadPlusPlus -or $SetupEdge -or $InstallSysinternals -or $InstallPython -or $InstallLibreoffice) {
		$MapDirsRO += "RESOURCES_INSTALLERS"
	}

	$HasMappedFolders = $false
	if ($MapDirs) {
		if (-not $HasMappedFolders) {
			$Template += "`t<MappedFolders>`n"
			$HasMappedFolders = $true
		}
		$DirPathRoot = "$PSScriptRoot\SHARED\writable"
		foreach ($Dir in $MapDirs) {
			$DirPath = "$DirPathRoot\$Dir"
			if (-not (Test-Path -Path $DirPath -PathType Container)) {
				New-Item -Path $DirPathRoot -Name $Dir -ItemType Directory | Out-Null
			}
			$Template += "`t`t<MappedFolder>`n"
			$Template += "`t`t`t<HostFolder>$DirPath</HostFolder>`n"
			$Template += "`t`t</MappedFolder>`n"
		}
	}
	if ($MapDirsRO) {
		if (-not $HasMappedFolders) {
			$Template += "`t<MappedFolders>`n"
			$HasMappedFolders = $true
		}
		$DirPathRoot = "$PSScriptRoot\SHARED\read-only"
		foreach ($DirRO in $MapDirsRO) {
			if ($DirRO -ne "RESOURCES_INSTALLERS") {
				$DirPath = "$DirPathRoot\$DirRO"
				if (-not (Test-Path -Path $DirPath -PathType Container)) {
					New-Item -Path $DirPathRoot -Name $DirRO -ItemType Directory | Out-Null
				}
				$Template += "`t`t<MappedFolder>`n"
				$Template += "`t`t`t<HostFolder>$DirPath</HostFolder>`n"
				$Template += "`t`t`t<ReadOnly>true</ReadOnly>`n"
				$Template += "`t`t</MappedFolder>`n"
			}
			else {
				$Template += "`t`t<MappedFolder>`n"
				$Template += "`t`t`t<HostFolder>$PSScriptRoot\resources</HostFolder>`n"
				$Template += "`t`t`t<SandboxFolder>C:\Users\WDAGUtilityAccount\AppData\Local\Temp\resources_installers</SandboxFolder>`n"
				$Template += "`t`t`t<ReadOnly>true</ReadOnly>`n"
				$Template += "`t`t</MappedFolder>`n"
			}
		}
	}
	if ($HasMappedFolders) {
		$Template += "`t</MappedFolders>`n"
	}



	if (-not $NoBasicConfig) {
		$ConfigFileextensionsCommand = {
			Set-ItemProperty -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced' -Name 'HideFileExt' -Value 0 -Type DWord -Force
			Write-Output "[$(Get-Date)] Un-hiding file extensions" | Out-File -FilePath "$HOME\Desktop\install_log.txt" -Append
		}
		$ConfigLaunchtocomputerCommand = {
			Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "LaunchTo" -Value 1 -Type DWord -Force
			Write-Output "[$(Get-Date)] Set launch-to my computer" | Out-File -FilePath "$HOME\Desktop\install_log.txt" -Append
		}
		$NeedExplorerRestart = $true
		$LogonCommands += "`t`t<Command>powershell.exe -ExecutionPolicy Bypass -EncodedCommand " + [System.Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($ConfigFileextensionsCommand.ToString())) + "</Command>`n"
		$LogonCommands += "`t`t<Command>powershell.exe -ExecutionPolicy Bypass -EncodedCommand " + [System.Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($ConfigLaunchtocomputerCommand.ToString())) + "</Command>`n"
	}



	### =======================================================================
	### Installers ------------------------------------------------------------
	### =======================================================================

	if (-not $DontInstall7zip) {
		if ((Get-Item "$PSScriptRoot\resources\7z*-x64.exe").Length -lt 1) {
			throw "7-zip installer not found in resources folder. Please download (the default x64 one): https://www.7-zip.org/"
		}
		$7zipCommand = {
			$7zInstaller = (Get-Item "$HOME\AppData\Local\Temp\resources_installers\7z*-x64.exe")[0]
			& $7zInstaller.FullName /S /D="C:\Program Files\7-Zip"
			Write-Output "[$(Get-Date)] Installed 7-zip" | Out-File -FilePath "$HOME\Desktop\install_log.txt" -Append
			cmd /c assoc .zip="svnzzip"
			cmd /c  --% ftype svnzzip="C:\Program Files\7-Zip\7zFM.exe" "%1"
			Write-Output "[$(Get-Date)] Associated .zip with 7-zip" | Out-File -FilePath "$HOME\Desktop\install_log.txt" -Append
			cmd /c assoc .7z="svnzsvnz"
			cmd /c  --% ftype svnzsvnz="C:\Program Files\7-Zip\7zFM.exe" "%1"
			Write-Output "[$(Get-Date)] Associated .7z with 7-zip" | Out-File -FilePath "$HOME\Desktop\install_log.txt" -Append
			cmd /c assoc .rar="svnzrar"
			cmd /c  --% ftype svnzrar="C:\Program Files\7-Zip\7zFM.exe" "%1"
			Write-Output "[$(Get-Date)] Associated .rar with 7-zip" | Out-File -FilePath "$HOME\Desktop\install_log.txt" -Append
			if (-not (Test-Path -Path "$HOME\AppData\Local\Temp\logoncommands_status" -PathType Container)) {
				New-Item -Path "$HOME\AppData\Local\Temp" -Name "logoncommands_status" -ItemType Directory | Out-Null
			}
			New-Item -Path "$HOME\AppData\Local\Temp\logoncommands_status" -Name "7zip.done" -ItemType File | Out-Null
		}
		$LogonCommands += "`t`t<Command>powershell.exe -ExecutionPolicy Bypass -EncodedCommand " + [System.Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($7zipCommand.ToString())) + "</Command>`n"
	}

	if (-not $DontInstallNotepadPlusPlus) {
		if ((Get-Item "$PSScriptRoot\resources\npp.*.Installer.x64.exe").Length -lt 1) {
			throw "Notepad++ installer not found in resources folder. Please download (the default x64 one (npp.<version>.Installer.x64.exe)): https://github.com/notepad-plus-plus/notepad-plus-plus/releases/latest"
		}
		$NPPCommand = {
			$NppInstaller = (Get-Item "$HOME\AppData\Local\Temp\resources_installers\npp.*.Installer.x64.exe")[0]
			& $NppInstaller.FullName /S
			Write-Output "[$(Get-Date)] Installed Notepad++" | Out-File -FilePath "$HOME\Desktop\install_log.txt" -Append
			cmd /c assoc .txt="npptxt"
			cmd /c  --% ftype npptxt="C:\Program Files\Notepad++\notepad++.exe" "%1"
			Write-Output "[$(Get-Date)] Associated .txt with Notepad++" | Out-File -FilePath "$HOME\Desktop\install_log.txt" -Append
			if (-not (Test-Path -Path "$HOME\AppData\Local\Temp\logoncommands_status" -PathType Container)) {
				New-Item -Path "$HOME\AppData\Local\Temp" -Name "logoncommands_status" -ItemType Directory | Out-Null
			}
			New-Item -Path "$HOME\AppData\Local\Temp\logoncommands_status" -Name "npp.done" -ItemType File | Out-Null
		}
		$LogonCommands += "`t`t<Command>powershell.exe -ExecutionPolicy Bypass -EncodedCommand " + [System.Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($NPPCommand.ToString())) + "</Command>`n"
	}

	if ($SetupEdge) {
		$SetupEdgeCommand = {
			$NRetries = 0
			$MaxRetries = 5
			$DirDone = $false
			while (-not $DirDone -and $NRetries -le $MaxRetries) {
				if (-not (Test-Path -Path "$HOME\AppData\Local\Temp\resources_installers" -PathType Container)) {
					$NRetries += 1
					Start-Sleep -Seconds 1
					continue
				}
				else {
					$DirDone = $true
					break
				}
			}
			if ($DirDone) {
				Remove-Item "$HOME\AppData\Local\Microsoft\Edge\User Data\Default\Preferences"
				Copy-Item "$HOME\AppData\Local\Temp\resources_installers\custom_Preferences.json" "$HOME\AppData\Local\Microsoft\Edge\User Data\Default\Preferences"
				Write-Output "[$(Get-Date)] Updated Edge preferences" | Out-File -FilePath "$HOME\Desktop\install_log.txt" -Append
				if (-not (Test-Path -Path "$HOME\AppData\Local\Temp\logoncommands_status" -PathType Container)) {
					New-Item -Path "$HOME\AppData\Local\Temp" -Name "logoncommands_status" -ItemType Directory | Out-Null
				}
				New-Item -Path "$HOME\AppData\Local\Temp\logoncommands_status" -Name "edge.done" -ItemType File | Out-Null
			}
			else {
				Write-Output "[$(Get-Date)] Updating Edge preferences failed because shared dir was missing" | Out-File -FilePath "$HOME\Desktop\install_log.txt" -Append
			}
		}
		$LogonCommands += "`t`t<Command>powershell.exe -ExecutionPolicy Bypass -EncodedCommand " + [System.Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($SetupEdgeCommand.ToString())) + "</Command>`n"
	}

	if ($InstallSysinternals) {
		if ($DontInstall7zip) {
			throw "Installation of sysinternals requires installation of 7-zip to be enabled."
		}
		if ((Get-Item "$PSScriptRoot\resources\SysinternalsSuite.zip").Length -lt 1) {
			throw "SysinternalsSuite.zip not found in resources folder. Please download: https://download.sysinternals.com/files/SysinternalsSuite.zip"
		}
		$SysinternalsCommand = {
			if (-not (Test-Path -Path "$HOME\AppData\Local\Temp\logoncommands_status\7zip.done")) {
				Write-Output "[$(Get-Date)] Failed to install Python, 7-zip not installed as expected" | Out-File -FilePath "$HOME\Desktop\install_log.txt" -Append
			}
			else {
				$SysinternalsZip = Get-Item "$HOME\AppData\Local\Temp\resources_installers\SysinternalsSuite.zip"
				& 'C:\Program Files\7-Zip\7z.exe' x -aoa $SysinternalsZip.FullName -o"$HOME\Desktop\SysinternalsSuite"
				New-Item -Path "HKCU:\Software\Sysinternals" -Force
				New-ItemProperty -Path "HKCU:\Software\Sysinternals" -Name "EulaAccepted" -Value 1 -Force
				Write-Output "[$(Get-Date)] Installed SysInternals suite" | Out-File -FilePath "$HOME\Desktop\install_log.txt" -Append
				if (-not (Test-Path -Path "$HOME\AppData\Local\Temp\logoncommands_status" -PathType Container)) {
					New-Item -Path "$HOME\AppData\Local\Temp" -Name "logoncommands_status" -ItemType Directory | Out-Null
				}
				New-Item -Path "$HOME\AppData\Local\Temp\logoncommands_status" -Name "sysinternals.done" -ItemType File | Out-Null
			}
		}
		$LogonCommands += "`t`t<Command>powershell.exe -ExecutionPolicy Bypass -EncodedCommand " + [System.Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($SysinternalsCommand.ToString())) + "</Command>`n"
	}

	if ($InstallPython) {
		if ($DontInstall7zip) {
			throw "Installation of Python requires installation of 7-zip to be enabled."
		}
		if ((Get-Item "$PSScriptRoot\resources\python*.zip").Length -lt 1) {
			throw "Zipped Python files not found in resources folder. Please download one, look for python-<version>-amd64.zip: https://www.python.org/ftp/python/"
		}
		$InstallPythonCommand = {
			if (-not (Test-Path -Path "$HOME\AppData\Local\Temp\logoncommands_status\7zip.done")) {
				Write-Output "[$(Get-Date)] Failed to install Python, 7-zip not installed as expected" | Out-File -FilePath "$HOME\Desktop\install_log.txt" -Append
			}
			else {
				$PythonZip = (Get-Item "$HOME\AppData\Local\Temp\resources_installers\python*.zip")[0]
				& 'C:\Program Files\7-Zip\7z.exe' x -aoa $PythonZip.FullName -o"C:\Python"
				[System.Environment]::SetEnvironmentVariable("Path", $env:Path + ";C:\Python\;C:\Python\Scripts\", [System.EnvironmentVariableTarget]::Machine)
				Write-Output "[$(Get-Date)] Installed Python in C:\Python\, pip not callable directly, use 'python -m pip'" | Out-File -FilePath "$HOME\Desktop\install_log.txt" -Append
				if (-not (Test-Path -Path "$HOME\AppData\Local\Temp\logoncommands_status" -PathType Container)) {
					New-Item -Path "$HOME\AppData\Local\Temp" -Name "logoncommands_status" -ItemType Directory | Out-Null
				}
				New-Item -Path "$HOME\AppData\Local\Temp\logoncommands_status" -Name "python.done" -ItemType File | Out-Null
			}
		}
		$LogonCommands += "`t`t<Command>powershell.exe -ExecutionPolicy Bypass -EncodedCommand " + [System.Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($InstallPythonCommand.ToString())) + "</Command>`n"
	}

	if ($InstallOletools) {
		if (-not $InstallPython) {
			throw "Installation of oletools requires installation of Python to be enabled."
		}
		$InstallOletoolsCommand = {
			if (-not (Test-Path -Path "$HOME\AppData\Local\Temp\logoncommands_status\python.done")) {
				Write-Output "[$(Get-Date)] Failed to install oletools, Python not installed as expected" | Out-File -FilePath "$HOME\Desktop\install_log.txt" -Append
			}
			else {
				python -m pip install -U oletools[full]
				Write-Output "[$(Get-Date)] Installed oletools" | Out-File -FilePath "$HOME\Desktop\install_log.txt" -Append
				if (-not (Test-Path -Path "$HOME\AppData\Local\Temp\logoncommands_status" -PathType Container)) {
					New-Item -Path "$HOME\AppData\Local\Temp" -Name "logoncommands_status" -ItemType Directory | Out-Null
				}
				New-Item -Path "$HOME\AppData\Local\Temp\logoncommands_status" -Name "oletools.done" -ItemType File | Out-Null
			}
		}
		$LogonCommands += "`t`t<Command>powershell.exe -ExecutionPolicy Bypass -EncodedCommand " + [System.Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($InstallOletoolsCommand.ToString())) + "</Command>`n"
	}

	if ($InstallLibreoffice) {
		if ((Get-Item "$PSScriptRoot\resources\LibreOffice*.msi").Length -lt 1) {
			throw "LibreOffice MSI installer not found in resources folder. Please download one: https://www.libreoffice.org/download/download-libreoffice/"
		}
		$InstallLibreofficeCommand = {
			$LibreofficeInstaller = (Get-Item "$HOME\AppData\Local\Temp\resources_installers\LibreOffice*.msi")[0]
			msiexec.exe /i $LibreofficeInstaller.FullName /log "$HOME\AppData\Local\Temp\libreoffice_install.log" /passive
			Write-Output "[$(Get-Date)] Installed LibreOffice" | Out-File -FilePath "$HOME\Desktop\install_log.txt" -Append
			if (-not (Test-Path -Path "$HOME\AppData\Local\Temp\logoncommands_status" -PathType Container)) {
				New-Item -Path "$HOME\AppData\Local\Temp" -Name "logoncommands_status" -ItemType Directory | Out-Null
			}
			New-Item -Path "$HOME\AppData\Local\Temp\logoncommands_status" -Name "libreoffice.done" -ItemType File | Out-Null
		}
		$LogonCommands += "`t`t<Command>powershell.exe -ExecutionPolicy Bypass -EncodedCommand " + [System.Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($InstallLibreofficeCommand.ToString())) + "</Command>`n"
	}


	

	if ($NeedExplorerRestart) {
		$RestartExplorerCommand = {
			Stop-Process -Name 'Explorer' -Force
			Start-Sleep -Seconds 3
			try {
				Get-Process -Name 'Explorer' -ErrorAction Stop
			}
			catch {
				try {
					Invoke-Item 'explorer.exe'
				}
				catch {
					Throw $_
				}
			}
			Write-Output "[$(Get-Date)] Restarted explorer" | Out-File -FilePath "$HOME\Desktop\install_log.txt" -Append
		}
		$LogonCommands += "`t`t<Command>powershell.exe -ExecutionPolicy Bypass -EncodedCommand " + [System.Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($RestartExplorerCommand.ToString())) + "</Command>`n"
	}

	if (-not $DontCleanupDownloads) {
		$CleanupCommand = {
			if ((Get-ChildItem -Path "$HOME\Downloads\" | Measure-Object).Count -ne 0) {
				Remove-Item -Path "$HOME\Downloads\*"
				Write-Output "[$(Get-Date)] Cleaned up Downloads dir" | Out-File -FilePath "$HOME\Desktop\install_log.txt" -Append
			}
		}
		$LogonCommands += "`t`t<Command>powershell.exe -ExecutionPolicy Bypass -EncodedCommand " + [System.Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($CleanupCommand.ToString())) + "</Command>`n"
	}
	
	if ($LogonCommands.Count -gt 0) {
		$Template += "`t<LogonCommand>`n"
		$Template += $LogonCommands -join ""
		$Template += "`t</LogonCommand>`n"
	}

}

END {

	$Template += "</Configuration>"
	
	$OutPath = "$PSScriptRoot\Sandbox.wsb"

	Write-Output $Template | Out-File -FilePath $OutPath -Encoding UTF8
	Write-Host "Generated template: $OutPath" -ForegroundColor Green

}
