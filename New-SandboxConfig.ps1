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
.PARAMETER Help
	Show help
.EXAMPLE
	New-SandboxConfig.ps1 -VGPUDisable -NetworkDisable -ClipboardSharingDisable -MapDirsRO "files" -ProtectedClientEnable
	# "Paranoid mode" for maximum security, but including a read-only shared folder for information exchange.
.EXAMPLE
	New-SandboxConfig.ps1 -VideoInputEnable -AudioInputEnable -NoBasicConfig -DontInstall7zip -DontInstallNotepadPlusPlus
	# Setting these flags creates what is essentially an empty config file, and an experience similar to running WSB without a config file
.EXAMPLE
	New-SandboxConfig.ps1 -MapDirsRO a_dir,b_dir -MapDirs results
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

	[Parameter(HelpMessage="Show help")]
	[Switch]$Help

)








BEGIN {

	# If -Help is set, show help and do nothing else
	if ($Help) {
		Write-Host ""
		Write-Host "Calling without any parameters will create a config file with the following default settings:"
		Write-Host "  vGPU:                  " -ForegroundColor Cyan -NoNewline; Write-Host "Enabled" -ForegroundColor Green -NoNewline; Write-Host " (WSB default)"
		Write-Host "  Network:               " -ForegroundColor Cyan -NoNewline; Write-Host "Enabled" -ForegroundColor Green -NoNewline; Write-Host " (WSB default)"
		Write-Host "  Audio input:           " -ForegroundColor Cyan -NoNewline; Write-Host "Disabled" -ForegroundColor Red
		Write-Host "  Video input:           " -ForegroundColor Cyan -NoNewline; Write-Host "Disabled" -ForegroundColor Red
		Write-Host "  Printer redirection:   " -ForegroundColor Cyan -NoNewline; Write-Host "Disabled" -ForegroundColor Red -NoNewline; Write-Host " (WSB default)"
		Write-Host "  Clipboard redirection: " -ForegroundColor Cyan -NoNewline; Write-Host "Enabled" -ForegroundColor Green -NoNewline; Write-Host " (WSB default)"
		Write-Host "  Protected client:      " -ForegroundColor Cyan -NoNewline; Write-Host "Disabled" -ForegroundColor Red -NoNewline; Write-Host " (WSB default)"
		Write-Host "  Allocated memory:      " -ForegroundColor Cyan -NoNewline; Write-Host "2048 MB (WSB default)"
		Write-Host "All of these can be changed with dedicated command line parameters."
		Write-Host ""
		Write-Host "Calling without parameters will also include logon commands to do the following:"
		Write-Host "  * " -ForegroundColor Yellow -NoNewline; Write-Host "Show file extensions" -ForegroundColor Cyan -NoNewline; Write-Host " (basic config)"
		Write-Host "  * " -ForegroundColor Yellow -NoNewline; Write-Host "Show hidden files and directories" -ForegroundColor Cyan -NoNewline; Write-Host " (basic config)"
		Write-Host "  * " -ForegroundColor Yellow -NoNewline; Write-Host "Set Windows Explorer to launch to 'This PC' instead of Quick Access by default" -ForegroundColor Cyan -NoNewline; Write-Host " (basic config)"
		Write-Host "  * " -ForegroundColor Yellow -NoNewline; Write-Host "Pin the home directory to Windows Explorer Quick Access" -ForegroundColor Cyan -NoNewline; Write-Host " (basic config)"
		Write-Host "  * " -ForegroundColor Yellow -NoNewline; Write-Host "Install 7-zip" -ForegroundColor Cyan
		Write-Host "  * " -ForegroundColor Yellow -NoNewline; Write-Host "Install Notepad++" -ForegroundColor Cyan
		Write-Host "Note that many of the installations are depended on installers being downloaded into the resources\ directory. Tooltips will be given if this is required."
		Write-Host ""
		Write-Host "Calling without parameters will also create a RO mapped directory:"
		Write-Host "  * " -NoNewline; Write-Host "$PSScriptRoot\resources\" -ForegroundColor Cyan -NoNewline; Write-Host " mapped to " -NoNewline; Write-Host "C:\Users\WDAGUtilityAccount\AppData\Local\Temp\resources_installers\" -ForegroundColor Cyan -NoNewline; Write-Host " in the sandbox."
		Write-Host ""
		Write-Host "New shared directories can be created in the following ways:"
		Write-Host "-MapDirs `"dir 1`",`"dir_2`",`"dir3`"" -ForegroundColor Yellow
		Write-Host "  ^ Will create the supplied directories under " -NoNewline; Write-Host "$PSScriptRoot\SHARED\writable\" -ForegroundColor Cyan -NoNewline; Write-Host " and map them to the desktop of the sandbox"
		Write-Host "    (writable both ways)"
		Write-Host "-MapDirsRO `"dirA`",`"dir_b`",`"Dir-C`"" -ForegroundColor Yellow
		Write-Host "  ^ Will create the supplied directories under " -NoNewline; Write-Host "$PSScriptRoot\SHARED\read-only\" -ForegroundColor Cyan -NoNewline; Write-Host " and map them to the desktop of the sandbox"
		Write-Host "    (read-only from within the sandbox)"
		Write-Host ""
		Write-Host "These are the available parameters and what they do:"
		Write-Host "  -VGPUDisable                 " -ForegroundColor Yellow -NoNewline; Write-Host "Set vGPU to disabled."
		Write-Host "  -NetworkDisable              " -ForegroundColor Yellow -NoNewline; Write-Host "Disable network access."
		Write-Host "  -MapDirs                     " -ForegroundColor Yellow -NoNewline; Write-Host "See above."
		Write-Host "  -MapDirsRO                   " -ForegroundColor Yellow -NoNewline; Write-Host "See above."
		Write-Host "  -AudioInputEnable            " -ForegroundColor Yellow -NoNewline; Write-Host "Enable audio input."
		Write-Host "  -VideoInputEnable            " -ForegroundColor Yellow -NoNewline; Write-Host "Enable video input."
		Write-Host "  -ProtectedClientEnable       " -ForegroundColor Yellow -NoNewline; Write-Host "Will run the sandbox in AppContainer isolation, see paranoid config below."
		Write-Host "  -PrinterSharingEnable        " -ForegroundColor Yellow -NoNewline; Write-Host "Enable printer redirection, letting the sandbox access the host printers."
		Write-Host "  -ClipboardSharingDisable     " -ForegroundColor Yellow -NoNewline; Write-Host "Disable clipboard redirection, preventing basic copy/paste between host and sandbox."
		Write-Host "  -MemoryMB                    " -ForegroundColor Yellow -NoNewline; Write-Host "Takes an int value, the allocated memory in MB. Default and minimum: 2048"
		Write-Host "  -NoBasicConfig               " -ForegroundColor Yellow -NoNewline; Write-Host "Do not run the logon commands that are marked as 'basic config' above."
		Write-Host "  -DontInstall7zip             " -ForegroundColor Yellow -NoNewline; Write-Host "Do not install 7-zip, note that several other installations depends on 7-zip."
		Write-Host "  -DontInstallNotepadPlusPlus  " -ForegroundColor Yellow -NoNewline; Write-Host "Do not install Notepad++, note that notepad.exe is not available in WSB."
		Write-Host "  -SetupEdge                   " -ForegroundColor Yellow -NoNewline; Write-Host "Replace the default Edge preferences with a custom set that is less anoying and somewhat preconfigured."
		Write-Host "  -InstallSysinternals         " -ForegroundColor Yellow -NoNewline; Write-Host "Install SysInternals suite."
		Write-Host "  -InstallPython               " -ForegroundColor Yellow -NoNewline; Write-Host "Install Python (pip won't be in map, must run as 'python -m pip')"
		Write-Host "  -InstallOletools             " -ForegroundColor Yellow -NoNewline; Write-Host "Install oletools, requires Python to be installed."
		Write-Host "  -InstallLibreoffice          " -ForegroundColor Yellow -NoNewline; Write-Host "Install LibreOffice."
		Write-Host "  -Help                        " -ForegroundColor Yellow -NoNewline; Write-Host "This."
		Write-Host ""
		Write-Host "In order to create a config file for `"paranoid mode`" sandbox, use the following command:"
		Write-Host "  New-SandboxConfig.ps1" -ForegroundColor Yellow -NoNewline; Write-Host " -VGPUDisable -NetworkDisable -ClipboardSharingDisable -MapDirsRO " -ForegroundColor DarkGray -NoNewline; Write-Host "`"files`"" -ForegroundColor DarkCyan -NoNewline; Write-Host " -ProtectedClientEnable" -ForegroundColor DarkGray
		Write-Host "  Explanation:"
		Write-Host "   -VGPUDisable             " -ForegroundColor DarkGray -NoNewline; Write-Host "According to the docs, disabling vGPU reduces the attack surface."
		Write-Host "   -NetworkDisable          " -ForegroundColor DarkGray -NoNewline; Write-Host "Disables network access, preventing any communication with attacker infrastructure or local network assets."
		Write-Host "   -ClipboardSharingDisable " -ForegroundColor DarkGray -NoNewline; Write-Host "Disables clipboard sharing, preventing clipboard snooping or tampering."
		write-host "   -MapDirsRO" -ForegroundColor DarkGray -NoNewline; Write-Host " `"files`"       " -ForegroundColor DarkCyan -NoNewline; Write-Host "Creates a shared directory which the sandbox cannot write to, for information exchange in place of copy-paste."
		Write-Host "   -ProtectedClientEnable   " -ForegroundColor DarkGray -NoNewline; Write-Host "Further reduces the attack surface and preventing e.g. copy/paste of files between host and sandbox."
		Write-Host "  7-zip and Notepad++ will still be installed by default in this setup, and all the other installations can also be optionally enabled."
		Write-Host ""
		exit
	}

	# Verify that the allocated memory is within limits
	# We're setting the hard limit at the total physical memory, trusting the user to be reasonable
	$TotalRAM = [System.Math]::Round((Get-CimInstance Win32_ComputerSystem).TotalPhysicalMemory / 1MB)
	if ($MemoryMB -lt 2048 -or $MemoryMB -gt $TotalRAM) {
		throw "Memory allocation must be between 2048 MB and $TotalRAM MB."
	}

	$ConfigFile = "<Configuration>`n"
	$LogonCommands = @()
	$NeedExplorerRestart = $false

}








PROCESS {

	# ============ ### ================== ###=================================================
	# ============ ### WSB config options ###-------------------------------------------------
	# ============ ### ================== ###=================================================

	if ($VGPUDisable) {
		$ConfigFile += "`t<vGPU>Disable</vGPU>`n"
	}

	if ($NetworkDisable) {
		$ConfigFile += "`t<Networking>Disable</Networking>`n"
	}

	if (-not $AudioInputEnable) {
		$ConfigFile += "`t<AudioInput>Disable</AudioInput>`n"
	}

	if (-not $VideoInputEnable) {
		$ConfigFile += "`t<VideoInput>Disable</VideoInput>`n"
	}

	if ($ProtectedClientEnable) {
		$ConfigFile += "`t<ProtectedClient>Enable</ProtectedClient>`n"
	}

	if ($PrinterSharingEnable) {
		$ConfigFile += "`t<PrinterRedirection>Enable</PrinterRedirection>`n"
	}

	if ($ClipboardSharingDisable) {
		$ConfigFile += "`t<ClipboardRedirection>Disable</ClipboardRedirection>`n"
	}

	if ($MemoryMB -ne 2048) {
		$ConfigFile += "`t<MemoryInMB>$MemoryMB</MemoryInMB>`n"
	}

	if (-not $DontInstall7zip -or -not $DontInstallNotepadPlusPlus -or $SetupEdge -or $InstallSysinternals -or $InstallPython -or ($InstallOletools -and $NetworkDisable) -or $InstallLibreoffice) {
		$MapDirsRO += "RESOURCES_INSTALLERS"
	}





	# ============ ### ====================== ###=============================================
	# ============ ### Shared folder mappings ###---------------------------------------------
	# ============ ### ====================== ###=============================================

	$HasMappedFolders = $false
	if ($MapDirs) {
		if (-not $HasMappedFolders) {
			$ConfigFile += "`t<MappedFolders>`n"
			$HasMappedFolders = $true
		}
		$DirPathRoot = "$PSScriptRoot\SHARED\writable"
		foreach ($Dir in $MapDirs) {
			$DirPath = "$DirPathRoot\$Dir"
			if (-not (Test-Path -Path $DirPath -PathType Container)) {
				New-Item -Path $DirPathRoot -Name $Dir -ItemType Directory | Out-Null
			}
			$ConfigFile += "`t`t<MappedFolder>`n"
			$ConfigFile += "`t`t`t<HostFolder>$DirPath</HostFolder>`n"
			$ConfigFile += "`t`t</MappedFolder>`n"
		}
	}
	if ($MapDirsRO) {
		if (-not $HasMappedFolders) {
			$ConfigFile += "`t<MappedFolders>`n"
			$HasMappedFolders = $true
		}
		$DirPathRoot = "$PSScriptRoot\SHARED\read-only"
		foreach ($DirRO in $MapDirsRO) {
			if ($DirRO -ne "RESOURCES_INSTALLERS") {
				$DirPath = "$DirPathRoot\$DirRO"
				if (-not (Test-Path -Path $DirPath -PathType Container)) {
					New-Item -Path $DirPathRoot -Name $DirRO -ItemType Directory | Out-Null
				}
				$ConfigFile += "`t`t<MappedFolder>`n"
				$ConfigFile += "`t`t`t<HostFolder>$DirPath</HostFolder>`n"
				$ConfigFile += "`t`t`t<ReadOnly>true</ReadOnly>`n"
				$ConfigFile += "`t`t</MappedFolder>`n"
			}
			else {
				$ConfigFile += "`t`t<MappedFolder>`n"
				$ConfigFile += "`t`t`t<HostFolder>$PSScriptRoot\resources</HostFolder>`n"
				$ConfigFile += "`t`t`t<SandboxFolder>C:\Users\WDAGUtilityAccount\AppData\Local\Temp\resources_installers</SandboxFolder>`n"
				$ConfigFile += "`t`t`t<ReadOnly>true</ReadOnly>`n"
				$ConfigFile += "`t`t</MappedFolder>`n"
			}
		}
	}
	if ($HasMappedFolders) {
		$ConfigFile += "`t</MappedFolders>`n"
	}





	# ============ ### =================================== ###================================
	# ============ ### System configuration logon commands ###--------------------------------
	# ============ ### =================================== ###================================

	# Unless basic config is disabled, add logon commands:
	if (-not $NoBasicConfig) {
		# Disables the "Hide extensions for known file types" setting in Explorer
		$ConfigFileextensionsCommand = {
			Set-ItemProperty -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced' -Name 'HideFileExt' -Value 0 -Type DWord -Force
			Write-Output "[$(Get-Date)] Un-hiding file extensions" | Out-File -FilePath "$HOME\Desktop\install_log.txt" -Append
		}
		# Switch Explorer setting for hidden files and folders to "Show hidden files, folders and drivers", and disable the "Hide protected operating system files" setting
		$ConfigShowhiddenCommand = {
			Set-ItemProperty -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced' -Name 'Hidden' -Value 1 -Type DWord -Force
			Set-ItemProperty -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced' -Name 'ShowSuperHidden' -Value 1 -Type DWord -Force
			Write-Output "[$(Get-Date)] Un-hiding hidden folders extensions" | Out-File -FilePath "$HOME\Desktop\install_log.txt" -Append
		}
		# Set Explorer to launch to "This PC" instead of Quick Access
		$ConfigLaunchtocomputerCommand = {
			Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "LaunchTo" -Value 1 -Type DWord -Force
			Write-Output "[$(Get-Date)] Set launch-to my computer" | Out-File -FilePath "$HOME\Desktop\install_log.txt" -Append
		}
		# Pin the home directory of the default sandbox user to Windows Explorer Quick Access
		$ConfigPinnedHomedirCommand = {
			$QuickAccess = New-Object -ComObject Shell.Application
			$QuickAccess.Namespace("shell:::{679f85cb-0220-4080-b29b-5540cc05aab6}").Items() | Where-Object {$_.Path -eq "$HOME"}
			$QuickAccess.Namespace("$HOME").Self.InvokeVerb("pintohome")
			Write-Output "[$(Get-Date)] Pinned home directory in Explorer" | Out-File -FilePath "$HOME\Desktop\install_log.txt" -Append
		}
		$NeedExplorerRestart = $true
		$LogonCommands += "`t`t<Command>powershell.exe -ExecutionPolicy Bypass -EncodedCommand " + [System.Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($ConfigFileextensionsCommand.ToString())) + "</Command>`n"
		$LogonCommands += "`t`t<Command>powershell.exe -ExecutionPolicy Bypass -EncodedCommand " + [System.Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($ConfigShowhiddenCommand.ToString())) + "</Command>`n"
		$LogonCommands += "`t`t<Command>powershell.exe -ExecutionPolicy Bypass -EncodedCommand " + [System.Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($ConfigLaunchtocomputerCommand.ToString())) + "</Command>`n"
		$LogonCommands += "`t`t<Command>powershell.exe -ExecutionPolicy Bypass -EncodedCommand " + [System.Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($ConfigPinnedHomedirCommand.ToString())) + "</Command>`n"
	}





	# ============ ### ============================ ###=======================================
	# ============ ### Installations logon commands ###---------------------------------------
	# ============ ### ============================ ###=======================================

	# Unless installation of 7-zip is disabled, check if the installer is present, and add a logon command to install it and associate .zip, .7z and .rar with 7-zip.
	if (-not $DontInstall7zip) {
		if ((Get-Item "$PSScriptRoot\resources\7z*-x64.exe").Length -lt 1) {
			throw "7-zip installer not found in resources folder. Please download (the default x64 one): https://www.7-zip.org/"
		}
		$7zipCommand = {
			$7zInstaller = (Get-Item "$HOME\AppData\Local\Temp\resources_installers\7z*-x64.exe")[0]
			$P = Start-Process -FilePath $7zInstaller.FullName -ArgumentList "/S","/D=`"C:\Program Files\7-Zip`"" -PassThru
			Wait-Process -Id $P.Id
			if ($P.ExitCode -eq 0) {
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
			else {
				Write-Output "[$(Get-Date)] 7-zip installation failed" | Out-File -FilePath "$HOME\Desktop\install_log.txt" -Append
				throw "7-zip installation failed"
			}
		}
		$LogonCommands += "`t`t<Command>powershell.exe -ExecutionPolicy Bypass -EncodedCommand " + [System.Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($7zipCommand.ToString())) + "</Command>`n"
	}



	# Unless installation of Notepad++ is disabled, check if the installer is present, and add a logon command to install it and associate .txt files with Notepad++.
	if (-not $DontInstallNotepadPlusPlus) {
		if ((Get-Item "$PSScriptRoot\resources\npp.*.Installer.x64.exe").Length -lt 1) {
			throw "Notepad++ installer not found in resources folder. Please download (the default x64 one (npp.<version>.Installer.x64.exe)): https://github.com/notepad-plus-plus/notepad-plus-plus/releases/latest"
		}
		$NPPCommand = {
			$NppInstaller = (Get-Item "$HOME\AppData\Local\Temp\resources_installers\npp.*.Installer.x64.exe")[0]
			$P = Start-Process -FilePath $NppInstaller.FullName -ArgumentList "/S" -PassThru
			Wait-Process -Id $P.Id
			if ($P.ExitCode -eq 0) {
				Write-Output "[$(Get-Date)] Installed Notepad++" | Out-File -FilePath "$HOME\Desktop\install_log.txt" -Append
				cmd /c assoc .txt="npptxt"
				cmd /c  --% ftype npptxt="C:\Program Files\Notepad++\notepad++.exe" "%1"
				Write-Output "[$(Get-Date)] Associated .txt with Notepad++" | Out-File -FilePath "$HOME\Desktop\install_log.txt" -Append
				if (-not (Test-Path -Path "$HOME\AppData\Local\Temp\logoncommands_status" -PathType Container)) {
					New-Item -Path "$HOME\AppData\Local\Temp" -Name "logoncommands_status" -ItemType Directory | Out-Null
				}
				New-Item -Path "$HOME\AppData\Local\Temp\logoncommands_status" -Name "npp.done" -ItemType File | Out-Null
			}
			else {
				Write-Output "[$(Get-Date)] Notepad++ installation failed" | Out-File -FilePath "$HOME\Desktop\install_log.txt" -Append
				throw "Notepad++ installation failed"
			}
		}
		$LogonCommands += "`t`t<Command>powershell.exe -ExecutionPolicy Bypass -EncodedCommand " + [System.Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($NPPCommand.ToString())) + "</Command>`n"
	}



	# If Edge setup is enabled: Ensure custom Edge preferences JSON is present, add logon command to replace the default Edge preferences with the custom one.
	if ($SetupEdge) {
		$SetupEdgeCommand = {
			$PrevHash = (Get-FileHash -Path "$HOME\AppData\Local\Microsoft\Edge\User Data\Default\Preferences" -Algorithm SHA1).Hash
			Remove-Item "$HOME\AppData\Local\Microsoft\Edge\User Data\Default\Preferences"
			Copy-Item "$HOME\AppData\Local\Temp\resources_installers\custom_Preferences.json" "$HOME\AppData\Local\Microsoft\Edge\User Data\Default\Preferences"
			$NewHash = (Get-FileHash -Path "$HOME\AppData\Local\Microsoft\Edge\User Data\Default\Preferences" -Algorithm SHA1).Hash
			if ($NewHash -eq $PrevHash) {
				Write-Output "[$(Get-Date)] Failed to update Edge preferences" | Out-File -FilePath "$HOME\Desktop\install_log.txt" -Append
				throw "Failed to update Edge preferences"
			}
			Write-Output "[$(Get-Date)] Updated Edge preferences" | Out-File -FilePath "$HOME\Desktop\install_log.txt" -Append
			if (-not (Test-Path -Path "$HOME\AppData\Local\Temp\logoncommands_status" -PathType Container)) {
				New-Item -Path "$HOME\AppData\Local\Temp" -Name "logoncommands_status" -ItemType Directory | Out-Null
			}
			New-Item -Path "$HOME\AppData\Local\Temp\logoncommands_status" -Name "edge.done" -ItemType File | Out-Null
		}
		$LogonCommands += "`t`t<Command>powershell.exe -ExecutionPolicy Bypass -EncodedCommand " + [System.Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($SetupEdgeCommand.ToString())) + "</Command>`n"
	}



	# If SysInternals installation is enabled: Ensure SysInternals zip is present, add logon command to extract it and set EULA to accepted.
	if ($InstallSysinternals) {
		if ($DontInstall7zip) {
			throw "Installation of SysInternals requires installation of 7-zip to be enabled."
		}
		if ((Get-Item "$PSScriptRoot\resources\SysinternalsSuite.zip").Length -lt 1) {
			throw "SysinternalsSuite.zip not found in resources folder. Please download: https://download.sysinternals.com/files/SysinternalsSuite.zip"
		}
		$SysinternalsCommand = {
			if (-not (Test-Path -Path "$HOME\AppData\Local\Temp\logoncommands_status\7zip.done")) {
				Write-Output "[$(Get-Date)] Failed to install SysInternals, 7-zip not installed as expected" | Out-File -FilePath "$HOME\Desktop\install_log.txt" -Append
			}
			else {
				$SysinternalsZip = Get-Item "$HOME\AppData\Local\Temp\resources_installers\SysinternalsSuite.zip"
				& 'C:\Program Files\7-Zip\7z.exe' x -aoa $SysinternalsZip.FullName -o"$HOME\Desktop\SysinternalsSuite"
				if (-not (Test-Path -Path "$HOME\Desktop\SysinternalsSuite\procexp.exe")) {
					Write-Output "[$(Get-Date)] SysInternals suite installation failed" | Out-File -FilePath "$HOME\Desktop\install_log.txt" -Append
					throw "SysInternals suite installation failed"
				}
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



	# If Python installation is enabled: Ensure Python zip is present, add logon command to extract it and add to path.
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



	# If oletools installation is enabled: Decide whether or not to use pip from internet or from zip based on network availability, and if relevant ensure oletools zip is present,
	# add logon command to install oletools with pip, checking if Python is installed as first.
	if ($InstallOletools) {
		if (-not $InstallPython) {
			throw "Installation of oletools requires installation of Python to be enabled."
		}
		if ($NetworkDisable) {
			Write-Warning "oletools.zip is sometimes detected as malware by AV, due to the presence of test documents containing macros. If you are prevented from downloading the zip for this reason, you are unable to use oletools in combination with the -NetworkDisable option."
			if ((Get-Item "$PSScriptRoot\resources\oletools*.zip") -lt 1) {
				throw "oletools.zip not found in resources folder. Please download the latest stable: https://github.com/decalage2/oletools/releases/latest"
			}
			# Untested:
			$InstallOletoolsCommand = {
				if (-not (Test-Path -Path "$HOME\AppData\Local\Temp\logoncommands_status\python.done")) {
					Write-Output "[$(Get-Date)] Failed to install oletools, Python not installed as expected" | Out-File -FilePath "$HOME\Desktop\install_log.txt" -Append
				}
				else {
					$OletoolsZip = (Get-Item "$HOME\AppData\Local\Temp\resources_installers\oletools*.zip")[0]
					python -m pip install -U $OletoolsZip.FullName
					Write-Output "[$(Get-Date)] Installed oletools" | Out-File -FilePath "$HOME\Desktop\install_log.txt" -Append
					if (-not (Test-Path -Path "$HOME\AppData\Local\Temp\logoncommands_status" -PathType Container)) {
						New-Item -Path "$HOME\AppData\Local\Temp" -Name "logoncommands_status" -ItemType Directory | Out-Null
					}
					New-Item -Path "$HOME\AppData\Local\Temp\logoncommands_status" -Name "oletools.done" -ItemType File | Out-Null
				}
			}
		}
		else {
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
		}
		$LogonCommands += "`t`t<Command>powershell.exe -ExecutionPolicy Bypass -EncodedCommand " + [System.Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($InstallOletoolsCommand.ToString())) + "</Command>`n"
	}



	# If LibreOffice installation is enabled: Ensure LibreOffice installer is present, add logon command to run the installer
	if ($InstallLibreoffice) {
		if ((Get-Item "$PSScriptRoot\resources\LibreOffice*.msi").Length -lt 1) {
			throw "LibreOffice MSI installer not found in resources folder. Please download one: https://www.libreoffice.org/download/download-libreoffice/"
		}
		$InstallLibreofficeCommand = {
			$LibreofficeInstaller = (Get-Item "$HOME\AppData\Local\Temp\resources_installers\LibreOffice*.msi")[0]
			$P = Start-Process -FilePath "C:\Windows\System32\msiexec.exe" -ArgumentList "/i",$LibreofficeInstaller.FullName,"/log","$HOME\AppData\Local\Temp\libreoffice_install.log","/passive" -PassThru
			Wait-Process -Id $P.Id
			if ($P.ExitCode -eq 0) {
				Write-Output "[$(Get-Date)] Installed LibreOffice" | Out-File -FilePath "$HOME\Desktop\install_log.txt" -Append
				if (-not (Test-Path -Path "$HOME\AppData\Local\Temp\logoncommands_status" -PathType Container)) {
					New-Item -Path "$HOME\AppData\Local\Temp" -Name "logoncommands_status" -ItemType Directory | Out-Null
				}
				New-Item -Path "$HOME\AppData\Local\Temp\logoncommands_status" -Name "libreoffice.done" -ItemType File | Out-Null
			}
			else {
				Write-Output "[$(Get-Date)] LibreOffice installation failed" | Out-File -FilePath "$HOME\Desktop\install_log.txt" -Append
				throw "LibreOffice installation failed"
			}
		}
		$LogonCommands += "`t`t<Command>powershell.exe -ExecutionPolicy Bypass -EncodedCommand " + [System.Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($InstallLibreofficeCommand.ToString())) + "</Command>`n"
	}


	


	# If a logon command has been added which (in some cases) require Explorer to be restarted to take effect (e.g. associating a file extension), we restart Explorer.
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

	# Add the logon commands to the config file
	if ($LogonCommands.Count -gt 0) {
		$ConfigFile += "`t<LogonCommand>`n"
		$ConfigFile += $LogonCommands -join ""
		$ConfigFile += "`t</LogonCommand>`n"
	}

}








END {

	$ConfigFile += "</Configuration>"
	
	$OutPath = "$PSScriptRoot\Sandbox.wsb"

	Write-Output $ConfigFile | Out-File -FilePath $OutPath -Encoding UTF8
	Write-Host "Generated config file: $OutPath" -ForegroundColor Green

}
