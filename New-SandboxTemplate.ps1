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

	# The MS default is that audio input is disabled, so we only set a value if the switch is NOT set
	if (-not $AudioInputEnable) {
		$Template += "`t<AudioInput>Disable</AudioInput>`n"
	}

	if ($VideoInputEnable) {
		$Template += "`t<VideoInput>Enable</VideoInput>`n"
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
			$DirPath = "$DirPathRoot\$DirRO"
			if (-not (Test-Path -Path $DirPath -PathType Container)) {
				New-Item -Path $DirPathRoot -Name $DirRO -ItemType Directory | Out-Null
			}
			$Template += "`t`t<MappedFolder>`n"
			$Template += "`t`t`t<HostFolder>$DirPath</HostFolder>`n"
			$Template += "`t`t`t<ReadOnly>true</ReadOnly>`n"
			$Template += "`t`t</MappedFolder>`n"
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
		$7zipCommand = {
			$7zipBaseURL = "https://www.7-zip.org/"
			$Response = Invoke-WebRequest -Uri $7zipBaseURL -UseBasicParsing
			$HTML = $Response.Content
			$InstallerURL = if ($HTML -match '<a[^>]+href=["'']([^"''>]*-x64\.exe)["''][^>]*>') { $Href = $Matches[1]; $Href }
			$InstallerFilename = ($InstallerURL -split "/")[1]
			$InstallerURL = $7zipBaseURL + $InstallerURL
			Invoke-WebRequest -Uri $InstallerURL -OutFile (Join-Path "$HOME\Downloads" $InstallerFilename)
			Set-Location $HOME
			& .\Downloads\$InstallerFilename /S /D="C:\Program Files\7-Zip"
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
		}
		$LogonCommands += "`t`t<Command>powershell.exe -ExecutionPolicy Bypass -EncodedCommand " + [System.Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($7zipCommand.ToString())) + "</Command>`n"
	}

	if (-not $DontInstallNotepadPlusPlus) {
		$NPPCommand = {
			$Response = Invoke-WebRequest -Uri "https://github.com/notepad-plus-plus/notepad-plus-plus/releases/latest" -UseBasicParsing
			$Version = $Response.BaseResponse.ResponseUri.AbsoluteUri.Split("/")[-1]
			$InstallerFilename = "npp."
			$InstallerFilename += $Version.Replace("v", "")
			$InstallerFilename += ".Installer.x64.exe"
			$InstallerURL = "https://github.com/notepad-plus-plus/notepad-plus-plus/releases/download/$Version/$InstallerFilename"
			Invoke-WebRequest -Uri $InstallerURL -OutFile (Join-Path "$HOME\Downloads" $InstallerFilename)
			& "$HOME\Downloads\$InstallerFilename" /S
			Write-Output "[$(Get-Date)] Installed Notepad++" | Out-File -FilePath "$HOME\Desktop\install_log.txt" -Append
			cmd /c assoc .txt="npptxt"
			cmd /c  --% ftype npptxt="C:\Program Files\Notepad++\notepad++.exe" "%1"
			Write-Output "[$(Get-Date)] Associated .txt with Notepad++" | Out-File -FilePath "$HOME\Desktop\install_log.txt" -Append
		}
		$LogonCommands += "`t`t<Command>powershell.exe -ExecutionPolicy Bypass -EncodedCommand " + [System.Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($NPPCommand.ToString())) + "</Command>`n"
	}


	

	if ($NeedExplorerRestart) {
		$RestartExplorerCommand = {
			Stop-Process -Name 'Explorer' -Force
			Start-Sleep -Seconds 3
			try {
				$p = Get-Process -Name 'Explorer' -ErrorAction Stop
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
