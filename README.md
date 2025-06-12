# Windows Sandbox config generator

## What, why and so on

### What does this thing do?

When executed, this script will create a Windows Sandbox configuration file, with configuration based on the run parameters.

### What is WSB (Windows Sandbox)?

See [Windows Sandbox | Microsoft Learn](https://learn.microsoft.com/en-us/windows/security/application-security/application-isolation/windows-sandbox/)

### What is Windows Sandbox configs?

If Windows Sandbox is enabled, XML files with the `.wsb` file extension can be used to launch Windows Sandbox with custom configuration, customized shared folders, and custom logon scripts.

See [Use and configure Windows Sandbox | Microsoft Learn](https://learn.microsoft.com/en-us/windows/security/application-security/application-isolation/windows-sandbox/windows-sandbox-configure-using-wsb-file)

### Why not just use a normal VM?

In many situations it's useful to have a clean and ready sandbox for testing apps, analyzing threats, etc.

By using Windows Sandbox it's quick to get a sandbox up in a ready state. Using a normal VM takes time, as the OS has to be installed and so on. VM snapshots can be used instead, but managing snapshots over time can get messy, and a VM usually requires more resources to run and store than WSB, which is fairly lightweight and requires no storage space at all by comparison.

When to use VM (with snapshots) *instead of* WSB:

* If you need to be able to set and restore from "backup points" *during* an analysis (you cannot save the state of WSB between sessions)
* If you need to have a sandbox with another OS than Windows

## Setup

### Setup WSB

Ensure WSB is enabled: [Install Windows Sandbox | Microsoft Learn](https://learn.microsoft.com/en-us/windows/security/application-security/application-isolation/windows-sandbox/windows-sandbox-install)

### Setup this project

Easiest is to clone or download the whole repo.

But you can also just download `New-SandboxConfig.ps1` as well as `custom_Preferences.json` (or create one after your own preferences) and manually setup the required directory structure:

```
📂 (script root)
 ├─ 📂 resources
 │   └─ 📄 custom_Preferences.json
 ├─ 📂 SHARED
 │   ├─ 📂 read-only
 │   └─ 📂 writable
 └─ 📄 New-SandboxConfig.ps1
```

In order to install various things using the logon scripts, zip archives and installers will have to be downloaded and placed into `resources/` before running the script. The script will check if these are present, and let you know if they're not, as well as from where they can be downloaded.

## Features

All of the basic WSB settings can be configured, such as disabling network or cliboard sharing, running in AppContainer isolation (protected mode), shared folders, etc. See [Use and configure Windows Sandbox | Microsoft Learn](https://learn.microsoft.com/en-us/windows/security/application-security/application-isolation/windows-sandbox/windows-sandbox-configure-using-wsb-file) or run the script with the `-Help` parameter.

Running the script without any parameters at all produces a config file with the following settings:

* **vGPU:** <code style="color : red">text</code>

The following system config and installations is currently supported:

* (list of all the logon command things)

Run the script with the `-Help` parameter for additional information.

## Bug reports and feature requests

Create an issue in this repository.