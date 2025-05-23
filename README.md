<img width="400" src="https://github.com/user-attachments/assets/44bac428-01bb-4fe9-9d85-96cba7698bee" alt="Tor Logo with the onion and a crosshair on it"/>

# Threat Hunt Report: Unauthorized TOR Usage
- [Scenario Creation](https://github.com/mar7inb/threat-hunt-scenario-tor/blob/main/threat-hunting-scenario-tor-event-creation.md)

## Platforms and Languages Leveraged
- Windows 10 Virtual Machines (Microsoft Azure)
- EDR Platform: Microsoft Defender for Endpoint
- Kusto Query Language (KQL)
- Tor Browser

##  Scenario

Management suspects that some employees may be using TOR browsers to bypass network security controls because recent network logs show unusual encrypted traffic patterns and connections to known TOR entry nodes. Additionally, there have been anonymous reports of employees discussing ways to access restricted sites during work hours. The goal is to detect any TOR usage and analyze related security incidents to mitigate potential risks. If any use of TOR is found, notify management.

### High-Level TOR-Related IoC Discovery Plan

- **Check `DeviceFileEvents`** for any `tor(.exe)` or `firefox(.exe)` file events.
- **Check `DeviceProcessEvents`** for any signs of installation or usage.
- **Check `DeviceNetworkEvents`** for any signs of outgoing connections over known TOR ports.

---

## Steps Taken

### 1. Searched the `DeviceFileEvents` Table

Searched the DeviceFileEvents table for any file that contained the word “tor” and discovered that the user/employee downloaded the Tor installer and actioned things that resulted in many tor-related files being generated. The user created a file named “tor-shopping-list.txt” on the desktop. These events began at: 2025-05-23T00:03:45.0125733Z


**Query used to locate events:**

```kql
DeviceFileEvents
| where FileName startswith "tor"
| where InitiatingProcessAccountName == "labuser01"
| where DeviceName == "mb-mde-vm01"
| where Timestamp >= datetime(2025-05-23T00:03:45.0125733Z)
| order by Timestamp desc
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, Account = InitiatingProcessAccountName
```
<img width="1212" alt="image" src="https://github.com/user-attachments/assets/660f2333-a3c5-4aa9-9839-d329216f2799">

---

### 2. Searched the `DeviceProcessEvents` Table

Searched the DeviceProcessEvents table for any processes that contained the string “tor-browser-windows-x86_64-portable-14.5.2.exe"”. Based on logs returned, on May 22, 2025, at 5:06 PM, a user on the computer mb-mde-vm01 launched the portable version of the Tor Browser (version 14.5.2) from their Downloads folder. The file, named tor-browser-windows-x86_64-portable-14.5.2.exe, was executed without any special commands—suggesting a typical launch, likely for private or anonymous web browsing..

**Query used to locate event:**

```kql

DeviceProcessEvents
| where DeviceName == "mb-mde-vm01"
| where ProcessCommandLine contains "tor-browser-windows-x86_64-portable-14.5.2.exe"
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine
```
<img width="1212" alt="image" src="https://github.com/user-attachments/assets/8a67881c-edca-49a8-9d51-ebdde6f17eb3">

---

### 3. Searched the `DeviceProcessEvents` Table for TOR Browser Execution

Searched the DeviceProcessEvents table for any indication that the user actually opened the tor browser. There was evidence that the user opened it at 2025-05-23T00:08:47.1449731Z- There were many instances of firefox.ex


**Query used to locate events:**

```kql
DeviceProcessEvents
| where DeviceName == "mb-mde-vm01"
| where FileName has_any ("tor.exe", "firefox.exe", "tor-browser.exe")
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine
| order by Timestamp desc
```
<img width="1212" alt="image" src="https://github.com/user-attachments/assets/456c4fc7-5328-4fd4-a919-28f5d0d7a496">

---

### 4. Searched the `DeviceNetworkEvents` Table for TOR Network Connections

Searched the DeviceNetworkEvents table for any indication the tor browser was used tp establish a connection using any of the known ports. On May 22, 2025, at 5:06 PM, a user on the computer mb-mde-vm01 launched the portable version of the Tor Browser (version 14.5.2) from their Downloads folder. The file, named tor-browser-windows-x86_64-portable-14.5.2.exe, was executed without any special commands—suggesting a typical launch, likely for private or anonymous web browsing.

**Query used to locate events:**

```kql
DeviceNetworkEvents
| where DeviceName == "mb-mde-vm01"
| where InitiatingProcessAccountName != "system"
| where RemotePort in ("9050", "9051", "9150", "9151")
| project Timestamp, DeviceName, InitiatingProcessAccountName, ActionType, RemoteIP, RemotePort, RemoteUrl, InitiatingProcessFileName, InitiatingProcessFolderPath
| order by Timestamp desc
```
<img width="1212" alt="image" src="![image](https://github.com/user-attachments/assets/9c286438-a1a5-4b16-9bd3-6493af07f6fe)
">

---

## Chronological Event Timeline 

### 1. File Download - TOR Installer

A user named labuser01 on computer mb-mde-vm01 downloaded a file called tor-browser-windows-x86_64-portable-14.5.2.exe on May 22, 2025, at 5:03 PM.


This file is the installer for the Tor Browser, which is used to browse the internet anonymously.

### 2. Process Execution - TOR Browser Installation

The user ran this Tor installer at least 7 times between 5:05 PM and 5:08 PM, trying both regular and silent install methods (the /S flag is for silent install, meaning no pop-ups).

### 3. Process Execution - TOR Browser Launch

After those installs, files like tor.exe, firefox.exe (Tor uses a modified Firefox), and several license documents were created in the "Desktop\Tor Browser" folder. This confirms that Tor Browser was successfully installed.

### 4. Network Connection - TOR Network

Starting at 5:10 PM, several processes named firefox.exe were launched from the Tor Browser directory. These show that the Tor Browser was being actively used, likely to browse multiple tabs.


### 5. File Creation - TOR Shopping List

Around 5:22 PM, the user created and then modified a text file called tor-shopping-list.txt.txt on the Desktop.


A shortcut to this file was also created, which shows the file was opened or accessed shortly after creation.

---

## Summary

On May 22, 2025, at 5:06 PM, a user on device mb-mde-vm01 executed the portable Tor Browser (version 14.5.2) from the Downloads folder. The process started normally without additional commands, indicating a standard launch likely intended for anonymous browsing.

---

## Response Taken

TOR usage was confirmed on the endpoint mb-mde-vm01 by the employee The device was isolated and the user's direct manager was notified
---
