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
<img width="1212" alt="image" src="![image](https://github.com/user-attachments/assets/660f2333-a3c5-4aa9-9839-d329216f2799)
">

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
<img width="1212" alt="image" src="![image](https://github.com/user-attachments/assets/8a67881c-edca-49a8-9d51-ebdde6f17eb3)
">

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
<img width="1212" alt="image" src="https://github.com/user-attachments/assets/456c4fc7-5328-4fd4-a919-28f5d0d7a496
">

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

- **Timestamp:** `2024-11-08T22:14:48.6065231Z`
- **Event:** The user "employee" downloaded a file named `tor-browser-windows-x86_64-portable-14.0.1.exe` to the Downloads folder.
- **Action:** File download detected.
- **File Path:** `C:\Users\employee\Downloads\tor-browser-windows-x86_64-portable-14.0.1.exe`

### 2. Process Execution - TOR Browser Installation

- **Timestamp:** `2024-11-08T22:16:47.4484567Z`
- **Event:** The user "employee" executed the file `tor-browser-windows-x86_64-portable-14.0.1.exe` in silent mode, initiating a background installation of the TOR Browser.
- **Action:** Process creation detected.
- **Command:** `tor-browser-windows-x86_64-portable-14.0.1.exe /S`
- **File Path:** `C:\Users\employee\Downloads\tor-browser-windows-x86_64-portable-14.0.1.exe`

### 3. Process Execution - TOR Browser Launch

- **Timestamp:** `2024-11-08T22:17:21.6357935Z`
- **Event:** User "employee" opened the TOR browser. Subsequent processes associated with TOR browser, such as `firefox.exe` and `tor.exe`, were also created, indicating that the browser launched successfully.
- **Action:** Process creation of TOR browser-related executables detected.
- **File Path:** `C:\Users\employee\Desktop\Tor Browser\Browser\TorBrowser\Tor\tor.exe`

### 4. Network Connection - TOR Network

- **Timestamp:** `2024-11-08T22:18:01.1246358Z`
- **Event:** A network connection to IP `176.198.159.33` on port `9001` by user "employee" was established using `tor.exe`, confirming TOR browser network activity.
- **Action:** Connection success.
- **Process:** `tor.exe`
- **File Path:** `c:\users\employee\desktop\tor browser\browser\torbrowser\tor\tor.exe`

### 5. Additional Network Connections - TOR Browser Activity

- **Timestamps:**
  - `2024-11-08T22:18:08Z` - Connected to `194.164.169.85` on port `443`.
  - `2024-11-08T22:18:16Z` - Local connection to `127.0.0.1` on port `9150`.
- **Event:** Additional TOR network connections were established, indicating ongoing activity by user "employee" through the TOR browser.
- **Action:** Multiple successful connections detected.

### 6. File Creation - TOR Shopping List

- **Timestamp:** `2024-11-08T22:27:19.7259964Z`
- **Event:** The user "employee" created a file named `tor-shopping-list.txt` on the desktop, potentially indicating a list or notes related to their TOR browser activities.
- **Action:** File creation detected.
- **File Path:** `C:\Users\employee\Desktop\tor-shopping-list.txt`

---

## Summary

The user "employee" on the "threat-hunt-lab" device initiated and completed the installation of the TOR browser. They proceeded to launch the browser, establish connections within the TOR network, and created various files related to TOR on their desktop, including a file named `tor-shopping-list.txt`. This sequence of activities indicates that the user actively installed, configured, and used the TOR browser, likely for anonymous browsing purposes, with possible documentation in the form of the "shopping list" file.

---

## Response Taken

TOR usage was confirmed on the endpoint `threat-hunt-lab` by the user `employee`. The device was isolated, and the user's direct manager was notified.

---
