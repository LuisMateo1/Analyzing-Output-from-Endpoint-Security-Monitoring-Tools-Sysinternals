# Analyzing Output from Endpoint Security Monitoring Tools- Using Windows Sysinternals tools to analyze and log the anomalous behavior of a malicious process
<h3>Objectives</h3>

- Analyze data as part of security monitoring activities
- Implement configuration changes to existing controls to improve security
- Analyze potential indicators of compromise
#

<h3>Settign up The Phishing Attack</h3>

To simulate an attack, I will use a Trojan created by injecting code for a Meterpreter reverse shell into a legitimate executable. Meterpreter is a component of the Metasploit Framework(MSF).
- A reverse shell is one where the exploited machine opens a connection to its handler. This takes advantage of the fact that many networks are configured with limited outbound filtering, so the connection is more likely to be allowed than if a remote machine were trying to open it.

This is the site I’ll use to simulate tricking an employee on the 515support Windows network into running the trojan
![Screenshot 2024-05-28 153535](https://github.com/user-attachments/assets/d7e51e5a-adb8-4b5f-ac79-a96b56d58045)
- This is just the support webpage that loads by searching the IP address for this workstation, thanks to an Apache server also running on this host. Later I will go to this site on another VM, in that case, I would type in the IP of this VM and not localhost since I'll be on a different host/VM.
  - ![image](https://github.com/user-attachments/assets/560c83e2-a6cc-4423-84c9-b0c7ef805335)
  - You can do this by either opening a terminal or a search engine and typing in: ‘firefox http://localhost’ or ‘firefox http://192.168.2.192’ If I did it on a browser I wouldn’t need to specify the browser.
- The host IP can be found by entering ifconfig into the terminal. In this case, this Kali Linux VM’s IP is 192.168.2.192
  - ![image](https://github.com/user-attachments/assets/6bfad3d4-4d8b-4efc-8ce4-f0e6e90cab30)


Now I’ll run the Metasploit Framework Console by running: 'msfconsole' in terminal
![Screenshot 2024-05-28 154623](https://github.com/user-attachments/assets/2f75b1eb-8d1b-46ee-9316-483444be7911)
- In this case, I won't need to use the database so I can ignore the connection errors

Then run the command for the meterpreter payload and specify the listening host and port
![Screenshot 2024-05-28 230012](https://github.com/user-attachments/assets/4089d86c-6d8b-4b43-9c11-e75cc7f0bc82)
As the output says, this starts the reverse TCP handler on 192.168.2.192 on port 3389 which is the port used for Remote Desktop Protocol(RDP). Using the RDP port is important because it's a common port which means it's more likely that it can be used for this exploit.
#
<h3>Analysing Packets for Malware</h3>
Now that the payload is created when another host loads up the support site and downloads the connection tool, it will download the malicious payload as well. I'm going to start a packet capture to see this happen.

Now on a Windows VM, I'll be using NetworkMiner for the packet capture, I've disabled the Windows Defender firewall, because the payload that will be downloaded is a known trojan and Defender will block the download. 

Before starting the capture

![image](https://github.com/user-attachments/assets/36d79ec8-4f2e-4253-a079-401de2afd779)

I started the capture, went to HTTP://192.168.2.192, and downloaded the connection tool
![image](https://github.com/user-attachments/assets/816703aa-ff7d-4392-915f-59c779f7d6b3)

**Results**

**Hosts Tab**
- 6 hosts were identified, some active and others inactive (this is because they are in the VM's ARP cache).
- NetworkMiner performs fingerprinting to identify open ports and host OS, that's why it was able to identify another Windows VM.
![image](https://github.com/user-attachments/assets/ffa4a2da-8cd7-466c-ac14-d6100d9f7f0d)

**Files Tab**
- 3 files were found:
  - The webpage (.html)
  - The background image (.jpg)
  - The executable file (.exe) 
![image](https://github.com/user-attachments/assets/5cc8a415-5877-4e2d-8ff7-f52582982c1c)
![image](https://github.com/user-attachments/assets/9c3caa4e-383e-48af-a343-a11aeff1db3d)

Looking further into the file hash, when looking it up on VirusTotal, evilputty.exe has been flagged by 57 security vendors as malicious. They have flagged it as a trojan, and meterpreter. Which is the payload I used to infect the 515support page.
#
<h3>Configuring Sysinternals Logging and Monitoring Tools</h3>

Now I'll be using sysinternals tools to monitor evilputty.exe after execution. I'll be using the following tools:
- Process Explorer and Process Monitor, which can be used for live monitoring. These are most useful in a sandbox environment, where we know something will happen and we want to analyze it.
- Sysmon, which logs events that match a given configuration profile. This is used more for passive monitoring, and in this case, I'll be using a Sysmon configuration profile developed by InfoSec Swift on Security. That is done on Command Prompt as shown:
![image](https://github.com/user-attachments/assets/2b7c13e7-b36b-4cb1-bfe5-7b794ac69d1e)



