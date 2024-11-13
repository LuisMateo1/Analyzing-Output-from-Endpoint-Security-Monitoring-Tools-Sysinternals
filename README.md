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
- The host IP can be found by entering ifconfig into the terminal. In this case, this Kali Linux VM’s IP is 192.168.2.192, this will be the attack box.
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

![Screenshot 2024-05-28 222019](https://github.com/user-attachments/assets/6c660b95-2a72-4ca0-bf02-03667b99d59e)
![Screenshot 2024-05-28 222147](https://github.com/user-attachments/assets/a09f0b9a-1c94-4d89-9851-67a1c98280bc)

#
<h3>Configuring Sysinternals Logging and Monitoring Tools</h3>

Now I'll be using sysinternals tools to monitor evilputty.exe after execution. I'll be using the following tools:
- Process Explorer, which can be used for live monitoring of running processes. This is most useful in a sandbox environment, where we know something will happen and we want to analyze it.
- Sysmon, which logs events that match a given configuration profile. This is used more for passive monitoring, and in this case, I'll be using a Sysmon configuration profile developed by InfoSec Swift on Security. That is done on Command Prompt as shown:
![image](https://github.com/user-attachments/assets/2b7c13e7-b36b-4cb1-bfe5-7b794ac69d1e)

This is Process Explorer, it lists every running process, PID, the user that started the process, and much more. For this lab, I only added the user and integrity fields.
- I'll come back to Process Explorer after running the malware.
![Screenshot 2024-05-28 224210](https://github.com/user-attachments/assets/5a61b043-4d66-41cd-9231-21de26caff5c)

<h3>Analzing the Malware Process</h3>
Now I will run the malware, and look for indicators of anomalous behavior with the Sysmon tools. I will run the malware specifically from the browser, instead of looking for it in the downloads folder, this will come up later.

![image](https://github.com/user-attachments/assets/b46070a8-167a-4ea6-87b7-79d34edd13a6)
![Screenshot 2024-05-28 225314](https://github.com/user-attachments/assets/db4cbaee-e43b-4a37-b98a-720d20ec40a9)

After clicking 'run', the PuTTY configuration window shows up. More importantly, now that I ran the executable this VM connected to 192.168.2.192, the Linux VM/attack box.

![image](https://github.com/user-attachments/assets/e3906202-4de8-420c-a128-b1d091ec75e3)

Now in Process Explorer, evilputty.exe has shown up, some things to take note of are:
- its parent process is browser_broker.exe, meaning it was executed by the browser rather than Explorer. And they are both running as children of a svchost container.
- It is run by the logged-on user and has only medium privileges
- The description, company, and publisher name are those of the legitimate process.
![image](https://github.com/user-attachments/assets/5e1313e6-b7f4-47f6-9193-e4f753f8837b)

Right-clicking the process -> properties -> TCP/IP tab shows that there is an established connection to the Linux VM/attack box
![image](https://github.com/user-attachments/assets/57440b59-8fdb-422a-80dd-8a61926ab5be)
![image](https://github.com/user-attachments/assets/9e0b7fde-6586-44dc-b8a9-d8f96cf9289f)

<h3>Analyze a Persistence Mechanism</h3>

After gaining access to a system, one of the top objectives of an attacker is to establish persistence. Persistence establishes a method for the attacker to return to the system at a later time, regardless of if a user is logged on. Since the attacker has to interact with the host system, they will create a discoverable trail in audit logs, that can expose the attacker.

Back on the attack box, I'll run persistence.exe, and hide it by changing the name to svchost.exe, it will execute evilputty.exe on startup, etc.

![Screenshot 2024-05-28 232907](https://github.com/user-attachments/assets/4f6d25e6-2236-4d2f-9d7f-2b873c0e79be)
![Screenshot 2024-05-28 233226](https://github.com/user-attachments/assets/3f51cc08-8a83-4ff1-b01d-20a2bff4515f)

If I were to restart the Windows VM, we would see this in action and PuTTY will be open on startup. Unfortunately, Windows Defender turns back on and will not allow it.




