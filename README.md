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
- This is just the support webpage that loads by searching the IP address for this workstation (localhost).
- You can do this by either opening a terminal or a search engine and typing in: ‘firefox http://localhost’ or ‘firefox http://192.168.2.192’ If I did it on a browser I wouldn’t need to specify the address.
- Host IP can be found by entering ifconfig on the terminal. In this case, this kali linux VM’s IP is 192.168.2.192

Now I’ll run the Metasploit Framework Console by running: 'msfconsole' in terminal
![Screenshot 2024-05-28 154623](https://github.com/user-attachments/assets/2f75b1eb-8d1b-46ee-9316-483444be7911)
- In this case, I won't need to use the database so I can ignore the connection errors

Then run the command for the meterpreter payload and specify the listening host and port
![Screenshot 2024-05-28 230012](https://github.com/user-attachments/assets/4089d86c-6d8b-4b43-9c11-e75cc7f0bc82)

<h3>Packet Analysis</h3>
