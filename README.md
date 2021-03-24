# Project 2 of Cybersecurity Course

### Introduction
Target machine: Metasploitable 3 running in VirtualBox (IP address: 172.28.128.3)

Attacker: Ubuntu 18.04.5 LTS (physical machine) (IP address 172.28.128.1 and 192.168.1.166)

Before conducting attacks, run `sudo nmap -sS -sV -v -n -p- 172.28.128.3` to scan ports of target mahcine. `-sS` sends TCP SYN, `-sV` probes open ports to determine service/version info, `-v` represents verbose, showing the scan process, `-n` ignores DNS resolution as the target machine and the attacker are in the same internal network, and `-p-` scans all 65535 ports.

Result:

![](https://github.com/yumoL/cybersecurity-project2/blob/main/images/open_port.png)

The previous 4 attacks are conducted based on the [known exploits](https://stuffwithaurum.com/2020/04/17/metasploitable-3-linux-an-exploitation-guide/)
### Identified Attack 1: ProFTPD
The vulnerability of the ProFTPD server running on port 21 can be exploited using the “exploit/unix/ftp/proftpd_modcopy_exec” module.
![](https://github.com/yumoL/cybersecurity-project2/blob/main/images/ftp-exploit.png)
Snort logs:
```
03/23-09:28:53.333754  [**] [1:1356:5] WEB-ATTACKS perl execution attempt [**] [Classification: Web Application Attack] [Priority: 1] {TCP} 172.28.128.1:46583 -> 172.28.128.3:80
03/23-09:29:03.687996  [**] [1:2019284:1] ET ATTACK_RESPONSE Output of id command from HTTP server [**] [Classification: Potentially Bad Traffic] [Priority: 2] {TCP} 172.28.128.3:54528 -> 172.28.128.1:4444
```

### Identified Attack 2: Apache Httpd
The vulnerability of the Apache http server running on port 80 can be exploited using the “exploit/multi/http/apache_mod_cgi_bash_env_exec” module.
![](https://github.com/yumoL/cybersecurity-project2/blob/main/images/apache-exploit.png)
Snort logs:
```
03/22-22:14:45.382424  [**] [1:2025869:2] ET WEB_SPECIFIC_APPS ELF file magic plain Inbound Web Servers Likely Command Execution 12 [**] [Classification: Attempted User Privilege Gain] [Priority: 1] {TCP} 172.28.128.1:35953 -> 172.28.128.3:80
03/22-22:14:45.382424  [**] [1:1336:5] WEB-ATTACKS chmod command attempt [**] [Classification: Web Application Attack] [Priority: 1] {TCP} 172.28.128.1:35953 -> 172.28.128.3:80
03/22-22:14:45.382424  [**] [1:100000122:1] COMMUNITY WEB-MISC mod_jrun overflow attempt [**] [Classification: Web Application Attack] [Priority: 1] {TCP} 172.28.128.1:35953 -> 172.28.128.3:80
03/22-22:14:45.382424  [**] [1:2019232:3] ET WEB_SERVER Possible CVE-2014-6271 Attempt in Headers [**] [Classification: Attempted Administrator Privilege Gain] [Priority: 1] {TCP} 172.28.128.1:35953 -> 172.28.128.3:80
03/22-22:14:45.652967  [**] [1:2022028:1] ET WEB_SERVER Possible CVE-2014-6271 Attempt [**] [Classification: Attempted Administrator Privilege Gain] [Priority: 1] {TCP} 172.28.128.1:43709 -> 172.28.128.3:80
03/22-22:14:45.652967  [**] [1:2019232:3] ET WEB_SERVER Possible CVE-2014-6271 Attempt in Headers [**] [Classification: Attempted Administrator Privilege Gain] [Priority: 1] {TCP} 172.28.128.1:43709 -> 172.28.128.3:80
```

### Identified Attack 3: UnrealIRCd
The vulnerability of the UnrealIRCd server running on port 6697 can be exploited using the “exploit/unix/irc/unreal_ircd_3281_backdoor” module.
![](https://github.com/yumoL/cybersecurity-project2/blob/main/images/ircd-exploit.png)
Snort logs:
```
03/23-12:49:48.321008  [**] [1:2000355:5] ET CHAT IRC authorization message [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.28.128.3:6697 -> 172.28.128.1:41853
03/23-12:49:51.617427  [**] [1:2019284:1] ET ATTACK_RESPONSE Output of id command from HTTP server [**] [Classification: Potentially Bad Traffic] [Priority: 2] {TCP} 172.28.128.3:54688 -> 172.28.128.1:4444
```
### Missed Attack 1: Docker Daemon Local Privilege Escalation
As mentioned in the [known exploits](https://stuffwithaurum.com/2020/04/17/metasploitable-3-linux-an-exploitation-guide/), the Docker daemon running on the target mahcine exposes an unprotected TCP socket. We can use the session obtained from the attack on Unreal IRCd as this session is running by a user who is in the docker group. First we keep the obtained session running in the background:
![](https://github.com/yumoL/cybersecurity-project2/blob/main/images/ircd-background.png)
Then we can exploit this vulnerability using the “exploit/linux/local/docker_daemon_privilege_escalation” module.:
![](https://github.com/yumoL/cybersecurity-project2/blob/main/images/docker-exploit.png)
Snort logs nothing about this exploit.

### Missed Attack 2: Brute-forcing SSH
In the previous attack we can obtain a list of usernames

![](https://github.com/yumoL/cybersecurity-project2/blob/main/images/usernames.png)

We save these usernames to [usernames.txt](https://github.com/yumoL/cybersecurity-project2/blob/main/usernames.txt). In this SSH attack we use the “auxiliary/scanner/ssh/ssh_login” module to test if there is such a credential where username and password are the same. If such username-password pair is found very quickly, for example, within 0-4 login attempts, Snort does not raise any alert. We already know that the password of username "vagrant" is also "vagrant", so we move "vagrant" to the 4th line of the username list and run SSH scan:
![](https://github.com/yumoL/cybersecurity-project2/blob/main/images/ssh-exploit.png)
Snort does not raise any alert.
It is worth noting that if we move "vagrant" to the end of the usernames file and make the SSH attempt fail for many times, Snort does raise alerts
```
03/23-15:47:22.466160  [**] [1:2001219:19] ET SCAN Potential SSH Scan [**] [Classification: Attempted Information Leak] [Priority: 2] {TCP} 172.28.128.1:33117 -> 172.28.128.3:22
```
The reason is that Snort raises alerts for possible SSH attacks if the number of login failures is over a specific threshold.
![](https://github.com/yumoL/cybersecurity-project2/blob/main/images/ssh-rules.png)

### Is it easier to fix applications than to detect attacks?

It is usually easier to fix applications than to detect attacks. Current intrusion detection systems face the following challenges which make intrusion detection difficult:

1) The requirement of expertise: Intrusion detection requires both technical and organizational expertise. Professionals need to have general security knowledge and specific knowledge of their network environment to configure an intrusion detection system to work effectively. Considering Snort, which detects attacks based on predefined rules, such expertise is required to configure the appropriate rules. 
2) Managing a high volume of alerts: Many intrusion detection systems raise alerts when they detect activities that match a known attack pattern or abnormal traffic. Many alerts are false positives, but organizations usually do not have enough time or resources to detect every alert. As a result, actual attacks, especially 0-day attacks, may be overlooked due to time and resource constraints. 
3) The reliance on internal teams: Many organizations rely on their internal security teams to analyze the alerts generated by intrusion detection systems. Unlike open source software, where everyone can contribute to fixing vulnerabilities, the logs of detection systems are not accessible for external people due to privacy and business concerns. Therefore, these organizations cannot improve their attack detection capability with the help of large open source communities.
 
From the developers’ perspective, sometimes it is easier to fix an application to prevent attacks from the beginning than to detect attacks after the application has already been brought into use. For example, in an extreme case where a user uses the same password in many services, if this password is leaked from service A and used by an attacker to log in to service B, it is nearly impossible for service B to detect the attack because the attacker has the exactly correct password and the log-in succeeds in one attempt. In this case, implementing multi-factor authentication, e.g., sending verification codes using SMS, is an efficient way to mitigate this problem. 

It is unrealistic to expect all end users to have enough security knowledge to detect attacks. They usually rely on firewalls for attack detection, but firewalls are also software and can also fall into an attack target. Therefore, from the end users’ perspective, it is easier to patch applications by updating them to the newest version in a timely manner than to detect attacks. 
Finally, it is worth noting that fixing applications and detecting attacks complement each other. To fix an application, it is necessary to identify the vulnerabilities, and attack detection is an efficient way to find vulnerabilities. It is also meaningless to only detect attacks without fixing the exploited vulnerabilities.  





