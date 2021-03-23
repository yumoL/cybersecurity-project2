# Project 2 of Cybersecurity Course

### Introduction
Target machine: Metasploitable 3 running in VirtualBox (IP address: 172.28.128.3)

Attacker: Ubuntu 18.04.5 LTS (physical machine) (IP address 172.28.128.1 and 192.168.1.166)

Before conducting attacks, we run `sudo nmap -sS -sV -v -n -p- 172.28.128.3` to scan . `-sS` sends TCP SYN; `-sV` probes open ports to determine service/version info, `-v` represents verbose, showing the scan process, `-n` ignores DNS resolution as the target machine and the attacker are in the same internal network, and `-p-` scans all 65535 ports.

Result:

![](https://github.com/yumoL/cybersecurity-project2/blob/main/images/open_port.png)

The following attacks were conducted based on [known exploits](https://stuffwithaurum.com/2020/04/17/metasploitable-3-linux-an-exploitation-guide/)
### Identified Attack 1: ProFTPD
The ProFTPD service was running on port 21.
![](https://github.com/yumoL/cybersecurity-project2/blob/main/images/ftp-exploit.png)
Snort logs:
```
03/23-09:28:53.333754  [**] [1:1356:5] WEB-ATTACKS perl execution attempt [**] [Classification: Web Application Attack] [Priority: 1] {TCP} 172.28.128.1:46583 -> 172.28.128.3:80
03/23-09:29:03.687996  [**] [1:2019284:1] ET ATTACK_RESPONSE Output of id command from HTTP server [**] [Classification: Potentially Bad Traffic] [Priority: 2] {TCP} 172.28.128.3:54528 -> 172.28.128.1:4444
```

### Identified Attack 2: Apache Httpd
The Apache HTTP server was running on port 80.
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

### Identified Attack 3: Unreal IRCd
The Unreal IRCd application was running on port 6697.
![](https://github.com/yumoL/cybersecurity-project2/blob/main/images/ircd-exploit.png)
Snort logs:
```
03/23-12:49:48.321008  [**] [1:2000355:5] ET CHAT IRC authorization message [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.28.128.3:6697 -> 172.28.128.1:41853
03/23-12:49:51.617427  [**] [1:2019284:1] ET ATTACK_RESPONSE Output of id command from HTTP server [**] [Classification: Potentially Bad Traffic] [Priority: 2] {TCP} 172.28.128.3:54688 -> 172.28.128.1:4444
```

