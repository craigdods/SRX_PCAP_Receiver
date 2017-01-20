# SRX_PCAP_Receiver
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
total 24K
drwxrwxr-x 2 admin admin 4.0K Jan 13 16:59 HTTP:MISC:CVE-2014-6332-OF
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

As an example, if I am attempting to locate the PCAP for the event below, I would look first for the directory of the signature  (HTTP:MISC:CVE-2014-6332-OF), and then identify the packet-log of interest (ls -lah | grep 460). The name of each PCAP has the packet-log-id appended to it after the epoch time
```
2017-01-19T23:47:58.570Z SRX1500-A RT_IDP - IDP_ATTACK_LOG_EVENT [junos@2636.1.1.1.2.137 epoch-time="1484869672" message-type="SIG" source-address="10.1.1.10" source-port="61478" destination-address="208.94.116.21" destination-port="80" protocol-name="TCP" service-name="SERVICE_IDP" application-name="HTTP" rule-name="3" rulebase-name="IPS" policy-name="Space-IPS-Policy" export-id="17908" repeat-count="0" action="DROP" threat-severity="HIGH" attack-name="HTTP:MISC:CVE-2014-6332-OF" nat-source-address="192.168.0.10" nat-source-port="0" nat-destination-address="0.0.0.0" nat-destination-port="0" elapsed-time="0" inbound-bytes="0" outbound-bytes="0" inbound-packets="0" outbound-packets="0" source-zone-name="Inside" source-interface-name="reth1.0" destination-zone-name="Outside" destination-interface-name="reth0.0" packet-log-id="460" alert="no" username="N/A" roles="N/A" message="-"]
```

```
admin@ubuntu16:~/Juniper_IDP_PCAP_Storage/HTTP:MISC:CVE-2014-6332-OF$ ls -lah | grep 460
-rw-rw-r-- 1 craig craig 1.9K Jan 19 18:48 1484869672-460-2.pcap

admin@ubuntu16:~/Juniper_IDP_PCAP_Storage/HTTP:MISC:CVE-2014-6332-OF$ tcpdump -r 1484869672-460-2.pcap -vv
reading from file 1484869672-460-2.pcap, link-type EN10MB (Ethernet)
-5:00:00.000000 IP (tos 0x0, ttl 51, id 53568, offset 0, flags [none], proto TCP (6), length 336)
    vhost.phx1.nearlyfreespeech.net.http > 10.1.1.10.61478: Flags [P.], cksum 0x7e35 (correct), seq 295935730:295936026, ack 2270029545, win 32120, length 296: HTTP, length: 296
        HTTP/1.1 200 OK
        Last-Modified: Tue, 17 Mar 2015 04:56:42 GMT
        Accept-Ranges: bytes
        Content-Length: 4045
        Content-Type: text/html; charset=UTF-8
        Date: Thu, 19 Jan 2017 23:47:52 GMT
        Server: Apache
        ETag: "fcd-51174caf43e24"
        Via: 1.1 vhost.phx1.nearlyfreespeech.net:3128 (squid/2.7.STABLE7)

-5:00:00.010000 IP (tos 0x0, ttl 51, id 53572, offset 0, flags [none], proto TCP (6), length 1500)
    vhost.phx1.nearlyfreespeech.net.http > 10.1.1.10.61478: Flags [P.], seq 296:1756, ack 1, win 32120, length 1460: HTTP
```




