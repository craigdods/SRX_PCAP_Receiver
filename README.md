# SRX_PCAP_Receiver
Open Source IDP PCAP receiver originally created by Oscar Ibatullin.

Used as an alternative to JSA/QRadar for collecting SRX IDP Attack Packets (PCAP)

# Installation instructions
1. Configure SRX to forward IDP Attack packets (pre and post) to the collector's IP address. The script listens on UDP port 2050 by default but you can change this.
set security idp sensor-configuration packet-log source-address 'your_source_address'
set security idp sensor-configuration packet-log host 'the_collector's_ip_address'
set security idp sensor-configuration packet-log host port 2050

2. If using routing-instances for dataplane connectivity to the collector, you'll need to setup a next-table statement from inet.0
set routing-options static route 'the_collector's_ip_address' next-table 'your_instance.inet.0'

3. Enable IDP Packet logging on the IDP policy of your choosing
set security idp idp-policy 'your_IDP_Policy' rulebase-ips rule 'your_rule' then notification packet-log pre-attack 2
set security idp idp-policy 'your_IDP_Policy' rulebase-ips rule 'your_rule' then notification packet-log post-attack 2
set security idp idp-policy 'your_IDP_Policy' rulebase-ips rule 'your_rule' then notification packet-log post-attack-timeout 5

4. Install script dependencies on the linux collector (Python 2.7 - Ubuntu Server 16.04)

i. Ubuntu Packages

$ sudo apt-get install python2.7 python-pip python-dpkt

ii. Python 2.7 packages

$ pip install twisted

# Usage instructions

Thankfully, usage is quite simple. The tool will create a directory called 'Juniper_IDP_PCAP_Storage' in the directory the script is executed from.
To execute and background the script, run:
$ python2.7 srx_pcap_receiver.py &

 When the script receives its first PCAP from the SRX, it will create the directory mentioned above.

Each signature is stored within its own subdirectory, like so:
admin@ubuntu16:~/Juniper_IDP_PCAP_Storage$ ls -lah
total 24K
drwxrwxr-x 2 admin admin 4.0K Jan 13 16:59 HTTP:MISC:CVE-2014-6332-OF
drwxrwxr-x 2 admin admin 4.0K Jan 13 16:49 HTTP:STC:JAVA:APPLET-CLASS-FILE
drwxrwxr-x 2 admin admin 4.0K Jan 13 16:49 SHELLCODE:WIN:SHIKATAGANAI-80S
drwxrwxr-x 2 admin admin 4.0K Jan 13 16:59 SHELLCODE:X86:DWORD-ADITIVE-80S

Navigate to the signature you'd like to analyze

admin@ubuntu16:~/Juniper_IDP_PCAP_Storage$ cd HTTP\:STC\:JAVA\:APPLET-CLASS-FILE/
admin@ubuntu16:~/Juniper_IDP_PCAP_Storage/HTTP:STC:JAVA:APPLET-CLASS-FILE$ ls -lah
total 12K
-rw-rw-r-- 1 admin admin  672 Jan 13 16:49 1484344180-229-2.pcap

Transfer and/or analyze with your favourite packet-analysis tool (Wireshark, tcpdump, tshark, etc)

admin@ubuntu16:~/Juniper_IDP_PCAP_Storage/HTTP:STC:JAVA:APPLET-CLASS-FILE$ tcpdump -r 1484344180-229-2.pcap
