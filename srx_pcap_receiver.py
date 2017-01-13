#!/usr/bin/env python

#==============================================================================
# srx_pcap_receiver.py
# 
# Created by Oscar Ibatullin on 2012-09-14.
# Copyright 2017 Juniper Networks. All rights reserved.
#------------------------------------------------------------------------------
# Tool to receive packet captures for IDP attack events from Juniper SRX.
#
# Changes in version 1.01:
# - Included installation instructions
# - Added to GitHub
# - Modified Naming Scheme
#
# Changes in version 1.00:
# - work as a server receiving pcaps, or process an offline DMI packet capture;
# - workaround a bug with session intermingling which exists in SRX pcap sender;
# - fix IP, TCP, UDP checksums in the resulting packet captures;
# - handle fragmentation (aka DMI type 2 packets).
#
# Version last tested: 15.1X49-D70 in January 2017
#
# Updated by Craig Dods on 2017-01-13
#==============================================================================

#==============================================================================
# Installation instructions
#------------------------------------------------------------------------------
# 1. Configure SRX to forward IDP Attack packets (pre and post) to the collector's IP address. The script listens on UDP port 2050 by default but you can change this.
# set security idp sensor-configuration packet-log source-address 'your_source_address'
# set security idp sensor-configuration packet-log host 'the_collector's_ip_address'
# set security idp sensor-configuration packet-log host port 2050
#
# 2. If using routing-instances for dataplane connectivity to the collector, you'll need to setup a next-table statement from inet.0
# set routing-options static route 'the_collector's_ip_address' next-table 'your_instance.inet.0'
#
# 3. Enable IDP Packet logging on the IDP policy of your choosing
# set security idp idp-policy 'your_IDP_Policy' rulebase-ips rule 'your_rule' then notification packet-log pre-attack 2
# set security idp idp-policy 'your_IDP_Policy' rulebase-ips rule 'your_rule' then notification packet-log post-attack 2
# set security idp idp-policy 'your_IDP_Policy' rulebase-ips rule 'your_rule' then notification packet-log post-attack-timeout 5
#
# 4. Install script dependencies on the linux collector (Python 2.7 - Ubuntu Server 16.04)
# i. Ubuntu Packages
# $ sudo apt-get install python2.7 python-pip python-dpkt
# 
# ii. Python 2.7 packages
# $ pip install twisted
#
#==============================================================================
# Usage instructions
#------------------------------------------------------------------------------
# Thankfully, usage is quite simple. The tool will create a directory called 'Juniper_IDP_PCAP_Storage' in the directory the script is executed from.
# To execute and background the script, run:
# $ python2.7 srx_pcap_receiver.py &
#
# When the script receives its first PCAP from the SRX, it will create the directory mentioned above.
# 
# Each signature is stored within its own subdirectory, like so:
# admin@ubuntu16:~/Juniper_IDP_PCAP_Storage$ ls -lah
# total 24K
# drwxrwxr-x 2 admin admin 4.0K Jan 13 16:59 HTTP:MISC:CVE-2014-6332-OF
# drwxrwxr-x 2 admin admin 4.0K Jan 13 16:49 HTTP:STC:JAVA:APPLET-CLASS-FILE
# drwxrwxr-x 2 admin admin 4.0K Jan 13 16:49 SHELLCODE:WIN:SHIKATAGANAI-80S
# drwxrwxr-x 2 admin admin 4.0K Jan 13 16:59 SHELLCODE:X86:DWORD-ADITIVE-80S
# 
# Navigate to the signature you'd like to analyze
#
# admin@ubuntu16:~/Juniper_IDP_PCAP_Storage$ cd HTTP\:STC\:JAVA\:APPLET-CLASS-FILE/
# admin@ubuntu16:~/Juniper_IDP_PCAP_Storage/HTTP:STC:JAVA:APPLET-CLASS-FILE$ ls -lah
# total 12K
# -rw-rw-r-- 1 admin admin  672 Jan 13 16:49 1484344180-229-2.pcap
#
# Transfer and/or analyze with your favourite packet-analysis tool (Wireshark, tcpdump, tshark, etc)
#
# admin@ubuntu16:~/Juniper_IDP_PCAP_Storage/HTTP:STC:JAVA:APPLET-CLASS-FILE$ tcpdump -r 1484344180-229-2.pcap
#
#------------------------------------------------------------------------------


from twisted.internet.protocol import DatagramProtocol
from twisted.internet import reactor
from threading import Timer
from ctypes import *
import cStringIO, struct, logging
import os, sys, time, signal
import argparse
import dpkt

PCAPD_PORT     = 2050      # Receiving port - Defined on SRX with "set security idp sensor-configuration packet-log host port 2050"
PCAPD_TIMEOUT  = 2        # timeout to complete one pcap, in seconds. Reduce further if congestion is seen
PCAPD_BASEDIR  = os.path.join('.','Juniper_IDP_PCAP_Storage')

#------------------------------------------------------------------------------

class PacketStruct(BigEndianStructure):
    """
    Base class for loading raw data from packets
    """
    _pack_ = 1

    def unpack(self, buf):
        fit = min(len(buf), sizeof(self))
        memmove(addressof(self), buf, fit)
        return self

    def __str__(self):
        return '\n'.join(['%s: %s'%(f[0], str(getattr(self,f[0])))
                                          for f in self._fields_])

#------------------------------------------------------------------------------

class dmi_hdr_t(PacketStruct):
    _fields_ = [('signature',     c_uint32),
                ('pdu_length',    c_uint32)]

    def unpack(self, buf):
        super(dmi_hdr_t, self).unpack(buf)
        assert(self.signature == 0x1234)
        return self


class blob_hdr_t(PacketStruct):
    _fields_ = [('bopl_const',    c_uint32, 24),  # BOPL = begin of packet log
                ('bopl_version',  c_uint32, 8),
                ('pkt_log_id',    c_uint64)]

    def unpack(self, buf):
        super(blob_hdr_t, self).unpack(buf)
        assert(self.bopl_const == 0x5e1ec7)
        assert(self.bopl_version == 1)
        return self

FIXED_PCAP_HDRS_LEN = sizeof(dmi_hdr_t) + sizeof(blob_hdr_t)

#------------------------------------------------------------------------------

class pcap_type1_hdr_t(PacketStruct):
    _fields_ = [('type',          c_uint16),
                ('num_bytes',     c_uint16),  # total number of bytes in this TLV including TLV hdr
                ('num_packets',   c_uint32),  # total number of packets captured for this attack
                ('cur_packet',    c_uint32)]  # current packet index

class pcap_type2_hdr_t(PacketStruct):
    _fields_ = [('type',          c_uint16),
                ('num_bytes',     c_uint16),
                ('num_packets',   c_uint32),
                ('cur_packet',    c_uint32),
                ('reserved',      c_uint16, 2),
                ('more_frgmts',   c_uint16, 1),
                ('frgmt_offset',  c_uint16, 13),
                ('frgment_bytes', c_uint16)]

class pcap_type3_hdr_t(PacketStruct):
    _fields_ = [('type',          c_uint16),
                ('time_stamp',    c_uint32),
                ('rule_id',       c_uint16),
                ('trigger_packet',c_uint16),
                ('attack_id',     c_uint32),
                ('attack_name',   c_char*32)]

pcap_hdr_types = (None, pcap_type1_hdr_t, pcap_type2_hdr_t, pcap_type3_hdr_t)

#------------------------------------------------------------------------------

class FragError(Exception):
    pass

class FragBuf(object):
    """
    String buffer to reassemble fragmented packets
    """
    def __init__(self):
        self._buf = ''
        self._pieces = {}

    def insert(self, offset, s):
        self._pieces[offset] = s

    @property
    def pieces(self):
        return '|'.join(['%d-%d'%(k,k+len(self._pieces[k])) for k in self._pieces])

    def finalize(self):
        for k in sorted(self._pieces.iterkeys()):
            if len(self._buf) == k:
                self._buf += self._pieces[k]
            else:
                raise FragError

    def __repr__(self):
        return 'FragBuf(%s)' % self._buf

    def __str__(self):
        return self._buf


#------------------------------------------------------------------------------

queue = {}

class queue_node_t(object):
    """
    Queue node that will save a pcap and self-destruct upon timeout
    """
    def __init__(self, log_id):
        self.packets    = {}
        self.header     = None
        self.fragments  = False
        self._log_id    = log_id
        self._finalized = False
        self._pcapf     = cStringIO.StringIO()
        self._pcapw     = dpkt.pcap.Writer(self._pcapf)
        self._timer     = Timer(PCAPD_TIMEOUT, self._timeout)
        self._timer.start()
        logging.debug('node %d created' % log_id)

        self._logged_bug1 = False  # XXX - FIXME: remove after SRX bugs are fixed
        self._logged_bug2 = False

    def _timeout(self):
        if not self.header or not self.fragments:
            logging.warning('node %d timed out, type3 hdr=%d, frags=%d' %
                            (self._log_id, self.header!=None, self.fragments))
        self.finalize()

    def _abort_pcap(self, msg, log_level=logging.WARNING):
        logging.log(log_level, 'will not store node %d, reason: %s' % (self._log_id, msg))
        self._destruct()

    def _destruct(self):
        self._pcapf.close()
        del(queue[self._log_id])  # self-destruct

    def finalize(self):
        if    self._finalized: return
        else: self._finalized = True
        self._timer.cancel()
        logging.debug('finalizing node %d' % self._log_id)

        if hasattr(self, 'rem_pkts') and len(self.rem_pkts) > 0:
            self._abort_pcap('%d packets were not received' % len(self.rem_pkts))
            return

        if len(self.packets) == 0:
            self._abort_pcap('no packets!')
            return

        if self.header == None:
            self._abort_pcap('type3 header was not received')
            return

        try:
            for i,k in enumerate(sorted(self.packets.iterkeys())):
                p = self.packets[k]
                if isinstance(p, FragBuf):
                    p.finalize()
                    p = str(p)

                if dpkt_is_icmp(p):
                    self._abort_pcap('ICMP packets', log_level=logging.DEBUG)
                    return

                try:
                    #
                    # this is a workaround for the SRX pcap session intermingling bugs
                    # bug 1: CTS flow client_ip:port_X, STC flow client_ip:port_Y
                    # bug 2: CTS flow server_IP_A, STC flow server_IP_B
                    # resulting pcap contains CTS and STC flows as separate sessions
                    #
                    if i==0:
                        srcip, sport = dpkt_get_src(p)
                        dstip, dport = dpkt_get_dst(p)

                    elif dpkt_get_src(p)[0] != srcip:
                        if dpkt_get_ports(p) != (dport, sport):
                            if not self._logged_bug1:  # log only once
                                logging.warning('node %d - SRX port bug found' % self._log_id)
                                self._logged_bug1 = True
                            #
                            # XXX - Uncomment to apply the workaround
                            #
                            #p = dpkt_set_ports(p, dport, sport)

                        elif dpkt_get_src(p)[0] != dstip or \
                             dpkt_get_dst(p)[0] != srcip:
                            if not self._logged_bug2:
                                logging.warning('node %d - SRX IP bug found' % self._log_id)
                                self._logged_bug2 = True
                            #
                            # XXX - Uncomment to apply the workaround
                            #
                            #p = dpkt_set_IPs(p, dstip, srcip)

                except (AssertionError, UnboundLocalError):
                    pass    # pcap is neither TCP nor UDP, store it for the science
                except:
                    logging.exception('')
                    return
                else:
                    p = dpkt_fix_checksums(p)

                self._pcapw.writepkt(p, i/float(100))
        except FragError:
            self._abort_pcap('missing fragments in packet %d. have pieces %s' % (k, p.pieces))
            return
        except:
            logging.exception('')
        else:
            # make a sub-directory with attack name
            subdir = self.header.attack_name
            if sys.platform.startswith('win'): subdir = subdir.replace(':', '_')
            path = os.path.join(PCAPD_BASEDIR, subdir)
            if not os.path.exists(path):
                try:
                    os.makedirs(path)
                except:
                    logging.error('Cannot create sub-directory %s' % path)
                    path = PCAPD_BASEDIR

            _pcapn  = os.path.join(path, '%d-%d-%d.pcap' %
                      (self.header.time_stamp, self._log_id, self.header.trigger_packet))

            try:
                with open(_pcapn, 'wb') as f:
                    f.write(self._pcapf.getvalue())
                logging.debug('saved pcap %s' % _pcapn)
            except:
                logging.exception('failed to save pcap %s' % _pcapn)

        self._destruct()


#==============================================================================
# DMI packet format is described in pcap-dmi-functional-spec.txt
#
def process_packet(p):
    global queue

    dmi_hdr  = dmi_hdr_t().unpack(p)
    blob_hdr = blob_hdr_t().unpack(p[sizeof(dmi_hdr):])
    pkt_type = ord(p[FIXED_PCAP_HDRS_LEN+1])

    log_id   = blob_hdr.pkt_log_id           # use this as a session key
    hdr      = pcap_hdr_types[pkt_type]().unpack(p[FIXED_PCAP_HDRS_LEN:])
    if VERBOSE > 1:
        logging.debug('\n----------- header -----------\n%s' % hdr)

    if not (1<=pkt_type<=3):
        logging.error('unknown packet type %d' % pkt_type)

    if log_id not in queue:
        queue[log_id] = queue_node_t(log_id)

    if pkt_type == 3:
        assert(FIXED_PCAP_HDRS_LEN + sizeof(hdr) == len(p))  # no payload
        queue[log_id].header = hdr
    else:
        buf  = p[FIXED_PCAP_HDRS_LEN:]
        node = queue[log_id]
        if not hasattr(node, 'rem_pkts'):
            node.rem_pkts = set(range(1,hdr.num_packets+1))  # track remaining packets for the node

        while True:
            if pkt_type==1:
                # no fragmentation
                node.packets[hdr.cur_packet] = buf[sizeof(hdr):hdr.num_bytes]
            else:
                # fragments can arrive out of order
                node.fragments = True
                node.packets.setdefault(hdr.cur_packet, FragBuf())
                node.packets[hdr.cur_packet].insert(offset = hdr.frgmt_offset,
                                            s = buf[sizeof(hdr):hdr.num_bytes])
            if hdr.cur_packet in node.rem_pkts:
                node.rem_pkts.remove(hdr.cur_packet)

            if VERBOSE > 1:
                logging.debug('node %d packets remaining %s' % (log_id, list(node.rem_pkts)))

            # point at next packet record in the DMI packet and continue
            buf = buf[hdr.num_bytes:]
            if len(buf)==0: break

            pkt_type = ord(buf[1])
            hdr = pcap_hdr_types[pkt_type]().unpack(buf)
            if VERBOSE > 1:
                logging.debug('\n--------- sub-header ---------\n%s' % hdr)

        # for type2 packet, fragments may arrive in random order, so we have no
        # other choice than just wait and rely on the timer to finalize them
        if len(node.rem_pkts)==0 and node.header and not node.fragments:
            logging.debug('all packets processed for node %d' % log_id)
            node.finalize()


#------------------------------------------------------------------------------
# some dpkt helper routines
#
def dpkt_assert_L3(d):
    assert(isinstance(d, dpkt.ip.IP))

def dpkt_assert_L4_UDP(d):
    assert(isinstance(d, dpkt.udp.UDP))

def dpkt_assert_L4_ports(d):
    assert(hasattr(d, 'sport') and hasattr(d, 'dport'))

def dpkt_is_icmp(pkt):
    eth = dpkt.ethernet.Ethernet(pkt)
    ip  = eth.data; dpkt_assert_L3(ip)
    return ip.p == dpkt.ip.IP_PROTO_ICMP

def dpkt_get_udp_payload(pkt):
    eth = dpkt.ethernet.Ethernet(pkt)
    ip  = eth.data; dpkt_assert_L3(ip)
    udp = ip.data;  dpkt_assert_L4_UDP(udp)
    return udp.data

def dpkt_get_ports(pkt):
    eth = dpkt.ethernet.Ethernet(pkt)
    ip  = eth.data; dpkt_assert_L3(ip)
    l4  = ip.data;  dpkt_assert_L4_ports(l4)
    return (l4.sport, l4.dport)

def dpkt_set_ports(pkt, sport, dport):
    eth = dpkt.ethernet.Ethernet(pkt)
    ip  = eth.data; dpkt_assert_L3(ip)
    l4  = ip.data;  dpkt_assert_L4_ports(l4)
    l4.sport = sport
    l4.dport = dport
    return str(eth)

def dpkt_get_src(pkt):
    eth = dpkt.ethernet.Ethernet(pkt)
    ip  = eth.data; dpkt_assert_L3(ip)
    l4  = ip.data;  dpkt_assert_L4_ports(l4)
    return (ip.src, l4.sport)

def dpkt_get_dst(pkt):
    eth = dpkt.ethernet.Ethernet(pkt)
    ip  = eth.data; dpkt_assert_L3(ip)
    l4  = ip.data;  dpkt_assert_L4_ports(l4)
    return (ip.dst, l4.dport)

def dpkt_set_IPs(pkt, src, dst):
    eth = dpkt.ethernet.Ethernet(pkt)
    ip  = eth.data; dpkt_assert_L3(ip)
    ip.src = src
    ip.dst = dst
    return str(eth)

def dpkt_fix_checksums(pkt):
    try:
        eth = dpkt.ethernet.Ethernet(pkt)
        ip  = eth.data
        ip.sum = 0
        if type(ip.data) in (dpkt.tcp.TCP, dpkt.udp.UDP):
            psdhdr = ip.src + ip.dst + struct.pack('!HH', ip.p, ip.len-20)
            ip.data.sum = 0
            ip.data.sum = dpkt.in_cksum(psdhdr + str(ip.data))

        padding = pkt[len(eth):]
        pkt = str(eth) + padding
    except:
        logging.exception('')
    return pkt


#------------------------------------------------------------------------------

class PcapReciever(DatagramProtocol):
    def datagramReceived(self, data, (host, port)):
        logging.debug('UDP received %d bytes from %s:%d' % (len(data), host, port))
        if len(data) > 64000: # basic attack prevention, skip huge blobs of data
            logging.error('Big Data problem!')
        else:
            try:    process_packet(data)
            except: logging.exception('')


def signal_handler(signal, frame):
    logging.info('Interrupted, shutting down')
    for k in list(queue.iterkeys()): # make a copy of the keys here
        queue[k].finalize()
    reactor.stop()


def main():
    global PCAPD_BASEDIR, VERBOSE

    argp = argparse.ArgumentParser(description='Juniper SRX IDP packet capture receiver')
    argp.add_argument('-p', metavar='port', default=PCAPD_PORT, type=int,
                            help='port to listen for incoming UDP connections (default: %d)' % PCAPD_PORT)
    argp.add_argument('-o', metavar='out_dir', default=PCAPD_BASEDIR,
                            help='path to store received pcaps (default: \'%s\')' % PCAPD_BASEDIR)
    argp.add_argument('-f', metavar='pcapfile', help='process an offline DMI pcap file')
    argp.add_argument('-v', action='count', default=0, help='be verbose (-vv = be super verbose)')
    try:
        args = argp.parse_args()
    except IOError, msg:
        argp.error(str(msg))

    PCAPD_BASEDIR = args.o
    logging.basicConfig(level=(logging.INFO if args.v==0 else logging.DEBUG),
                        format='[%(levelname)s] %(message)s')
    VERBOSE = args.v

    if not args.f:
        signal.signal(signal.SIGINT, signal_handler)
        logging.info('Starting server on port %d' % args.p)
        reactor.listenUDP(args.p, PcapReciever())
        reactor.run()
    else:
        try:
            with open(args.f, 'rb') as f:
                for i, (ts,p) in enumerate(dpkt.pcap.Reader(f).readpkts()):
                    try:
                        if VERBOSE > 1:
                            logging.debug('\n=========== packet %d ===========' % i)
                        process_packet(dpkt_get_udp_payload(p))
                    except:
                        logging.exception('')

            for k in list(queue.iterkeys()):
                queue[k].finalize()  # finalize the hanging timers

        except IOError, msg:
            print 'IOError:\n%s' % str(msg)
            sys.exit(-1)

if __name__ == '__main__':
    main()
