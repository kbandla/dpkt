import socket
import sys, os

sys.path.append(os.path.dirname(os.getcwd()))
from dpkt import cdp, ethernet, pcap

#test cdp packet sending if TEST_PACKET_SEND == True
#else test cdp pcap reading
TEST_PACKET_SEND = False

TEST_PCAP_READ = 'cdp.pcap'

INTERFACE = 'lo'
IP_INTERFACE = '192.168.1.103'

SRC_MAC = '\x00\x10\x7b\x78\x9a\xbc'
LLC = '\xaa\xaa\x03\x00\x00\x0c\x20\x00'
ETH_DEST = '\x01\x00\x0c\xcc\xcc\xcc'

def address_tlv():
    cdp_address = cdp.CDP.Address()
    cdp_address.data = socket.inet_aton(IP_INTERFACE)

    cdp_tlv = cdp.CDP.TLV(type=cdp.CDP_ADDRESS, data=cdp_address.pack())
    return cdp_tlv.pack()

def send_packet(lsocket):
    cdp_packet = cdp.CDP()

    cdp_tlv = cdp.CDP.TLV(type = cdp.CDP_DEVID, data = 'cisco')
    cdp_packet.data += cdp_tlv.pack()

    cdp_packet.data += address_tlv()

    ethernet_packet = ethernet.Ethernet(src=SRC_MAC, dst=ETH_DEST, type=len(LLC + cdp_packet.pack()), data=LLC + cdp_packet.pack())

    the_packet = ethernet_packet.pack()
    lsocket.send(the_packet)

def main():
    if TEST_PACKET_SEND:
        #test cdp packet sending
        lsocket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
        lsocket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, True)
        lsocket.bind((INTERFACE, 8192))
        send_packet(lsocket)
    else:
        #test cdp pcap reading
        #here test only Adresses field in cdp pcap
        f = open(TEST_PCAP_READ)
        the_pcap = pcap.Reader(f)

        for ts, buf in the_pcap:
            eth = ethernet.Ethernet(buf)
            address = cdp.CDP.Address(eth.data.data.data[1].data)
            print('Address numberadd : '+str(address.numberadd))
            print('Address ptype : '+str(address.ptype))
            print('Address plen : '+str(address.plen))
            print('Address p : '+str(address.p))
            print('Address alen : '+str(address.alen))
        f.close()

if __name__=='__main__':
    main()


