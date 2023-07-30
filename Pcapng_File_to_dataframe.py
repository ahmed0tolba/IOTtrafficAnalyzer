import pyshark
import pandas as pd
# import json

ip_mac = []

def resolve_mac(ip):
    mac = []



def pcapng_file_to_dataframe(file_name,iot_ip):
    columns_names = ["src_ip","dst_ip","src_prt","dst_prt","src_mac","dst_mac","protocol","packet_length","data_length","sniff_timestamp","tcp_seq_num","tcp_nxt_seq_num","tcp_ack_num","ttl","tcp_flag"]
    packets_df = pd.DataFrame(columns=columns_names) 
    
    # packets_iot = pyshark.FileCapture(file_name, display_filter="ip.addr == "+ iot_ip)
    packets_iot = pyshark.FileCapture(file_name)
    
    # numberOf_Packets = len([packet for packet in packets_iot]) # number of packets to device
    # with pd.option_context('display.max_rows', None,
    #                    'display.max_columns', None,
    #                    'display.precision', 3,
    #                    ):
    #     print("packets_iot" , packets_iot)
    idy = 0
    for packet in packets_iot:
        packet_length = int(packet.length)
        data_length = -1
        sniff_timestamp = float(packet.sniff_timestamp)
        dst_mac = ""
        src_mac = ""
        dst_ip = ""
        src_ip = ""
        src_prt = -1
        dst_prt = -1
        protocol = ""
        tcp_seq_num = -1
        tcp_nxt_seq_num = -1
        tcp_ack_num = -1
        ttl = -1
        tcp_flag = ""
        # if packet_length == 542:
        # print("time :  id : packet :" , sniff_timestamp ,  idy+1 , packet)

        for line in str(packet).splitlines():
            splits = str(line).split(":")
            # print("splits" ,splits ,len(splits))
            if len(splits) == 7:
                if splits[0] == "\tDestination":
                    dst_mac = ":".join(splits[1:])
                if splits[0] == "\tSource":
                    src_mac = ":".join(splits[1:])
            if len(splits) == 2:
                if splits[0] == "\tSource Address":
                    src_ip = splits[1].split(" ")[1]
                if splits[0] == "\tDestination Address":
                    dst_ip = splits[1].split(" ")[1]
                if splits[0] == "\tProtocol":
                    if splits[1].split(" ")[1] != "_http":
                        protocol = splits[1].split(" ")[1]
                if splits[0] == "\tXID Format":
                    protocol = "XID"  
                if splits[0] == "Layer EAPOL":
                    protocol = "EAPOL"
                if splits[0] == "Layer ARP":
                    protocol = "ARP"
                if splits[0] == "Layer DHCP":
                    protocol = "DHCP"  
                if splits[0] == "Layer COAP":
                    protocol = "COAP"  
                if splits[0] == "Layer MDNS":
                    protocol = "MDNS"  
                if splits[0] == "\tSource Port":
                    src_prt = int(splits[1].split("'")[0])
                if splits[0] == "\tDestination Port":
                    dst_prt = int(splits[1].split("'")[0])
                if splits[0] == "\tSequence Number":
                    tcp_seq_num = int(splits[1].split(" ")[1])
                if splits[0] == "\tNext Sequence Number":
                    tcp_nxt_seq_num = int(splits[1].split(" ")[1])
                if splits[0] == "\tAcknowledgment Number":
                    tcp_ack_num = int(splits[1].split(" ")[1])
                if splits[0] == "\tTime to Live":
                    ttl = int(splits[1].split(" ")[1])
                if splits[0] == "\tTotal Length":
                    data_length = int(splits[1].split(" ")[1])                
                if splits[0] == "\tFlags":
                    tcp_flag = int(splits[1].split(" ")[1].split("x")[1])
                
                        
        # print(packet_length)
        # print(data_length)
        # print(sniff_timestamp)        
        # print(dst_mac)
        # print(src_mac)
        # print(dst_ip)
        # print(src_ip)
        # print(src_prt)
        # print(dst_prt)
        # if protocol == "_http":
            # print(packet)
        # print(protocol)
        # print(tcp_seq_num)
        # print(tcp_nxt_seq_num)
        # print(tcp_ack_num)
        # break
        # if src_ip == "":

        # if dst_ip == "":
            
        packets_df.loc[idy] = [src_ip,dst_ip,src_prt,dst_prt,src_mac,dst_mac,protocol,packet_length,data_length,sniff_timestamp,tcp_seq_num,tcp_nxt_seq_num,tcp_ack_num,ttl,tcp_flag]
        # print(packets_df.loc[idy])
        idy += 1 
    packets_iot.close()
    # print(packets_iot[0])
    
    packets_df.to_csv(file_name+'-df.csv', index=False)

    IoT_mac = ""
    # identifying IoT mac
    cap_dst_df = packets_df[packets_df['dst_ip']==iot_ip]
    if len(cap_dst_df) > 0 :
        IoT_mac = cap_dst_df.iloc[0]["dst_mac"]
    else:        
        cap_src_df = packets_df[packets_df['src_ip']==iot_ip]
        if len(cap_src_df) > 0 :
            IoT_mac = cap_src_df.iloc[0]["src_mac"]
    
    if IoT_mac != "":
        packets_df.loc[ (packets_df.dst_ip == "") & (packets_df.dst_mac == IoT_mac), ['src_ip','dst_ip']] = ["Router","IoT"]
        packets_df.loc[ (packets_df.src_ip == "") & (packets_df.src_mac == IoT_mac), ['src_ip','dst_ip']] = ["IoT","Router"]
    
    packets_df.loc[ packets_df.dst_mac == " ff:ff:ff:ff:ff:ff", 'dst_ip'] = "Broadcast"
    packets_df.loc[ packets_df.src_mac == " ff:ff:ff:ff:ff:ff", 'src_ip'] = "Broadcast"

    packets_df.to_csv(file_name+'-df.csv', index=False)
    # print(packets_df)
    return packets_df


if __name__ == '__main__': 
  pcapng_file_to_dataframe(file_name="shelly plug s normal - idel - html view - no app - 201 packet 192.168.137.184.pcapng",iot_ip="192.168.137.184")
#   pcapng_file_to_dataframe(file_name="xiaomi lamp normal idel off no html app on no usage 114 packet 192.168.137.220.pcapng",iot_ip="192.168.137.220")