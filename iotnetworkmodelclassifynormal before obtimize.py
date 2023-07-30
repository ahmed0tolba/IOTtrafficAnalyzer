
# !pip install nest-asyncio
# import nest_asyncio
# nest_asyncio.apply()


# Installing pyshark as it is not by default in Colab
# !pip install pyshark
# !apt-get install -y libcap2-bin tshark
import pyshark
import os
# excel XLSX files writer
# !pip install XlsxWriter
# import progressbar

# resolve IoT server name
from tqdm import tqdm

import socket

resolved = []  ## [ip,translated,nameaddress]

def resolve_hostname(addr):
  # print(resolved)
  for i in resolved:
    if i[0] == addr:
      # print(addr, "in array" , type(addr))      
      return i[2] , i[1]
    
  # print(addr, "not in array" , type(addr))
      

  if socket.inet_aton(addr):
    try:
        name, _, _ = socket.gethostbyaddr(addr)
        translated = True
        resolved.append([addr,translated,name])
        return name , translated
    except socket.gaierror:
        # [Errno 8] nodename nor servname provided, or not known
        pass
    except socket.herror:
        # [Errno 1] Unknown host
        pass
    except socket.timeout:
        # Timeout.
        pass
    translated = False
    resolved.append([addr,translated,addr])
    return addr , translated
  else:
    raise ValueError('Invalid ip address.')
      

from math import inf
import xlsxwriter
import pandas as pd
from datetime import datetime
import socket
import csv
import numpy as np 
import statistics

# Input
# IOTIP --> the IP of the IOT device that is being analysed , ex : "10.42.0.15"
# studyFile --> the becap file containg the IOT device traffic , ex : "filename.pcapng"

# function I/O 
# analyseDeviceIP function --> Extract features representing the behaviour of IOT with the IP "IOTIP" from the file "studyFile" and store the traffic features in the output 2 excel files "studyFile.xlsx" & "studyFile.csv"

# Output
# 1- excel file with the name studyFile.xlsx 
# containing rows representing communications with each server
# 0 - IPS(Nameservers if available) connected to that iot (no unit) - IP layer
# 1 - Port on this Remote server (no unit) - TCP/UDP layer
# 2 - Protocol to this server (no unit) - IP layer
# 3 - Port on IOT (no unit) - TCP/UDP layer
# 4 - packets count received at IOT / sent to this server (packet count/ packet count) - IP layer
# 5 - average NumOfPackets from IOT to server Per Minute , (packet per minute) -  IP layer
# 6 - average NumOfPackets from server to IOT Per Minute , (packet per minute) -  IP layer
# 7 - average time to live from server to IOT (seconds) - IP layer
# 8 - flow volume (traffic volume) -> downloaded bytes + uploaded bytes from this server (bytes) - physical layer
# 9 - flow time -> cap file duration (seconds)
# 10 - average uploaded packet size from IOT to this server (bytes)
# 11 - average downloaded packet size from this server to IOT (bytes)
# 12 - flow rate -> flow volume / flow time -> uploaded bytes + downloades bytes for a specific server per minute (bytes per minute) - IP layer
# 13 - check if the server contacted by IOT has a name server
# 14 - average payload downloaded by IOT from server (bytes) - TCP UDP HTTP(application) layers  
# 15 - minimim payload downloaded by IOT from server (bytes) 
# 16 - maximum payload downloaded by IOT from server (bytes) 
# 17 - std standard deviation for payloads downloaded by IOT from server (bytes)
# 18 - average payload uploaded by IOT to server (bytes) 
# 19 - minimim payload uploaded by IOT to server (bytes) 
# 20 - maximum payload uploaded by IOT to server (bytes) 
# 21 - std standard deviation for payloads uploaded by IOT to server (bytes) 
# 22 - IP layer flags to IOT from this server (hex) - assume it was always the same throught the conversation (and it is not)
# 23 - IP layer flags from IOT to this server (hex) - assume it was always the same throught the conversation
# 24 - TCP layer flags to IOT from this server (hex) - assume it was always the same throught the conversation (and it is not)
# 25 - TCP layer flags from IOT to this server (hex) - assume it was always the same throught the conversation (and it is not)


def generate3rdFile(sourceData_df,dualComm_df):

  print("Processing file 3")
  # print(sourceData_df)
  # print(type(dualComm_df))
  # print(dualComm_df)

  sourceData_df['Req_packet_Lengths'] = 0 
  sourceData_df['Resp_packet_Lengths'] = 0
  sourceData_df['Req_packet_Payloads'] = 0
  sourceData_df['Resp_packet_Payloads'] = 0
  sourceData_df['Reqs_TTL'] = 0
  sourceData_df['Resps_time_min'] = 0
  sourceData_df['Resps_time_avg'] = 0 
  sourceData_df['Resps_time_max'] = 0
  sourceData_df['Repetitions'] = 0
  sourceData_df['Repetitions_per_minute'] = 0

  dataset_df = pd.DataFrame(columns=sourceData_df.columns) 
  for index_ref,row_ref in sourceData_df.iterrows():
    Dest_IP = row_ref['Dest_IP']  
    Dest_port_no = row_ref['Dest_port_no']  
    IoT_port_no = row_ref['IoT_port_no']  
    Protocol = row_ref['Protocol']  
    IsServer = row_ref['IsServer']  

    indexes_list_dualComm_df = dualComm_df.index[( ((dualComm_df['Src_IP'] == Dest_IP) & (dualComm_df['Src_Port'] == Dest_port_no) & (dualComm_df['Dst_port'] == IoT_port_no)) | ((dualComm_df['Dst_IP'] == Dest_IP) & (dualComm_df['Dst_port'] == Dest_port_no) & (dualComm_df['Src_Port'] == IoT_port_no)) ) & (dualComm_df['Protocol'] == Protocol) & (dualComm_df['IsServer'] == IsServer) ].tolist()
    for item in indexes_list_dualComm_df:
      dataset_df = pd.concat([dataset_df,sourceData_df.iloc[[index_ref]]])  
      dataset_df.iloc[-1, dataset_df.columns.get_loc('Req_packet_Lengths')] = dualComm_df.loc[item,'Req_packet_Length']
      dataset_df.iloc[-1, dataset_df.columns.get_loc('Resp_packet_Lengths')] = dualComm_df.loc[item,'Resp_packet_Length']
      dataset_df.iloc[-1, dataset_df.columns.get_loc('Req_packet_Payloads')] = dualComm_df.loc[item,'Req_packet_Payload'] 
      dataset_df.iloc[-1, dataset_df.columns.get_loc('Resp_packet_Payloads')] = dualComm_df.loc[item,'Resp_packet_Payload']
      dataset_df.iloc[-1, dataset_df.columns.get_loc('Reqs_TTL')] = dualComm_df.loc[item,'Req_TTL']
      dataset_df.iloc[-1, dataset_df.columns.get_loc('Resps_time_min')] = dualComm_df.loc[item,'Resp_time_min']
      dataset_df.iloc[-1, dataset_df.columns.get_loc('Resps_time_avg')] = dualComm_df.loc[item,'Resp_time_avg']
      dataset_df.iloc[-1, dataset_df.columns.get_loc('Resps_time_max')] = dualComm_df.loc[item,'Resp_time_max']
      dataset_df.iloc[-1, dataset_df.columns.get_loc('Repetitions')] = dualComm_df.loc[item,'Repetition']
      dataset_df.iloc[-1, dataset_df.columns.get_loc('Repetitions_per_minute')] = dualComm_df.loc[item,'Repetition_per_minute']

    # sourceData_df['Req_packet_Lengths'] = '_'.join(dualComm_df.loc[indexes_list_dualComm_df,'Req_packet_Length'].astype(str)) 
    # sourceData_df['Resp_packet_Lengths'] = '_'.join(dualComm_df.loc[indexes_list_dualComm_df,'Resp_packet_Length'].astype(str)) 
    # sourceData_df['Req_packet_Payloads'] = '_'.join(dualComm_df.loc[indexes_list_dualComm_df,'Req_packet_Payload'].astype(str)) 
    # sourceData_df['Resp_packet_Payloads'] = '_'.join(dualComm_df.loc[indexes_list_dualComm_df,'Resp_packet_Payload'].astype(str)) 
    # sourceData_df['Reqs_TTL'] = '_'.join(dualComm_df.loc[indexes_list_dualComm_df,'Req_TTL'].astype(str)) 
    # sourceData_df['Resps_time_min'] = '_'.join(dualComm_df.loc[indexes_list_dualComm_df,'Resp_time_min'].astype(str)) 
    # sourceData_df['Resps_time_avg'] = '_'.join(dualComm_df.loc[indexes_list_dualComm_df,'Resp_time_avg'].astype(str)) 
    # sourceData_df['Resps_time_max'] = '_'.join(dualComm_df.loc[indexes_list_dualComm_df,'Resp_time_max'].astype(str)) 
    # sourceData_df['Repetitions'] = '_'.join(dualComm_df.loc[indexes_list_dualComm_df,'Repetition'].astype(str)) 
    # sourceData_df['Repetitions_per_minute'] = '_'.join(dualComm_df.loc[indexes_list_dualComm_df,'Repetition_per_minute'].astype(str)) 
  return dataset_df


def analyseDeviceIP2(IOTIP,studyFile,device_type='',device_on=True,application_on=True,application_idel=True,attack_yes=True,attack_type='',alias_name='',scenario='',savename=''):

  sourceData_df_message = "1" # return message
  valid_ips = [] #
  invalid_ips = [] #  
  # create xlsx file , initialize xlsx column titles
  # if savename=='':
  #   workbook = xlsxwriter.Workbook(studyFile+'-In depth packet analysis.xlsx')
  # else:
  #   workbook = xlsxwriter.Workbook(savename+'-In depth packet analysis.xlsx')
  # worksheet = workbook.add_worksheet()
  # worksheet.write(0, 0,"Dest_IP")
  # worksheet.write(0, 1,"Dest_port_no")
  # worksheet.write(0, 2,"IoT_port_no")
  # worksheet.write(0, 3,"Protocol")
  # worksheet.write(0, 4,"Send_receive_ratio")
  
  # worksheet.write(0, 5,"No_of_received_packets_per_minutes") 
  # worksheet.write(0, 6,"No_of_sent_packets_per_minutes") 
  # worksheet.write(0, 7,"Avg_TTL")
  # worksheet.write(0, 8,"Flow_volume")
  # worksheet.write(0, 9,"Flow_duration")
  # worksheet.write(0, 10,"Dest_ip_avg_packet_length") 
  # worksheet.write(0, 11,"Src_ip_avg_packet_length")  
  # worksheet.write(0, 12,"Flow_rate")  
  # worksheet.write(0, 13,"IsServer")  
  # worksheet.write(0, 14,"Max_dest_SSL_payload")    #  avg14 min max16 ->  max14 min avg16   
  # worksheet.write(0, 15,"Min_dest_SSL_payload")  
  # worksheet.write(0, 16,"Avg_dest_SSL_payload")  
  # worksheet.write(0, 17,"Std_dest_SSL_payload")  
  # worksheet.write(0, 18,"Max_IoT_SSL_payload")    #  avg14 min max16 ->  max14 min avg16  
  # worksheet.write(0, 19,"Min_IoT_SSL_payload") 
  # worksheet.write(0, 20,"Avg_IoT_SSL_payload")   
  # worksheet.write(0, 21,"Std_IoT_SSL_payload")  

  # # worksheet.write(0, 22,"IP flags to IOT")      
  # # worksheet.write(0, 23,"IP flags from IOT")
  # worksheet.write(0, 22,"Dest_TCP_Flags")  
  # worksheet.write(0, 23,"IoT_TCP_Flags")  
  # # worksheet.write(0, 24,"device on")  
  # # worksheet.write(0, 25,"application on")  
  # # worksheet.write(0, 26,"application idle")  
  # # worksheet.write(0, 27,"attack yes")  
  # # worksheet.write(0, 28,"attack type")  
  # # worksheet.write(0, 29,"alias_name")  
  # # worksheet.write(0, 30,"device_type")  
  # # worksheet.write(0, 31,"scenario")  
  # ip address of server
  # boolean"device status on off"
  # boolean"mobile application on off"
  # boolean"attack yes no"
  # string"attack type" # DOS , 
  # End of initialize xlsx column titles, but file is still open
  
  # sleep time ??? 
  # cipher suit ???

  # excel 2
  # IP address of IOT 
  # mac address of IOT
  # alias name
  # FLOW CHART

  print(" warning: maybe analysing only first 100, because life is short")
  
  # column_names is a dataframe column title (not for excel but inside code)
  column_names = ["Dest_IP" , "Dest_port_no" , "IoT_port_no" , "Protocol", "Send_receive_ratio", "No_of_received_packets_per_minutes", "No_of_sent_packets_per_minutes", "Avg_TTL","Flow_volume","Flow_duration"
  , "Dest_ip_avg_packet_length" ,"Src_ip_avg_packet_length","Flow_rate","IsServer","Max_dest_SSL_payload","Min_dest_SSL_payload","Avg_dest_SSL_payload","Std_dest_SSL_payload","Max_IoT_SSL_payload","Min_IoT_SSL_payload"
                  ,"Avg_IoT_SSL_payload","Std_IoT_SSL_payload"
                  # ,"IP flags to IOT","IP flags from IOT"
                  ,"Dest_TCP_Flags","IoT_TCP_Flags"
                  ,"attack","attack type", "device type"
                  ]
  # print('Output is',column_names)
  
  # open studyfile and filter for destination IOT IP , neglect other devices on the network
  capdest = pyshark.FileCapture(studyFile, display_filter="ip.dst == "+ IOTIP
                                )                           
  numberOf_Packets = len([packet for packet in capdest]) # number of packets to device
  print("numberOf_Packets" , numberOf_Packets)
  if numberOf_Packets==0:
    sourceData_df_message= "invalid ip"
    print(sourceData_df_message)
    capdestips = pyshark.FileCapture(studyFile, display_filter="ip ")
    for packet in capdestips:
      if packet.ip.dst not in valid_ips and packet.ip.dst not in invalid_ips:
        if not resolve_hostname(packet.ip.dst)[1]:
          valid_ips.append(packet.ip.dst)
        else:
          invalid_ips.append(packet.ip.dst)
        
        
          print(valid_ips)
          print(invalid_ips)
    if savename=='':
      with open(studyFile+"-valid ips.csv", 'w') as f:
        for ip in valid_ips:
            f.write("%s\n"%(ip))
        for ip in invalid_ips:  
            f.write("%s\n"%(ip))
    else:
      with open(savename+"-valid ips.csv", 'w') as f:
        for ip in valid_ips:
            f.write("%s\n"%(ip))
        for ip in invalid_ips:  
            f.write("%s\n"%(ip))
    return [],[],sourceData_df_message,valid_ips
    
  package_duration_seconds = float(capdest[numberOf_Packets-1].sniff_timestamp) - float(capdest[0].sniff_timestamp) # capture duration in seconds , last package date - first package date
  package_duration_minutes = round(package_duration_seconds / 60,5) # file duration in minutes
  print("hi")
  idx = 0 
  idy = 0

  sourceData_df =  pd.DataFrame(columns = column_names) # dataframe table containing unique sets of [server IP , server port , protocol , IOTPort , and all the column_names ] that connected to device
  sourceData = []
  # progress bar
  # bar = progressbar.ProgressBar(maxval=numberOf_Packets, \widgets=[progressbar.Bar('=', '[', ']'), ' ', progressbar.Percentage()])
  # bar.start()
  # bar.update(0)

  sourceIPsSrcPortsProtocolDstPort=[]  # list containing unique sets of [server IP , server port , protocol , IOTPort] that connected to device - fyi: part of sourceData_df
  allPacketsSize = 0
  c1=1
  # widgets = ['Loading: ', progressbar.AnimatedMarker()]
  # bar = progressbar.ProgressBar(widgets=widgets).start()
  
  for packet in capdest: # looping on packets in pcabng file

    # bar update , if uncommented ofcorse
    c1+=1
    # bar.update(c1)
    # only 100 packet if uncommneted
    if c1>50:      
     break
    # print(c1 , " of " , numberOf_Packets , " for file 1")
    
    
    if (IOTIP.split(".")[:-1] != packet.ip.src.split(".")[:-1]) or True: # excluding local connections (if remove or true) , we are not excluding because we are attacking from access point
      
# 1 - Port on this Remote server (no unit) - TCP/UDP layer
# 3 - Port on IOT (no unit) - TCP/UDP layer
      if("TCP" in str(packet.layers)):
        srcport = packet.tcp.srcport
        dstport = packet.tcp.dstport
        srcportreqStr = "tcp.srcport"
        dstportreqStr = "tcp.dstport"
      elif ("UDP" in str(packet.layers)):
        srcport = packet.udp.srcport
        dstport = packet.udp.dstport
        srcportreqStr = "udp.srcport"
        dstportreqStr = "udp.dstport"
      else:
        continue
# end 1 & 3
      # print(packet)
      # IP_flag_from_IOT = -1

# 2 - Protocol to this server (no unit) - IP layer
      Protocol = packet.transport_layer
      if len(packet.layers)==3 and "TCP" in str(packet.layers):
        Protocol = "TCP"
      if "UDP" in str(packet.layers):
        Protocol = "UDP"
      if "SSL" in str(packet.layers):
        Protocol = "TCP"
      if "HTTP" in str(packet.layers):
        Protocol = "TCP"
# end of 2
      
      
      # checking if [server IP , server port , protocol , IOTPort] compination is not in sourceIPsSrcPortsProtocolDstPort , if not add a new row
      if [resolve_hostname(packet.ip.src)[0],srcport,packet.transport_layer,dstport] not in sourceIPsSrcPortsProtocolDstPort: 
        sourceIPsSrcPortsProtocolDstPort.append([resolve_hostname(packet.ip.src)[0],srcport,packet.transport_layer,dstport]) # add new serverIP+serverport+protocol+iotport to sourceIPsSrcPortsProtocolDstPort[]
        # acquring receive/send ratio by dividing receive count by send count from that IP+port+protocol
        cap_receivedIP = pyshark.FileCapture(studyFile, display_filter= # recieved packets from IP+..
                                      "ip.dst == " + IOTIP 
                                      + " and ip.src == " + packet.ip.src 
                                      + " and " + srcportreqStr + " == " + srcport 
                                      + " and ip.proto == " + packet.transport_layer  # 
                                      + " and " + dstportreqStr + " == " + dstport
                                      )
        NumOfPackets_ReceivedIP = len([packet1 for packet1 in cap_receivedIP]) # recieved packets from IP+.. count
        # print(NumOfPackets_ReceivedIP)
# 7 - average time to live from server to IOT (seconds) - IP layer
        avgTTL = round(sum([int(packet1['IP'].ttl) for packet1 in cap_receivedIP]) / NumOfPackets_ReceivedIP,2)
        
# 9 - flow time -> cap file duration (seconds)
        if NumOfPackets_ReceivedIP == 1 : 
          PacketsSize_RecievedIP_period = package_duration_seconds
        if NumOfPackets_ReceivedIP > 1 : 
          PacketsSize_RecievedIP_period = float(cap_receivedIP[NumOfPackets_ReceivedIP-1].sniff_timestamp) - float(capdest[0].sniff_timestamp)

# 8 (1) - flow volume (traffic volume) -> downloaded bytes + uploaded bytes from this server (bytes) - physical layer
        PacketsSize_RecievedIP = sum([float(packet1.captured_length) for packet1 in cap_receivedIP])  # downloaded bytes

# 11 - average downloaded packet size from this server to IOT (bytes)
        avg_PacketsSize_RecievedIP = round(PacketsSize_RecievedIP / NumOfPackets_ReceivedIP,2) 
        

# 14 - average payload downloaded by IOT from server (bytes) - TCP UDP HTTP(application) layers  
# 15 - minimim payload downloaded by IOT from server (bytes) 
# 16 - maximum payload downloaded by IOT from server (bytes) 
# 17 - std standard deviation for payloads downloaded by IOT from server (bytes)
# 22 - IP layer flags to IOT from this server (hex) - assume it was always the same throught the conversation (and it is not)
        IP_flag_to_IOT = float(str(cap_receivedIP[0].layers[1]).splitlines()[8].split("0x")[1].split(",")[0])
        ssl_layer_packekets_for_this_ip = 0 # counter for packets downloaded
        ssl_layer_packekets_for_this_ip_sum_ip = 0 # sum for packets downloaded
        TLS_length_min_Recieved_at_IOT = 0 # initial min value
        TLS_length_max_Recieved_at_IOT = 0 # initial max value
        TLS_length_std_Recieved_at_IOT = 0 # initial std value
        TLS_lengths_Recieved_at_IOT_list=[]
        c = 0
        for packet1 in cap_receivedIP:
          # print("c " , c)
          # print(packet1)
          # print(packet1.layers)
          if len(packet1.layers)==3 and "TCP" in str(packet1.layers): # case 1 : 3 layers only and one of them is called TCP
          # 24 - TCP layer flags to IOT from this server (hex) - assume it was always the same throught the conversation (and it is not)
            #print(packet1)
            if os.name == "nt":
              TCP_flag_to_IOT = float(str(packet1.layers[2]).splitlines()[12].split("0x")[1].split()[0]) 
            else:
              try:              
                TCP_flag_to_IOT = float(str(packet1.layers[2]).splitlines()[12].split("0x")[1].split()[0])
              except: 
                TCP_flag_to_IOT = -1
            # print("hi ",TCP_flag_to_IOT)          

            layer2lines = str(packet1.layers[2]).splitlines()
            
            if len(layer2lines)>41 :
              if len(layer2lines[41].split("(")[-1].split()) > 1 :
                if layer2lines[41].split("(")[-1].split()[1] == "bytes)":
                  ssl_layer_packekets_size = float(layer2lines[41].split("(")[-1].split()[0]) # payload is layer 3 line 42
                  ssl_layer_packekets_for_this_ip += 1
                  if c == 0:
                    TLS_length_min_Recieved_at_IOT = ssl_layer_packekets_size
                  c += 1
                  ssl_layer_packekets_for_this_ip_sum_ip += ssl_layer_packekets_size
                  TLS_lengths_Recieved_at_IOT_list.append(ssl_layer_packekets_size)
                  if TLS_length_min_Recieved_at_IOT > ssl_layer_packekets_size:
                    TLS_length_min_Recieved_at_IOT = ssl_layer_packekets_size
                  if TLS_length_max_Recieved_at_IOT < ssl_layer_packekets_size:
                    TLS_length_max_Recieved_at_IOT = ssl_layer_packekets_size



          if ("UDP" in str(packet1.layers)): # case 1 : contain a layer called TCP
            TCP_flag_to_IOT = float(str(packet1.layers[2]).splitlines()[3].split()[-1])
            ssl_layer_packekets_for_this_ip += 1
            ssl_layer_packekets_size = float(str(packet1.layers[2]).splitlines()[3].split()[-1]) # payload is layer 3 line 4
            if c == 0:
              TLS_length_min_Recieved_at_IOT = ssl_layer_packekets_size
            c += 1
            ssl_layer_packekets_for_this_ip_sum_ip += ssl_layer_packekets_size
            TLS_lengths_Recieved_at_IOT_list.append(ssl_layer_packekets_size)
            if TLS_length_min_Recieved_at_IOT > ssl_layer_packekets_size:
              TLS_length_min_Recieved_at_IOT = ssl_layer_packekets_size
            if TLS_length_max_Recieved_at_IOT < ssl_layer_packekets_size:
              TLS_length_max_Recieved_at_IOT = ssl_layer_packekets_size

          if "SSL" in str(packet1.layers) or "TLS" in str(packet1.layers) : # case 1 : contain a layer called SSL
            
            if os.name == "nt":
              TCP_flag_to_IOT = float(str(packet1.layers[2]).splitlines()[12].split("0x")[1].split()[0])  # 9 in colab
            else:
              try:
                TCP_flag_to_IOT = float(str(packet1.layers[2]).splitlines()[12].split("0x")[1].split()[0])  # 12 in ubuntu server
              except:
                TCP_flag_to_IOT = -1 
            
            ssl_layer_packekets_for_this_ip += 1
            # if len(packet1.layers)>4:
            #   print(packet1)
            #   print(packet1.layers)
            #   print(str(packet1.layers[-1]).splitlines()[4])
            found = False
            if len(packet1.layers)==6:
              if len(str(packet1.layers[5]).splitlines())>4:
                
                ssl_layer_packekets_size = float(str(packet1.layers[5]).splitlines()[4].split()[-1])  # payload is layer 4 line 5
                found = True
            if len(packet1.layers)==5 and not found:
              if len(str(packet1.layers[4]).splitlines())>4:
                ssl_layer_packekets_size = float(str(packet1.layers[4]).splitlines()[4].split()[-1])  # payload is layer 4 line 5
                found = True
            if len(packet1.layers)==4 and not found:
              if len(str(packet1.layers[3]).splitlines())>4:
                ssl_layer_packekets_size = float(str(packet1.layers[3]).splitlines()[4].split()[-1])  # payload is layer 4 line 5
                found = True
            
            if c == 0:
              TLS_length_min_Recieved_at_IOT = ssl_layer_packekets_size
            c += 1
            ssl_layer_packekets_for_this_ip_sum_ip += ssl_layer_packekets_size
            TLS_lengths_Recieved_at_IOT_list.append(ssl_layer_packekets_size)
            if TLS_length_min_Recieved_at_IOT > ssl_layer_packekets_size:
              TLS_length_min_Recieved_at_IOT = ssl_layer_packekets_size
            if TLS_length_max_Recieved_at_IOT < ssl_layer_packekets_size:
              TLS_length_max_Recieved_at_IOT = ssl_layer_packekets_size

          if ("HTTP" in str(packet1.layers)):  # case 1 : contain a layer called HTTP
            layer2lines = str(packet1.layers[2]).splitlines()
            # print("1")
            # print(packet1.layers)
            # print(layer2lines[45])
            if len(layer2lines)>44 :
              
              if len(layer2lines[45].split("(")[-1].split()) > 1 :
                if layer2lines[45].split("(")[-1].split()[1] == "bytes)":
                  ssl_layer_packekets_size = float(layer2lines[45].split("(")[-1].split()[0]) # payload is layer 3 line 45
                  # print(ssl_layer_packekets_size)
                  ssl_layer_packekets_for_this_ip += 1
                  if c == 0:
                    TLS_length_min_Recieved_at_IOT = ssl_layer_packekets_size
                  c += 1
                  ssl_layer_packekets_for_this_ip_sum_ip += ssl_layer_packekets_size
                  TLS_lengths_Recieved_at_IOT_list.append(ssl_layer_packekets_size)
                  if TLS_length_min_Recieved_at_IOT > ssl_layer_packekets_size:
                    TLS_length_min_Recieved_at_IOT = ssl_layer_packekets_size
                  if TLS_length_max_Recieved_at_IOT < ssl_layer_packekets_size:
                    TLS_length_max_Recieved_at_IOT = ssl_layer_packekets_size
            

        if ssl_layer_packekets_for_this_ip > 0:
          TLS_length_avg_Recieved_at_IOT = round(float(ssl_layer_packekets_for_this_ip_sum_ip) / float(ssl_layer_packekets_for_this_ip),2) # avg
          if len(TLS_lengths_Recieved_at_IOT_list)>1: # std can't be calculated for less than 1
            TLS_length_std_Recieved_at_IOT = round(statistics.stdev(TLS_lengths_Recieved_at_IOT_list),2) # std
        else:
          TLS_length_avg_Recieved_at_IOT = 0
# end of 14 - 15 - 16 - 17        

        if (NumOfPackets_ReceivedIP==1):
          if package_duration_minutes!=0:
            avg_NumOfPackets_RecievedIP_PerMinute = round(1 / package_duration_minutes,2)
          else:
            avg_NumOfPackets_RecievedIP_PerMinute = 100
        elif (NumOfPackets_ReceivedIP==0):
          avg_NumOfPackets_RecievedIP_PerMinute = 0 
        else:          
# 6 - average NumOfPackets from server to IOT Per Minute , (packet per minute) -  IP layer
          # avg_NumOfPackets_RecievedIP_PerMinute = round(float(NumOfPackets_ReceivedIP) / package_duration_minutes,2)
          avg_NumOfPackets_RecievedIP_PerMinute = round(float(NumOfPackets_ReceivedIP-1) / (float(cap_receivedIP[NumOfPackets_ReceivedIP-1].sniff_timestamp) - float(cap_receivedIP[0].sniff_timestamp)) * 60,2)
        

        ## going to stranger - upload
        cap_Sent2IP = pyshark.FileCapture(studyFile, display_filter= # sent packets to IP+.. 
                                      "ip.src == " + IOTIP 
                                      + " and ip.dst == " + packet.ip.src 
                                      + " and " + srcportreqStr + " == " + dstport
                                      + " and ip.proto == " + packet.transport_layer # 
                                      + " and " + dstportreqStr + " == " + srcport
                                      )
        NumOfPackets_Sent2IP = len([packet1 for packet1 in cap_Sent2IP]) # sent packets to IP+.. count      
        # if (NumOfPackets_Sent2IP == 0):
        #   NumOfPackets_Sent2IP = 0.0001

        
        if NumOfPackets_Sent2IP == 0 :
          receiveSend_RatioIP = -1 # float('inf')
        elif (NumOfPackets_Sent2IP!=1):       
# 4 - packets count received at IOT / sent to this server (packet count/ packet count) - IP layer  
          receiveSend_RatioIP =  round(NumOfPackets_ReceivedIP / NumOfPackets_Sent2IP,2) # receive send ratio
        else:
          receiveSend_RatioIP = 1


        
        if NumOfPackets_Sent2IP != 0 :
          if NumOfPackets_Sent2IP == 1:
            PacketsSize_Sent2IP_period_seconds = package_duration_seconds
          if NumOfPackets_Sent2IP > 1:
            PacketsSize_Sent2IP_period_seconds = float(cap_Sent2IP[NumOfPackets_Sent2IP-1].sniff_timestamp) - float(cap_Sent2IP[0].sniff_timestamp)
# 8 (2)- flow volume (traffic volume) -> downloaded bytes + uploaded bytes from this server (bytes) - physical layer
          PacketsSize_Sent2IP = sum([float(packet1.captured_length) for packet1 in cap_Sent2IP])   # uploaded bytes
# 10 - average uploaded packet size from IOT to this server (bytes)
          avg_PacketsSize_Sent2IP = round(PacketsSize_Sent2IP / NumOfPackets_Sent2IP,2)
        else:
          PacketsSize_Sent2IP_period_seconds = 0
          PacketsSize_Sent2IP = 0
          avg_PacketsSize_Sent2IP = 0
        if NumOfPackets_Sent2IP > 1 :         
          PacketsSize_Sent2IP_period_seconds = float(cap_Sent2IP[NumOfPackets_Sent2IP-1].sniff_timestamp) - float(cap_Sent2IP[0].sniff_timestamp)

# 12 - flow rate -> flow volume / flow time -> uploaded bytes + downloades bytes for a specific server per minute (bytes per minute) - IP layer        
        if PacketsSize_Sent2IP_period_seconds != 0 :
          flowrate = round(float(PacketsSize_Sent2IP + PacketsSize_RecievedIP) / float(PacketsSize_Sent2IP_period_seconds),2)
        else:
          flowrate = PacketsSize_Sent2IP + PacketsSize_RecievedIP

# 22 - IP layer flags to IOT from this server (hex) - assume it was always the same throught the conversation (and it is not)
        IP_flag_from_IOT = float(str(packet1.layers[1]).splitlines()[8].split("0x")[1].split(",")[0])

# 18 - average payload uploaded by IOT to server (bytes) 
# 19 - minimim payload uploaded by IOT to server (bytes) 
# 20 - maximum payload uploaded by IOT to server (bytes) 
# 21 - std standard deviation for payloads uploaded by IOT to server (bytes) 
        ssl_layer_packekets_from_this_ip = 0 
        ssl_layer_packekets_from_this_ip_sum_ip = 0
        TLS_length_min_Sent_From_IOT = 0
        TLS_length_max_Sent_From_IOT = 0
        TLS_length_std_Sent_From_IOT = 0
        TLS_lengths_list_From_IOT=[]
        c = 0
        TCP_flag_from_IOT = -1
        for packet1 in cap_Sent2IP:
          # print(packet1)

          if len(packet1.layers)==3 and "TCP" in str(packet1.layers):
# 25 - TCP layer flags from IOT to this server (hex) - assume it was always the same throught the conversation (and it is not)            
            if os.name == "nt":
              TCP_flag_from_IOT = float(str(packet1.layers[2]).splitlines()[12].split("0x")[1].split()[0])
            else:
              try:
                TCP_flag_from_IOT = float(str(packet1.layers[2]).splitlines()[12].split("0x")[1].split()[0]) # 9 in colab
              except:
                TCP_flag_from_IOT = -1
            layer2lines = str(packet1.layers[2]).splitlines()
            # print(len(layer2lines))

            if len(layer2lines)>41 :
              if len(layer2lines[41].split("(")) > 1:
                if len(layer2lines[41].split("(")[-1].split()) > 1 :
                  if layer2lines[41].split("(")[-1].split()[1] == "bytes)":
                    ssl_layer_packekets_size = float(layer2lines[41].split("(")[-1].split()[0]) # payload is layer 3 line 42
                    # print(ssl_layer_packekets_size)
                    ssl_layer_packekets_from_this_ip += 1
                    if c == 0:
                      TLS_length_min_Sent_From_IOT = ssl_layer_packekets_size
                    c += 1
                    ssl_layer_packekets_from_this_ip_sum_ip += ssl_layer_packekets_size
                    TLS_lengths_list_From_IOT.append(ssl_layer_packekets_size)
                    if TLS_length_min_Sent_From_IOT > ssl_layer_packekets_size:
                      TLS_length_min_Sent_From_IOT = ssl_layer_packekets_size
                    if TLS_length_max_Sent_From_IOT < ssl_layer_packekets_size:
                      TLS_length_max_Sent_From_IOT = ssl_layer_packekets_size
         


          if ("UDP" in str(packet1.layers)):
            ssl_layer_packekets_from_this_ip += 1
            ssl_layer_packekets_size = float(str(packet1.layers[2]).splitlines()[3].split()[-1])
            if c == 0:
              TLS_length_min_Sent_From_IOT = ssl_layer_packekets_size
            c += 1
            ssl_layer_packekets_from_this_ip_sum_ip += ssl_layer_packekets_size
            TLS_lengths_list_From_IOT.append(ssl_layer_packekets_size)
            if TLS_length_min_Sent_From_IOT > ssl_layer_packekets_size:
              TLS_length_min_Sent_From_IOT = ssl_layer_packekets_size
            if TLS_length_max_Sent_From_IOT < ssl_layer_packekets_size:
              TLS_length_max_Sent_From_IOT = ssl_layer_packekets_size

          if "SSL" in str(packet1.layers) or "TLS" in str(packet1.layers) :   
            if os.name == "nt":
              TCP_flag_from_IOT = float(str(packet1.layers[2]).splitlines()[12].split("0x")[1].split()[0]) # 9 in colab
            else:
              try :
                TCP_flag_from_IOT = float(str(packet1.layers[2]).splitlines()[12].split("0x")[1].split()[0]) # 9 in colab , 12 in ubuntu server
              except:
                TCP_flag_from_IOT = -1

            ssl_layer_packekets_from_this_ip += 1
            ssl_layer_packekets_size = float(str(packet1.layers[3]).splitlines()[4].split()[-1])
            if c== 0 :
              TLS_length_min_Sent_From_IOT = ssl_layer_packekets_size
            c +=1
            ssl_layer_packekets_from_this_ip_sum_ip += ssl_layer_packekets_size
            TLS_lengths_list_From_IOT.append(ssl_layer_packekets_size)
            if TLS_length_min_Sent_From_IOT > ssl_layer_packekets_size:
              TLS_length_min_Sent_From_IOT = ssl_layer_packekets_size
            if TLS_length_max_Sent_From_IOT < ssl_layer_packekets_size:
              TLS_length_max_Sent_From_IOT = ssl_layer_packekets_size

          if ("HTTP" in str(packet1.layers)):
            
            layer2lines = str(packet1.layers[2]).splitlines()
            # print(packet1)
            # print(packet1.layers)
          
            if len(layer2lines)>45 :
              payloadline = 45
            else:
              payloadline = 41

            if len(packet1.layers)==6:
              payloadline = 38

            # print(layer2lines[payloadline])

            if len(layer2lines[payloadline].split("(")[-1].split()) > 1 :
              if layer2lines[payloadline].split("(")[-1].split()[1] == "bytes)":
                ssl_layer_packekets_size = float(layer2lines[payloadline].split("(")[-1].split()[0])

                ssl_layer_packekets_from_this_ip += 1
                if c == 0:
                  TLS_length_min_Recieved_from_IOT = ssl_layer_packekets_size
                c += 1
                ssl_layer_packekets_from_this_ip_sum_ip += ssl_layer_packekets_size
                TLS_lengths_list_From_IOT.append(ssl_layer_packekets_size)
                if TLS_length_min_Sent_From_IOT > ssl_layer_packekets_size:
                  TLS_length_min_Sent_From_IOT = ssl_layer_packekets_size
                if TLS_length_max_Sent_From_IOT < ssl_layer_packekets_size:
                  TLS_length_max_Sent_From_IOT = ssl_layer_packekets_size
              
                    
        if ssl_layer_packekets_from_this_ip>0:
          TLS_length_avg_Sent_From_IOT = round(float(ssl_layer_packekets_from_this_ip_sum_ip) / float(ssl_layer_packekets_from_this_ip),2)
          if len(TLS_lengths_list_From_IOT)>1:
            TLS_length_std_Sent_From_IOT = round(statistics.stdev(TLS_lengths_list_From_IOT),2)
        else:
          TLS_length_avg_Sent_From_IOT = 0
# end of 18 - 19 - 20 - 21    
        
        if NumOfPackets_Sent2IP == 0 :
          avg_NumOfPackets_Sent2IP_PerMinute = 0
        elif (NumOfPackets_Sent2IP==1):      
# 5 - average NumOfPackets from IOT to server Per Minute , (packet per minute) -  IP layer     
          # avg_NumOfPackets_Sent2IP_PerMinute = round(NumOfPackets_Sent2IP / (float(cap_Sent2IP[NumOfPackets_Sent2IP-1].sniff_timestamp) - float(cap_Sent2IP[0].sniff_timestamp)) * 60,2)
          avg_NumOfPackets_Sent2IP_PerMinute = round(NumOfPackets_Sent2IP / package_duration_minutes,2)
        elif (NumOfPackets_Sent2IP>1):      
          avg_NumOfPackets_Sent2IP_PerMinute = round((NumOfPackets_Sent2IP-1) / (float(cap_Sent2IP[NumOfPackets_Sent2IP-1].sniff_timestamp) - float(cap_Sent2IP[0].sniff_timestamp)) * 60,2)
        else:
          avg_NumOfPackets_Sent2IP_PerMinute = 1
        
        
        if [resolve_hostname(packet.ip.src)[0] , srcport , packet.transport_layer , dstport,receiveSend_RatioIP,avg_NumOfPackets_Sent2IP_PerMinute,avg_NumOfPackets_RecievedIP_PerMinute,avgTTL,avg_PacketsSize_Sent2IP,avg_PacketsSize_RecievedIP] not in sourceData: # if pattern not in sourceData
          sourceData.append([resolve_hostname(packet.ip.src)[0] , srcport , packet.transport_layer , dstport, receiveSend_RatioIP,avg_NumOfPackets_Sent2IP_PerMinute,avg_NumOfPackets_RecievedIP_PerMinute,avgTTL,avg_PacketsSize_Sent2IP,avg_PacketsSize_RecievedIP]) # add pattern to sourceData
          
          if attack_yes and  receiveSend_RatioIP == -1: #  not resolve_hostname(packet.ip.src)[1] and
            attack_yes_processed = 1
            attack_type = "reconnaissance"
          else:
            attack_yes_processed = 0

          if attack_yes_processed:
            attack_type_processed = attack_type
          else:
            attack_type_processed = ""

          sourceData_df.loc[idy] = [resolve_hostname(packet.ip.src)[0] , srcport  , dstport, packet.transport_layer, receiveSend_RatioIP,avg_NumOfPackets_Sent2IP_PerMinute,
                                    avg_NumOfPackets_RecievedIP_PerMinute,avgTTL,PacketsSize_Sent2IP + PacketsSize_RecievedIP,round(PacketsSize_Sent2IP_period_seconds,2),
                                    avg_PacketsSize_Sent2IP,avg_PacketsSize_RecievedIP,
                                    flowrate,resolve_hostname(packet.ip.src)[1],
                                    TLS_length_max_Recieved_at_IOT,TLS_length_min_Recieved_at_IOT,TLS_length_avg_Recieved_at_IOT,TLS_length_std_Recieved_at_IOT,
                                    TLS_length_max_Sent_From_IOT,TLS_length_min_Sent_From_IOT,TLS_length_avg_Sent_From_IOT,TLS_length_std_Sent_From_IOT,
                                    # IP_flag_to_IOT,IP_flag_from_IOT,
                                    IP_flag_to_IOT,IP_flag_from_IOT,
                                    attack_yes_processed,attack_type_processed,device_type
                                    ] # add pattern to sourceData
          # store values in the xlsx rows
          idy+=1 # row number # all servers counter
#           worksheet.write(idy, 0,resolve_hostname(packet.ip.src)[0])
#           worksheet.write(idy, 1,srcport)
#           worksheet.write(idy, 2,packet.transport_layer)
#           worksheet.write(idy, 3,dstport)
          
#           if (receiveSend_RatioIP != float('inf')):
#             worksheet.write(idy, 4,receiveSend_RatioIP)
#           else:
#             worksheet.write(idy, 4,"inf")

#           if (avg_NumOfPackets_Sent2IP_PerMinute != float('inf')):
#             worksheet.write(idy, 5,avg_NumOfPackets_Sent2IP_PerMinute)
#           else:
#             worksheet.write(idy, 5,"inf")
#           worksheet.write(idy, 6,avg_NumOfPackets_RecievedIP_PerMinute)

#           worksheet.write(idy, 7,avgTTL)
          
#           worksheet.write(idy, 8,PacketsSize_Sent2IP + PacketsSize_RecievedIP)
#           worksheet.write(idy, 9,package_duration_minutes)

#           worksheet.write(idy, 10,avg_PacketsSize_Sent2IP)
#           worksheet.write(idy, 12,avg_PacketsSize_RecievedIP)
          
#           worksheet.write(idy, 12,flowrate)

# # 13 - check if the server contacted by IOT has a name server
#           worksheet.write(idy, 13,resolve_hostname(packet.ip.src)[1])

#           worksheet.write(idy, 14,TLS_length_avg_Recieved_at_IOT)
#           worksheet.write(idy, 15,TLS_length_min_Recieved_at_IOT)
#           worksheet.write(idy, 16,TLS_length_max_Recieved_at_IOT)
#           worksheet.write(idy, 17,TLS_length_std_Recieved_at_IOT)

#           worksheet.write(idy, 18,TLS_length_avg_Sent_From_IOT)
#           worksheet.write(idy, 19,TLS_length_min_Sent_From_IOT)
#           worksheet.write(idy, 20,TLS_length_max_Sent_From_IOT)
#           worksheet.write(idy, 21,TLS_length_std_Sent_From_IOT)
#           # worksheet.write(idy, 22,IP_flag_to_IOT)
#           # worksheet.write(idy, 23,IP_flag_from_IOT)
#           worksheet.write(idy, 22,TCP_flag_to_IOT)
#           worksheet.write(idy, 23,TCP_flag_from_IOT)

#           # worksheet.write(idy, 26,device_on)
#           # worksheet.write(idy, 27,application_on)
#           # worksheet.write(idy, 28,application_idel)
#           # worksheet.write(idy, 29,attack_yes_processed)
#           # worksheet.write(idy, 30,attack_type_processed)
      idx+=1
#   workbook.close()
  # close the xlsx file
  if savename=='':
    sourceData_df.to_csv(studyFile+'-In depth packet analysis.csv',index=False)
  else:
    sourceData_df.to_csv(savename+'-In depth packet analysis.csv',index=False)
    
# 2-1 'all_packets_recieved_per_minute': average total number of packets recieved(downloaded) at IOT from all connections per minute
  if (numberOf_Packets == 0):
    all_packets_recieved_per_minute =0
  elif (numberOf_Packets == 1):
    all_packets_recieved_per_minute =1
  else:
    all_packets_recieved_per_minute = round(numberOf_Packets / (float(capdest[numberOf_Packets-1].sniff_timestamp) - float(capdest[0].sniff_timestamp)) * 60,2)

# 2-2 'initialized_tcp_per_minute': average number of initialized tcp connections per minute
  packets_initialize_tcp = pyshark.FileCapture(studyFile, display_filter= # sent packets to IP+.. 
                                      "ip.dst == " + IOTIP 
                                      + " and tcp.flags.syn == 1 "
                                      + " and tcp.flags.ack == 0 "
                                      )
  numberOf_packets_initialize_tcp = len([packet for packet in packets_initialize_tcp]) # number of packets to device


  if (numberOf_packets_initialize_tcp == 0):
    initialized_tcp_per_minute = 0
  elif (numberOf_packets_initialize_tcp == 1):
    initialized_tcp_per_minute = 1
  else:
    initialized_tcp_per_minute = round((numberOf_packets_initialize_tcp-1) / (float(packets_initialize_tcp[numberOf_packets_initialize_tcp-1].sniff_timestamp) - float(packets_initialize_tcp[0].sniff_timestamp)) * 60,2)
  
  # 2-3 'tcp_reset': number of TCP reset packages
  packets_tcp_reset = pyshark.FileCapture(studyFile, display_filter= # sent packets to IP+.. 
                                      "ip.src == " + IOTIP 
                                      + " and tcp.flags.reset == 1 "
                                      )
  numberOf_packets_tcp_reset = len([packet for packet in packets_tcp_reset]) # number of packets to device
   

# 2-12 'dns req': average number of dns requests per minute
  packets_dns_req = pyshark.FileCapture(studyFile, display_filter= # sent packets to IP+.. 
                                      "ip.src == " + IOTIP 
                                      + " and dns "
                                      )
  numberOf_packets_dns_req = len([packet for packet in packets_dns_req]) # number of packets to device

  if (numberOf_packets_dns_req == 0):
    packets_dns_req_per_minute =0
  elif (numberOf_packets_dns_req == 1):
    packets_dns_req_per_minute =1
  else:
    packets_dns_req_per_minute = round((numberOf_packets_dns_req-1) / (float(packets_dns_req[numberOf_packets_dns_req-1].sniff_timestamp) - float(capdest[0].sniff_timestamp)) * 60,2)

# 2-13 'dns resp': average number of dns responds per minute
  packets_dns_resp = pyshark.FileCapture(studyFile, display_filter= # sent packets to IP+.. 
                                      "ip.dst == " + IOTIP 
                                      + " and dns "
                                      )
  numberOf_packets_dns_resp = len([packet for packet in packets_dns_resp]) # number of packets to device

  if (numberOf_packets_dns_resp == 0):
    packets_dns_resp_per_minute =0
  elif (numberOf_packets_dns_resp == 1):
    packets_dns_resp_per_minute =1
  else:
    packets_dns_resp_per_minute = round((numberOf_packets_dns_resp-1) / (float(packets_dns_resp[numberOf_packets_dns_resp-1].sniff_timestamp) - float(capdest[0].sniff_timestamp)) * 60,2)
# 2-14 'ntp req': average number of ntp requests per minute
  packets_ntp_req = pyshark.FileCapture(studyFile, display_filter= # sent packets to IP+.. 
                                      "ip.src == " + IOTIP 
                                      + " and ntp "
                                      )
  numberOf_packets_ntp_req = len([packet for packet in packets_ntp_req]) # number of packets to device
  if (numberOf_packets_ntp_req == 0):
    packets_ntp_req_per_minute =0
  elif (numberOf_packets_ntp_req == 1):
    packets_ntp_req_per_minute =1
  else:
    packets_ntp_req_per_minute = round((numberOf_packets_ntp_req-1) / (float(packets_ntp_req[numberOf_packets_ntp_req-1].sniff_timestamp) - float(capdest[0].sniff_timestamp)) * 60,2)

# 2-15 'ntp resp': average number of ntp responds per minute
  packets_ntp_resp = pyshark.FileCapture(studyFile, display_filter= # sent packets to IP+.. 
                                      "ip.dst == " + IOTIP 
                                      + " and ntp "
                                      )
  numberOf_packets_ntp_resp = len([packet for packet in packets_ntp_resp]) # number of packets to device

  if (numberOf_packets_ntp_resp == 0):
    packets_ntp_resp_per_minute =0
  elif (numberOf_packets_ntp_resp == 1):
    packets_ntp_resp_per_minute =1
  else:
    packets_ntp_resp_per_minute = round((numberOf_packets_ntp_resp-1) / (float(packets_ntp_resp[numberOf_packets_ntp_resp-1].sniff_timestamp) - float(capdest[0].sniff_timestamp)) * 60,2)

  # remote_IPs_TCP = 
  # remote_IPs_UDP = sourceData_df.loc[sourceData_df['Protocoled']=='TCP']
  remote_Ports_TCP =[]
  remote_Ports_UDP =[]
  device_Ports_TCP =[]
  device_Ports_UDP =[]
  device_Recieved_Data_TCP = []
  device_Sent_Data_TCP = []
  device_Recieved_Data_UDP = []
  device_Sent_Data_UDP = []
  
  attack_yes_summary = 0
  attack_type_summary = ""

  if numberOf_packets_tcp_reset > 2 and initialized_tcp_per_minute < 10:
    attack_yes_summary = 1
    attack_type_summary = "reconnaissance"
  
  device_Ports_irresponsive = len(sourceData_df.loc[sourceData_df['Send_receive_ratio']==inf]['IoT_port_no'].value_counts())

  if device_Ports_irresponsive > 0:
    attack_yes_summary = 1
    attack_type_summary = "reconnaissance"

  if initialized_tcp_per_minute > 10:
    attack_yes_summary = 1
    attack_type_summary = "DOS"

  overall_analysis = {
    "Sum_of_all_packets":  all_packets_recieved_per_minute,
    "No_TCP_handshake": initialized_tcp_per_minute ,
    "TCP_reset": numberOf_packets_tcp_reset ,
    "No_of_IP_servers": len(sourceData_df.loc[sourceData_df['IsServer']==True]['Dest_IP'].value_counts()),
    "No_of_TCP_connection": len(sourceData_df.loc[sourceData_df['Protocol']=='TCP']['Dest_IP'].value_counts()),  # number of IPS that estaplish TCP  
    "No_UDP_connection": len(sourceData_df.loc[sourceData_df['Protocol']=='UDP']['Dest_IP'].value_counts()),  # number of IPS that estaplish UDP 
    "No_of_Dest_TCP_ports": len(sourceData_df.loc[sourceData_df['Protocol']=='TCP']['Dest_port_no'].value_counts()),
    "No_IoT_TCP_ports": len(sourceData_df.loc[sourceData_df['Protocol']=='TCP']['IoT_port_no'].value_counts()),
    "No_of_Dest_UDP_ports": len(sourceData_df.loc[sourceData_df['Protocol']=='UDP']['Dest_port_no'].value_counts()),
    "No_of_IoT_UDP_ports": len(sourceData_df.loc[sourceData_df['Protocol']=='UDP']['IoT_port_no'].value_counts()),
    "No_of_irresponsive_ports": device_Ports_irresponsive,
    "No_of_DNS_request": packets_dns_req_per_minute,
    "No_of_DNS_response": packets_dns_resp_per_minute,
    "No_of_NTP_request": packets_ntp_req_per_minute,
    "No_of_NTP_response": packets_ntp_resp_per_minute,
    "attack" : attack_yes_summary,
    "attack type" : attack_type_summary,

  }


  if savename=='':
    with open(studyFile+"-network traffic analysis.csv", 'w') as f:
      for key in overall_analysis.keys():
          f.write("%s,%s\n"%(key,overall_analysis[key]))
  else:
    with open(savename+"-network traffic analysis.csv", 'w') as f:
      for key in overall_analysis.keys():
          f.write("%s,%s\n"%(key,overall_analysis[key]))
  print("\n")


  packets,dualComm_unique,dualComm_df = analyseDeviceIPDualCommunications2(IOTIP,studyFile,device_on,application_on,application_idel,attack_yes,attack_type,alias_name,device_type,scenario,savename)
  
  generate3rdFile_df = generate3rdFile(sourceData_df,dualComm_df)
  print(generate3rdFile_df)

  if savename=='':
    generate3rdFile_df.to_csv(studyFile+'-IoT traffic Dataset.csv', index=False)
  else:
    generate3rdFile_df.to_csv(savename+'-IoT traffic Dataset.csv', index=False)

  return sourceData_df,overall_analysis,sourceData_df_message,valid_ips

# print("\nData for plug on , plugoff-noapp-slowhttptest-success")
# destIP = "10.42.0.226" # lamp
# studyFile = '/FromDrive/MyDrive/IOTSecurityProject/plugoff-noapp-slowhttptest-success.pcapng' # lamp file with 0% light and no app
# studyFile = '/FromDrive/MyDrive/IOTSecurityProject/lampnormalusage0%noapp249.pcapng'
# sourceData_df,overall_analysis = analyseDeviceIP(destIP,studyFile)
# print(sourceData_df,overall_analysis) # analyse

def analyseDeviceIPDualCommunications2(IOTIP,studyFile,device_on=True,application_on=True,application_idel=True,attack_yes=False,attack_type='',alias_name='',device_type='',scenario='',savename=''):

  print(" warning: analysing only first 100, because life is short")

  # column_names is a dataframe column title (not for excel but inside code).
  column_names_unique = ["Src_IP" ,"Src_Port", "Dst_IP" ,"Dst_port","Protocol"]
  column_names = ["Src_IP" ,"Src_Port", "Dst_IP" ,"Dst_port","Protocol" 
                  # , "reqIPflag", "resIPflag" 
                  , "Req_packet_Length", "Resp_packet_Length", "Req_packet_Payload", "Resp_packet_Payload", "Req_TTL"
                  # ,"resttl"
                  ,"Resp_time_min","Resp_time_avg","Resp_time_max", "Repetition" 
                  ,"Repetition_per_minute","IsServer"
                  # ,"device_on","application_on","application_idel"
                  ,"attack","attack_type"
                  #,"alias_name","device_type","scenario"
                  ]
  # print('Output is',column_names)
  
  # open studyfile and filter for destination IOT IP , neglect other devices on the network
  cap = pyshark.FileCapture(studyFile, display_filter="ip.addr == "+ IOTIP
                                )                           
  numberOf_Packets = len([packet for packet in cap]) # number of packets to device
  package_duration_seconds = float(cap[numberOf_Packets-1].sniff_timestamp) - float(cap[0].sniff_timestamp) # capture duration in seconds , last package date - first package date
  package_duration_minutes = package_duration_seconds / 60 # file duration in minutes
  
  idx = 0 
  idy = 0

  dualComm_unique = [] # dataframe table containing unique sets of [server IP , server port , protocol , IOTPort , and all the column_names ] that connected to device
  dualComm_unique_df = pd.DataFrame(columns = column_names_unique)
  dualComm_unique_column_list_repeatance=[]
  dualComm_unique_column_list_repeatance_starttime=[]
  dualComm_unique_column_list_repeatance_endtime=[]
  dualComm_unique_column_list_time_res_min=[]
  dualComm_unique_column_list_time_res_max=[]
  dualComm_unique_column_list_time_res_avg=[]
  dualComm_unique_column_list_time_res_sum=[]
  dualComm = []
  dualComm_df =  pd.DataFrame(columns = column_names)
  
  packets=[]
  for packet in cap: # looping on packets in pcabng file      
     
    if("TCP" in str(packet.layers)):
      srcport = packet.tcp.srcport
      dstport = packet.tcp.dstport
      srcportreqStr = "tcp.srcport"
      dstportreqStr = "tcp.dstport"
    elif ("UDP" in str(packet.layers)):
      srcport = packet.udp.srcport
      dstport = packet.udp.dstport
      srcportreqStr = "udp.srcport"
      dstportreqStr = "udp.dstport"
    else:
      continue

    Protocol = packet.transport_layer
    if len(packet.layers)==3 and "TCP" in str(packet.layers):
      Protocol = "TCP"
    if "UDP" in str(packet.layers):
      Protocol = "UDP"
    if "SSL" in str(packet.layers):
      Protocol = "TCP"
    if "HTTP" in str(packet.layers):
      Protocol = "TCP"
    
    if ("TCP" in str(packet.layers)):
      # print(packet.layers)
      # print(str(packet.layers[2]))
      if os.name == "nt":
        flag_req = int(str(packet.layers[2]).splitlines()[12].split("0x")[1].split()[0])  # 9 in colab  , 12 in ubuntu server
        tcp_seq_num_req = int(str(packet.layers[2]).splitlines()[6].split()[2])   # 5 in colab 
        tcp_nxt_seq_num_req = int(str(packet.layers[2]).splitlines()[8].split()[3])  # 6 in colab 
        tcp_ack_num_req = int(str(packet.layers[2]).splitlines()[9].split()[2]) # 7 in colab 

      else:
        try:              
          flag_req = int(str(packet.layers[2]).splitlines()[12].split("0x")[1].split()[0])  # 9 in colab           
        except: 
          flag_req = -1
        tcp_seq_num_req = int(str(packet.layers[2]).splitlines()[6].split()[2])   # 5 in colab 
        tcp_nxt_seq_num_req = int(str(packet.layers[2]).splitlines()[8].split()[3])  # 6 in colab 
        tcp_ack_num_req = int(str(packet.layers[2]).splitlines()[9].split()[2]) # 7 in colab 
        
      packets.append([resolve_hostname(packet.ip.src)[0] , srcport , resolve_hostname(packet.ip.dst)[0], dstport, packet.transport_layer,tcp_nxt_seq_num_req])

  uniqueCount=0
  cap_count = -1
  c=1
  for packet in cap: # looping on packets in pcabng file
    cap_count += 1
    # bar update , if uncommented ofcorse
    # bar.update(c)
    c+=1
    # print(packet.layers)
    # only 100 packet if uncommneted
    if c>50:      
     break    
    # print(c , " of " , numberOf_Packets , " for file 2")
    
    if (IOTIP.split(".")[:-1] != packet.ip.src.split(".")[:-1]) or True: # excluding local connections (if remove or true) , we are not excluding because we are attacking from access point
      
      #  Port on this Remote server (no unit) - TCP/UDP layer
      #  Port on IOT (no unit) - TCP/UDP layer
      if("TCP" in str(packet.layers)):
        srcport = packet.tcp.srcport
        dstport = packet.tcp.dstport
        srcportreqStr = "tcp.srcport"
        dstportreqStr = "tcp.dstport"
      elif ("UDP" in str(packet.layers)):
        srcport = packet.udp.srcport
        dstport = packet.udp.dstport
        srcportreqStr = "udp.srcport"
        dstportreqStr = "udp.dstport"
      else:
        continue
      # 

      # 2 - Protocol to this server (no unit) - IP layer
      Protocol = packet.transport_layer
      if len(packet.layers)==3 and "TCP" in str(packet.layers):
        Protocol = "TCP"
      if "UDP" in str(packet.layers):
        Protocol = "UDP"
      if "SSL" in str(packet.layers):
        Protocol = "TCP"
      if "HTTP" in str(packet.layers):
        Protocol = "TCP"
      # end of 2
      
      reqonly = True
      if ("TCP" in str(packet.layers)):
        #print(packet)
        # print(packet.layers)
        # print(str(packet.layers[2]))
        if os.name == "nt":
          flag_req = int(str(packet.layers[2]).splitlines()[12].split("0x")[1].split()[0])  # 9 in colab 
          tcp_seq_num_req = int(str(packet.layers[2]).splitlines()[6].split()[2])  # 5 in colab 
          tcp_nxt_seq_num_req = int(str(packet.layers[2]).splitlines()[8].split()[3])  # 6 in colab 
          tcp_ack_num_req = int(str(packet.layers[2]).splitlines()[9].split()[2])   # 7 in colab 
        else:
          try:
            flag_req = int(str(packet.layers[2]).splitlines()[12].split("0x")[1].split()[0])  # 9 in colab 
          except:
            flag_req = -1 
          tcp_seq_num_req = int(str(packet.layers[2]).splitlines()[6].split()[2])  # 5 in colab 
          tcp_nxt_seq_num_req = int(str(packet.layers[2]).splitlines()[8].split()[3])  # 6 in colab 
          tcp_ack_num_req = int(str(packet.layers[2]).splitlines()[9].split()[2])   # 7 in colab
        
        req_time = packet.sniff_timestamp
        length_req = packet.captured_length
        ttl_req = packet['IP'].ttl
        layer2lines = str(packet.layers[2]).splitlines()
        
        if os.name == 'nt':
          line1 = 38
          line2 = 39
        else:
          line1 = 36  # windows 33 , hostinger ubuntu 20 vps 34 
          line2 = 36  # windows 34 , hostinger ubuntu 20 vps 35
        reqPayload = 0
        if len(layer2lines)>line1 and len(packet.layers)==3:
          if len(layer2lines[line1].split("(")[-1].split()) > 1 :
            if layer2lines[line1].split("(")[-1].split()[1] == "bytes)":
              reqPayload = float(layer2lines[line1].split("(")[-1].split()[0])  
            else:
              reqPayload = 0
          else:
            reqPayload = 0              
        elif len(layer2lines)>line2 and len(packet.layers)==4:
          if len(layer2lines[line2].split("(")[-1].split()) > 1 :
            if layer2lines[line2].split("(")[-1].split()[1] == "bytes)":
              reqPayload = float(layer2lines[line2].split("(")[-1].split()[0])
            else:
              reqPayload = 0
          else:
            reqPayload = 0        
        
        else:
          reqPayload = 0
          
        # print(packet.layers[2])
        # looping on the next packets for response
        for aftercount in range (cap_count,numberOf_Packets): 
          if ("TCP" in str(cap[aftercount].layers) and packet.ip.src == cap[aftercount].ip.dst and packet.ip.dst == cap[aftercount].ip.src and packet.transport_layer == cap[aftercount].transport_layer):
            if os.name == "nt":
              tcp_nxt_seq_num_res_aftercount = int(str(cap[aftercount].layers[2]).splitlines()[8].split()[3]) # 6 in colab 
            else:
              tcp_nxt_seq_num_res_aftercount = int(str(cap[aftercount].layers[2]).splitlines()[8].split()[3]) #  don't forget  
            if tcp_nxt_seq_num_res_aftercount == tcp_ack_num_req:
              reqonly = False
              if os.name == "nt":
                flag_res = int(str(cap[aftercount].layers[2]).splitlines()[12].split("0x")[1].split()[0])  # 9 in colab 
                tcp_seq_num_res = int(str(cap[aftercount].layers[2]).splitlines()[6].split()[2])  # 5 in colab 
                tcp_nxt_seq_num_res = int(str(cap[aftercount].layers[2]).splitlines()[8].split()[3]) # 6 in colab 
                tcp_ack_num_res = int(str(cap[aftercount].layers[2]).splitlines()[9].split()[2])  # 7 in colab 
              else:
                try:
                  flag_res = int(str(cap[aftercount].layers[2]).splitlines()[12].split("0x")[1].split()[0])  # 9 in colab
                except:
                  flag_res = -1 
                tcp_seq_num_res = int(str(cap[aftercount].layers[2]).splitlines()[6].split()[2])  # 5 in colab 
                tcp_nxt_seq_num_res = int(str(cap[aftercount].layers[2]).splitlines()[8].split()[3]) # 6 in colab 
                tcp_ack_num_res = int(str(cap[aftercount].layers[2]).splitlines()[9].split()[2])  # 7 in colab
                 
              res_time = cap[aftercount].sniff_timestamp
              req_res_time = float(res_time) - float(req_time)

              length_res = cap[aftercount].captured_length
              ttl_res = cap[aftercount]['IP'].ttl
              layer2lines = str(cap[aftercount].layers[2]).splitlines()
              # print(len(layer2lines))
              resPayload = 0
              if len(layer2lines)>line1 and len(packet.layers)==3:
                if len(layer2lines[line1].split("(")[-1].split()) > 1 :
                  if layer2lines[line1].split("(")[-1].split()[1] == "bytes)":
                    resPayload = float(layer2lines[line1].split("(")[-1].split()[0])              
              elif len(layer2lines)>line2 and len(packet.layers)==4:
                if len(layer2lines[line2].split("(")[-1].split()) > 1 :
                  if layer2lines[line2].split("(")[-1].split()[1] == "bytes)":
                    resPayload = float(layer2lines[line2].split("(")[-1].split()[0]) 
              else:
                resPayload = 0
              
              break
        
        # print(flag_req)
        if flag_req == 18 and not reqonly :
          # print(flag_req)
          
          if [packet.ip.src , srcport , packet.ip.dst , dstport , packet.transport_layer , flag_req , flag_res , length_req , length_res , reqPayload , resPayload , ttl_req , ttl_res] not in dualComm_unique:
            # dualComm_unique_df.loc[uniqueCount] = [resolve_hostname(packet.ip.src)[0] , srcport , resolve_hostname(packet.ip.dst)[0], dstport, packet.transport_layer]
            dualComm_unique.append([packet.ip.src , srcport , packet.ip.dst, dstport, packet.transport_layer, flag_req , flag_res , length_req , length_res , reqPayload , resPayload , ttl_req , ttl_res])
            if req_res_time != -1:
              dualComm_unique_column_list_time_res_min.append(req_res_time)
              dualComm_unique_column_list_time_res_max.append(req_res_time)
              dualComm_unique_column_list_time_res_sum.append(req_res_time)
              dualComm_unique_column_list_repeatance.append(1)
              dualComm_unique_column_list_repeatance_starttime.append(float(packet.sniff_timestamp))
              dualComm_unique_column_list_repeatance_endtime.append(float(packet.sniff_timestamp))
                  # print(cap_count)
                  # print(aftercount)

            # dualComm.append([packet.sniff_timestamp, resolve_hostname(packet.ip.src)[0] , srcport , resolve_hostname(packet.ip.dst)[0], dstport, packet.transport_layer,flag_req,tcp_seq_num_req,tcp_nxt_seq_num_req,tcp_ack_num_req])
            
          else:
            row_repeated = dualComm_unique.index([packet.ip.src , srcport , packet.ip.dst, dstport, packet.transport_layer, flag_req , flag_res , length_req , length_res , reqPayload , resPayload , ttl_req , ttl_res])
            # print()
            dualComm_unique_column_list_repeatance_endtime[row_repeated] = float(packet.sniff_timestamp)
            if req_res_time != -1:
              if req_res_time < dualComm_unique_column_list_time_res_min[row_repeated]:
                dualComm_unique_column_list_time_res_min[row_repeated] = req_res_time
              if req_res_time > dualComm_unique_column_list_time_res_max[row_repeated]:
                dualComm_unique_column_list_time_res_max[row_repeated] = req_res_time
              dualComm_unique_column_list_time_res_sum[row_repeated] += req_res_time
              dualComm_unique_column_list_repeatance[row_repeated] +=1
            idy += 1
  

  for i in range(0,len(dualComm_unique)):
    isServer = resolve_hostname(dualComm_unique[i][0])[1] or resolve_hostname(dualComm_unique[i][2])[1]

    under_attack_detected = 0
    attack_type_detected =  ''
    if dualComm_unique[i][8] == 0:
      under_attack_detected = 1
      attack_type_detected =  'reconnaissance'

    if (dualComm_unique_column_list_repeatance_endtime[i] != dualComm_unique_column_list_repeatance_starttime[i]):
      repeatance_per_minute = round(float(dualComm_unique_column_list_repeatance[i]-1)/( dualComm_unique_column_list_repeatance_endtime[i] - dualComm_unique_column_list_repeatance_starttime[i] )*60 , 2)
    else:
      repeatance_per_minute = float(1)/( package_duration_minutes )

    dualComm_df.loc[i] = [resolve_hostname(dualComm_unique[i][0])[0],dualComm_unique[i][1],resolve_hostname(dualComm_unique[i][2])[0],dualComm_unique[i][3],dualComm_unique[i][4]
                          ,dualComm_unique[i][5],dualComm_unique[i][6]
                          ,dualComm_unique[i][7],dualComm_unique[i][8] 
                          ,dualComm_unique[i][9]
                          #,dualComm_unique[i][10],dualComm_unique[i][12],dualComm_unique[i][12]
                          ,dualComm_unique_column_list_time_res_min[i]
                          ,float(dualComm_unique_column_list_time_res_sum[i])/float(dualComm_unique_column_list_repeatance[i])
                          ,dualComm_unique_column_list_time_res_max[i],dualComm_unique_column_list_repeatance[i] , repeatance_per_minute , isServer
                          #,device_on,application_on,application_idel
                          ,under_attack_detected,attack_type_detected
                          #,alias_name,device_type,scenario
                          ]  

          # print(flag_req,tcp_seq_num_req,tcp_nxt_seq_num_req,tcp_ack_num_req)
          # print(packet)
          # return
          # ssl_layer_packekets_from_this_ip += 1
          # ssl_layer_packekets_size = float(str(packet1.layers[2]).splitlines()[3].split()[-1])
          # if c == 0:
          #   TLS_length_min_Sent_From_IOT = ssl_layer_packekets_size
          # c += 1
          # ssl_layer_packekets_from_this_ip_sum_ip += ssl_layer_packekets_size
          # TLS_lengths_list_From_IOT.append(ssl_layer_packekets_size)
          # if TLS_length_min_Sent_From_IOT > ssl_layer_packekets_size:
          #   TLS_length_min_Sent_From_IOT = ssl_layer_packekets_size
          # if TLS_length_max_Sent_From_IOT < ssl_layer_packekets_size:
          #   TLS_length_max_Sent_From_IOT = ssl_layer_packekets_size
  if savename=='':
    dualComm_df.to_csv(studyFile+'-communication pattern mapping.csv', index=False)
  else:
    dualComm_df.to_csv(savename+'-communication pattern mapping.csv', index=False)
  # print(ssl_layer_packekets_from_this_ip)
  # workbook = xlsxwriter.Workbook(studyFile+'.xlsx')
  # worksheet = workbook.add_worksheet()
  # worksheet.write(0, 0,"IP")
  # worksheet.write(idy, 0,resolve_hostname(packet.ip.src)[0])
  # workbook.close()
  print(dualComm_df)
  return packets,dualComm_unique,dualComm_df

# print("\nData for cam no app idle")
# IOTIP = "10.42.0.107" #  
# studyFile = '/FromDrive/MyDrive/IOTSecurityProject/camnoappidle.pcapng' 
# sourceData,overall_analysis = analyseDeviceIP(IOTIP,studyFile,device_on=True,application_on=False,application_idel=True,attack_yes=False,attack_type="",alias_name="",device_type="")
# # packets,dualComm_unique,dualComm = analyseDeviceIPDualCommunications(IOTIP,studyFile,device_on=True,application_on=False,application_idel=True,attack_yes=False,attack_type="",alias_name="",device_type="")
# print(sourceData)
# print(overall_analysis)
# # print(dualComm)

# pd.set_option('display.expand_frame_repr', False)


# print("\nData for cam app idle")
# IOTIP = "10.42.0.107" # 
# studyFile = '/FromDrive/MyDrive/IOTSecurityProject/camappidle.pcapng' 
# sourceData,overall_analysis = analyseDeviceIP(IOTIP,studyFile,device_on=True,application_on=True,application_idel=True,attack_yes=False,attack_type="",alias_name="",device_type="")
# # packets,dualComm_unique,dualComm = analyseDeviceIPDualCommunications(IOTIP,studyFile,device_on=True,application_on=True,application_idel=True,attack_yes=False,attack_type="",alias_name="",device_type="")
# print(sourceData)
# print(overall_analysis)
# # print(dualComm)

