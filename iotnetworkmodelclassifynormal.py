
# !pip install nest-asyncio
# import nest_asyncio
# nest_asyncio.apply()

# Installing pyshark as it is not by default in Colab
# !pip install pyshark
# !apt-get install -y libcap2-bin tshark
import pyshark
import os
from Pcapng_File_to_dataframe import pcapng_file_to_dataframe
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
  try: # OSError: illegal IP address string passed to inet_aton
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
  except:
    translated = False
    resolved.append([addr,translated,addr])
    return addr , translated

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
    Dest_IP = row_ref['IP']  
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
  
  print(" warning: maybe analysing only first 100, because life is short")
  
  # column_names is a dataframe column title (not for excel but inside code)
  column_names = ['IP' , "Dest_port_no" , "IoT_port_no" , "Protocol", "Send_receive_ratio", "No_of_received_packets_per_minutes", "No_of_sent_packets_per_minutes", "Avg_TTL","Flow_volume","Flow_duration"
  , "Dest_ip_avg_packet_length" ,"Src_ip_avg_packet_length","Flow_rate","IsServer","Max_dest_SSL_payload","Min_dest_SSL_payload","Avg_dest_SSL_payload","Std_dest_SSL_payload","Max_IoT_SSL_payload","Min_IoT_SSL_payload"
                  ,"Avg_IoT_SSL_payload","Std_IoT_SSL_payload"
                  # ,"IP flags to IOT","IP flags from IOT"
                  ,"Dest_TCP_Flags","IoT_TCP_Flags"
                  ,"attack","attack type", "device type"
                  ]
  # print('Output is',column_names)
  
  # open studyfile and filter for destination IOT IP , neglect other devices on the network
  packets_iot_df = pcapng_file_to_dataframe(studyFile , IOTIP)
  # capdest = pyshark.FileCapture(studyFile, display_filter="ip.dst == "+ IOTIP
  #                               )
  packets_iot_df["processed"] = False
  print(packets_iot_df)
  capdst_df = packets_iot_df[(packets_iot_df['dst_ip']==IOTIP) | (packets_iot_df['dst_ip']=="IoT")]
  capsrc_df = packets_iot_df[(packets_iot_df['src_ip']==IOTIP) | (packets_iot_df['src_ip']=="IoT")]

  n_Packets_2_device = len(capdst_df) # number of packets to device
  n_Packets_from_device = len(capsrc_df) # number of packets to device
  n_Packets_2_and_from_device = n_Packets_2_device + n_Packets_from_device
  # print("n_Packets_2_device" , n_Packets_2_device)
  if n_Packets_2_and_from_device == 0:
    sourceData_df_message= "invalid ip"
    print(sourceData_df_message)
    # capdestips = pyshark.FileCapture(studyFile, display_filter="ip ")
    cap_ips = pd.unique(packets_iot_df[['src_ip', 'dst_ip']].values.ravel('K'))
    for ip in cap_ips:
      if ip not in valid_ips and ip not in invalid_ips:
        if not resolve_hostname(ip)[1]:
          valid_ips.append(ip)
        else:
          invalid_ips.append(ip)
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

  # 9 - flow time -> cap file duration (seconds)  
  package_duration_seconds = float(packets_iot_df['sniff_timestamp'].iloc[-1]) - float(packets_iot_df['sniff_timestamp'].iloc[0]) # capture duration in seconds , last package date - first package date
  package_duration_minutes = round(package_duration_seconds / 60,5) # file duration in minutes

  sourceData_df =  pd.DataFrame(columns = column_names) # dataframe table containing unique sets of [server IP , server port , protocol , IOTPort , and all the column_names ] that connected to device
    
  for index_packets_iot,packets_iot_row_ref in packets_iot_df.iterrows(): # looping on packets in pcabng file    packet packet
    # look for row in previous process

    if packets_iot_df.loc[index_packets_iot,"processed"] == False and (packets_iot_row_ref['dst_ip']==IOTIP or packets_iot_row_ref['dst_ip']=="IoT"):

        # extract row repeatance from packets_iot_df   &&    extract row respond repeatance from packets_iot_df
        capdst_row_ref_repeated_df = packets_iot_df[ ( packets_iot_df['src_ip'] == packets_iot_row_ref['src_ip']) & ( packets_iot_df['src_prt'] == packets_iot_row_ref['src_prt']) & 
                                          (packets_iot_df['protocol'] == packets_iot_row_ref['protocol']) & (packets_iot_df['dst_prt'] == packets_iot_row_ref['dst_prt']) ]
        capdst_row_ref_resp_repeated_df = packets_iot_df[ ( packets_iot_df['dst_ip'] == packets_iot_row_ref['src_ip']) & ( packets_iot_df['dst_prt'] == packets_iot_row_ref['src_prt']) & 
                                          (packets_iot_df['protocol'] == packets_iot_row_ref['protocol']) & (packets_iot_df['src_prt'] == packets_iot_row_ref['dst_prt']) ]
    
        # mark as processed
        capdst_row_ref_repeated_df_indexes = capdst_row_ref_repeated_df.index
        capdst_row_ref_resp_repeated_df_indexes = capdst_row_ref_resp_repeated_df.index
        packets_iot_df.loc[capdst_row_ref_repeated_df_indexes,"processed"]=True
        packets_iot_df.loc[capdst_row_ref_resp_repeated_df_indexes,"processed"]=True

        # packets count
        NumOfPackets_IOT_Received_from_IP = len(capdst_row_ref_repeated_df)
        NumOfPackets_IOT_Sent_to_IP = len(capdst_row_ref_resp_repeated_df)

        # packets count per minute
        NumOfPackets_IOT_Received_from_IP_per_min = round(NumOfPackets_IOT_Received_from_IP / package_duration_minutes,2)
        NumOfPackets_IOT_Sent_to_IP_per_min = round(NumOfPackets_IOT_Sent_to_IP / package_duration_minutes,2)

        # cap_receivedIP_df = packets_iot_df[(packets_iot_df['dst_ip']==IOTIP) & (packets_iot_df['src_ip']==packets_iot_row_ref['src_ip']) & (packets_iot_df['src_prt']==packets_iot_row_ref['src_prt']) & (packets_iot_df['protocol']==packets_iot_row_ref['protocol']) & (packets_iot_df['dst_prt']==packets_iot_row_ref['dst_prt'])]
  # 7 - average time to live from server to IOT (seconds) - IP layer
        avgTTL = round(capdst_row_ref_repeated_df['ttl'].mean() ,2)

  # 8 (1) - flow volume (traffic volume) -> downloaded bytes + uploaded bytes from this server (bytes) - physical layer
        bytes_IOT_Received_from_IP_PacketsSize = capdst_row_ref_repeated_df['packet_length'].sum()  # downloaded bytes
        bytes_IOT_Sent_to_IP_PacketsSize = capdst_row_ref_resp_repeated_df['packet_length'].sum()  # uploaded bytes

  # 11 - average downloaded packet size from this server to IOT (bytes)
        avg_PacketsSize_IoT_Recieved_from_IP = round(capdst_row_ref_repeated_df['packet_length'].mean(),2) 
        avg_PacketsSize_IoT_Sent_to_IP = round(capdst_row_ref_resp_repeated_df['packet_length'].mean(),2) 
        
  # 14 - average payload downloaded by IOT from server (bytes) - TCP UDP HTTP(application) layers  
  # 15 - minimim payload downloaded by IOT from server (bytes) 
  # 16 - maximum payload downloaded by IOT from server (bytes) 
  # 17 - std standard deviation for payloads downloaded by IOT from server (bytes)
  # 22 - IP layer flags to IOT from this server (hex) - assume it was always the same throught the conversation (and it is not)
        IP_flag_to_IOT_rows = capdst_row_ref_repeated_df['tcp_flag']
        if len(IP_flag_to_IOT_rows)>0:
          IP_flag_to_IOT = IP_flag_to_IOT_rows.iloc[0]
        else:
          IP_flag_to_IOT = ""
        TLS_length_min_Recieved_at_IOT = capdst_row_ref_repeated_df["data_length"].min()
        TLS_length_max_Recieved_at_IOT = capdst_row_ref_repeated_df["data_length"].max()
        TLS_length_std_Recieved_at_IOT = capdst_row_ref_repeated_df["data_length"].std()
        TLS_length_avg_Recieved_at_IOT = capdst_row_ref_repeated_df["data_length"].mean()

        # cap_Sent2IP_df = packets_iot_df[(packets_iot_df['src_ip']==IOTIP) & (packets_iot_df['dst_ip']==packets_iot_row_ref['src_ip']) & (packets_iot_df['src_prt']==packets_iot_row_ref['dst_prt']) & (packets_iot_df['protocol']==packets_iot_row_ref['protocol']) & (packets_iot_df['dst_prt']==packets_iot_row_ref['src_prt'])]
        # NumOfPackets_Sent2IP = len(cap_Sent2IP_df) # sent packets to IP+.. count      
        
        if NumOfPackets_IOT_Sent_to_IP == 0 :
          receiveSend_RatioIP = -1 # float('inf')
  # 4 - packets count received at IOT / sent to this server (packet count/ packet count) - IP layer  
        else:
          receiveSend_RatioIP =  round(NumOfPackets_IOT_Received_from_IP / NumOfPackets_IOT_Sent_to_IP,2) # receive send ratio
        
  # 8 (2)- flow volume (traffic volume) -> downloaded bytes + uploaded bytes from this server (bytes) - physical layer
            # uploaded bytes
  # 10 - average uploaded packet size from IOT to this server (bytes)
  # 12 - flow rate -> flow volume / flow time -> uploaded bytes + downloades bytes for a specific server per minute (bytes per minute) - IP layer        
  # 22 - IP layer flags to IOT from this server (hex) - assume it was always the same throught the conversation (and it is not)
        IP_flag_from_IOT_rows =  capdst_row_ref_resp_repeated_df["tcp_flag"]
        if len(IP_flag_from_IOT_rows)>0:
          IP_flag_from_IOT = IP_flag_from_IOT_rows.iloc[0]
        else:
          IP_flag_from_IOT = ""
  # 18 - average payload uploaded by IOT to server (bytes) 
  # 19 - minimim payload uploaded by IOT to server (bytes) 
  # 20 - maximum payload uploaded by IOT to server (bytes) 
  # 21 - std standard deviation for payloads uploaded by IOT to server (bytes) 
        TLS_length_min_Sent_From_IOT = capdst_row_ref_resp_repeated_df["data_length"].min()
        TLS_length_max_Sent_From_IOT = capdst_row_ref_resp_repeated_df["data_length"].max()
        TLS_length_std_Sent_From_IOT = capdst_row_ref_resp_repeated_df["data_length"].std()
        TLS_length_avg_Sent_From_IOT = capdst_row_ref_resp_repeated_df["data_length"].mean()

        flowrate =  (bytes_IOT_Received_from_IP_PacketsSize + bytes_IOT_Sent_to_IP_PacketsSize) / package_duration_minutes

        sourceData_df.loc[len(sourceData_df)] = [resolve_hostname(packets_iot_row_ref["src_ip"])[0] , packets_iot_row_ref["src_prt"]  , packets_iot_row_ref["dst_prt"], packets_iot_row_ref["protocol"], 
                                  receiveSend_RatioIP,NumOfPackets_IOT_Received_from_IP_per_min,NumOfPackets_IOT_Sent_to_IP_per_min,avgTTL,
                                  bytes_IOT_Received_from_IP_PacketsSize + bytes_IOT_Sent_to_IP_PacketsSize,
                                  package_duration_minutes,
                                  avg_PacketsSize_IoT_Recieved_from_IP,avg_PacketsSize_IoT_Sent_to_IP,
                                  flowrate,
                                  resolve_hostname(packets_iot_row_ref["src_ip"])[1],
                                  TLS_length_max_Recieved_at_IOT,TLS_length_min_Recieved_at_IOT,TLS_length_avg_Recieved_at_IOT,TLS_length_std_Recieved_at_IOT,
                                  TLS_length_max_Sent_From_IOT,TLS_length_min_Sent_From_IOT,TLS_length_avg_Sent_From_IOT,TLS_length_std_Sent_From_IOT,
                                  # IP_flag_to_IOT,IP_flag_from_IOT,
                                  IP_flag_to_IOT,IP_flag_from_IOT,
                                  0,0,device_type
                                  ] # add pattern to sourceData
          # store values in the xlsx rows


  capsrc_df = packets_iot_df[((packets_iot_df['src_ip']==IOTIP) | (packets_iot_df['src_ip']=="IoT")) & (packets_iot_df['processed']==False)]

  for index_packets_iot,packets_iot_row_ref in packets_iot_df.iterrows():
    # look for row in previous process
    
    if not packets_iot_df.loc[index_packets_iot,"processed"] and (packets_iot_row_ref['src_ip']==IOTIP or packets_iot_row_ref['src_ip']=="IoT"):
      
      # extract row repeatance from capsrc_df
      capsrc_row_ref_repeated_df = packets_iot_df[ ( packets_iot_df['src_ip'] == packets_iot_row_ref['src_ip']) & ( packets_iot_df['src_prt'] == packets_iot_row_ref['src_prt']) & 
                                        (packets_iot_df['protocol'] == packets_iot_row_ref['protocol']) & (packets_iot_df['dst_prt'] == packets_iot_row_ref['dst_prt']) ]
   
      # mark as processed
      capsrc_row_ref_repeated_df_indexes = capsrc_row_ref_repeated_df.index
      packets_iot_df.loc[capsrc_row_ref_repeated_df_indexes,"processed"]=True

      No_of_sent_packets_per_minutes = round(len(capsrc_row_ref_repeated_df)/package_duration_minutes,2)

      
      sourceData_df.loc[len(sourceData_df)] = [resolve_hostname(packets_iot_row_ref["src_ip"])[0] , packets_iot_row_ref["src_prt"]  , packets_iot_row_ref["dst_prt"], packets_iot_row_ref["protocol"], 
                                  0,0,
                                  No_of_sent_packets_per_minutes,0,0,0,
                                  0,0,
                                  0,resolve_hostname(packets_iot_row_ref["dst_ip"])[1],
                                  0,0,0,0,
                                  0,0,0,0,
                                  # IP_flag_to_IOT,IP_flag_from_IOT,
                                  0,0,
                                  0,0,device_type
                                  ] # add pattern to sourceData


  sourceData_df.loc[(sourceData_df["Protocol"] == "EAPOL") & (sourceData_df["No_of_received_packets_per_minutes"] > 8), ["attack","attack type"]] = [1,"deauth"]
  sourceData_df.loc[(sourceData_df["Protocol"] == "XID") & (sourceData_df["No_of_sent_packets_per_minutes"] > 1), ["attack","attack type"]] = [1,"deauth"]

  # syn tcp dos
  sourceData_df.loc[(sourceData_df["IsServer"] == False) & (sourceData_df["Protocol"] == "TCP") & (sourceData_df["No_of_received_packets_per_minutes"] > 0) & (sourceData_df["No_of_received_packets_per_minutes"] < 25) & (sourceData_df["No_of_sent_packets_per_minutes"] >= 0) & (sourceData_df["No_of_sent_packets_per_minutes"] < 25) & (sourceData_df["Flow_volume"] > 0) & (sourceData_df["Flow_volume"] < 2000) & ((sourceData_df["Send_receive_ratio"] >= .5) | (sourceData_df["Send_receive_ratio"] == -1)) , ["attack","attack type"]] = [1,"dos"]

  #MITM
  sourceData_df.loc[(sourceData_df["Protocol"] == "ICMP") & (sourceData_df["Flow_volume"] > 62) & (sourceData_df["Send_receive_ratio"] > -1), ["attack","attack type"]] = [1,"MITM"]

  # nmap , port scan
  sourceData_df.loc[(sourceData_df["Protocol"] == "TCP") & ((sourceData_df["No_of_received_packets_per_minutes"] == 3.32) | (sourceData_df["No_of_sent_packets_per_minutes"] == 3.32)) , ["attack","attack type"]] = [1,"scan"]

  if savename=='':
    sourceData_df.to_csv(studyFile+'-In depth packet analysis.csv',index=False)
  else:
    sourceData_df.to_csv(savename+'-In depth packet analysis.csv',index=False)
    
# 2-1 'all_packets_recieved_per_minute': average total number of packets recieved(downloaded) at IOT from all connections per minute
  if (n_Packets_2_device == 0):
    all_packets_recieved_per_minute =0
  elif (n_Packets_2_device == 1):
    all_packets_recieved_per_minute =1
  else:
    all_packets_recieved_per_minute = round(n_Packets_2_device / (float(capdst_df["sniff_timestamp"].iloc[-1]) - float(capdst_df["sniff_timestamp"].iloc[0])) * 60,2)

# 2-2 'initialized_tcp_per_minute': average number of initialized tcp connections per minute
  packets_initialize_tcp = pyshark.FileCapture(studyFile, display_filter= # sent packets to IP+.. 
                                      "ip.dst == " + IOTIP 
                                      + " and tcp.flags.syn == 1 "
                                      + " and tcp.flags.ack == 0 "
                                      )
  packets_initialize_tcp.close()
  n_Packets_2_device_initialize_tcp = len([packet for packet in packets_initialize_tcp]) # number of packets to device


  if (n_Packets_2_device_initialize_tcp == 0):
    initialized_tcp_per_minute = 0
  elif (n_Packets_2_device_initialize_tcp == 1):
    initialized_tcp_per_minute = 1
  else:
    initialized_tcp_per_minute = round((n_Packets_2_device_initialize_tcp-1) / (float(packets_initialize_tcp[n_Packets_2_device_initialize_tcp-1].sniff_timestamp) - float(packets_initialize_tcp[0].sniff_timestamp)) * 60,2)
  
  # 2-3 'tcp_reset': number of TCP reset packages
  packets_tcp_reset = pyshark.FileCapture(studyFile, display_filter= # sent packets to IP+.. 
                                      "ip.src == " + IOTIP 
                                      + " and tcp.flags.reset == 1 "
                                      )
  packets_tcp_reset.close()                                      
  n_Packets_2_device_tcp_reset = len([packet for packet in packets_tcp_reset]) # number of packets to device
   

# 2-12 'dns req': average number of dns requests per minute
  packets_dns_req = pyshark.FileCapture(studyFile, display_filter= # sent packets to IP+.. 
                                      "ip.src == " + IOTIP 
                                      + " and dns "
                                      )
  packets_dns_req.close()   
  n_Packets_2_device_dns_req = len([packet for packet in packets_dns_req]) # number of packets to device

  if (n_Packets_2_device_dns_req == 0):
    packets_dns_req_per_minute =0
  elif (n_Packets_2_device_dns_req == 1):
    packets_dns_req_per_minute =1
  else:
    packets_dns_req_per_minute = round((n_Packets_2_device_dns_req-1) /  (float(capdst_df["sniff_timestamp"].iloc[-1]) - float(capdst_df["sniff_timestamp"].iloc[0])) * 60,2)

# 2-13 'dns resp': average number of dns responds per minute
  packets_dns_resp = pyshark.FileCapture(studyFile, display_filter= # sent packets to IP+.. 
                                      "ip.dst == " + IOTIP 
                                      + " and dns "
                                      )
  packets_dns_resp.close()   
  n_Packets_2_device_dns_resp = len([packet for packet in packets_dns_resp]) # number of packets to device

  if (n_Packets_2_device_dns_resp == 0):
    packets_dns_resp_per_minute =0
  elif (n_Packets_2_device_dns_resp == 1):
    packets_dns_resp_per_minute =1
  else:
    packets_dns_resp_per_minute = round((n_Packets_2_device_dns_resp-1) /  (float(capdst_df["sniff_timestamp"].iloc[-1]) - float(capdst_df["sniff_timestamp"].iloc[0])) * 60,2)
# 2-14 'ntp req': average number of ntp requests per minute
  packets_ntp_req = pyshark.FileCapture(studyFile, display_filter= # sent packets to IP+.. 
                                      "ip.src == " + IOTIP 
                                      + " and ntp "
                                      )
  packets_ntp_req.close()
  n_Packets_2_device_ntp_req = len([packet for packet in packets_ntp_req]) # number of packets to device
  if (n_Packets_2_device_ntp_req == 0):
    packets_ntp_req_per_minute =0
  elif (n_Packets_2_device_ntp_req == 1):
    packets_ntp_req_per_minute =1
  else:
    packets_ntp_req_per_minute = round((n_Packets_2_device_ntp_req-1) /  (float(capdst_df["sniff_timestamp"].iloc[-1]) - float(capdst_df["sniff_timestamp"].iloc[0])) * 60,2)

# 2-15 'ntp resp': average number of ntp responds per minute
  packets_ntp_resp = pyshark.FileCapture(studyFile, display_filter= # sent packets to IP+.. 
                                      "ip.dst == " + IOTIP 
                                      + " and ntp "
                                      )

  packets_ntp_resp.close()
  n_Packets_2_device_ntp_resp = len([packet for packet in packets_ntp_resp]) # number of packets to device

  if (n_Packets_2_device_ntp_resp == 0):
    packets_ntp_resp_per_minute =0
  elif (n_Packets_2_device_ntp_resp == 1):
    packets_ntp_resp_per_minute =1
  else:
    packets_ntp_resp_per_minute = round((n_Packets_2_device_ntp_resp-1) /  (float(capdst_df["sniff_timestamp"].iloc[-1]) - float(capdst_df["sniff_timestamp"].iloc[0])) * 60,2)

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

  if n_Packets_2_device_tcp_reset > 2 and initialized_tcp_per_minute < 10:
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
    "TCP_reset": n_Packets_2_device_tcp_reset ,
    "No_of_IP_servers": len(sourceData_df.loc[sourceData_df['IsServer']==True]['IP'].value_counts()),
    "No_of_TCP_connection": len(sourceData_df.loc[sourceData_df['Protocol']=='TCP']['IP'].value_counts()),  # number of IPS that estaplish TCP  
    "No_UDP_connection": len(sourceData_df.loc[sourceData_df['Protocol']=='UDP']['IP'].value_counts()),  # number of IPS that estaplish UDP 
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
  # cap = pyshark.FileCapture(studyFile, display_filter="ip.addr == "+ IOTIP
  #                               )  
  cap_df = pcapng_file_to_dataframe(studyFile , IOTIP)                         
  n_Packets_2_device = len(cap_df) # number of packets to device
  package_duration_seconds = cap_df["sniff_timestamp"].iloc[-1] - cap_df["sniff_timestamp"].iloc[0] # capture duration in seconds , last package date - first package date
  package_duration_minutes = package_duration_seconds / 60 # file duration in minutes
  

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
  for cap_df_index , cap_df_packet in cap_df.iterrows(): # looping on packets in pcabng file      
     
   
    flag_req = cap_df_packet['tcp_flag']
    tcp_seq_num_req = cap_df_packet['tcp_seq_num']
    tcp_nxt_seq_num_req = cap_df_packet['tcp_nxt_seq_num']
    tcp_ack_num_req = cap_df_packet['tcp_ack_num']

        
    packets.append([resolve_hostname(cap_df_packet['src_ip'])[0] , cap_df_packet['src_prt'] , resolve_hostname(cap_df_packet['dst_ip'])[0], cap_df_packet['dst_prt'], cap_df_packet['protocol'],tcp_nxt_seq_num_req])

  uniqueCount=0
  cap_count = -1
  c=1
  for cap_df_index , cap_df_packet in cap_df.iterrows(): # looping on packets in pcabng file
    cap_count += 1
    # bar update , if uncommented ofcorse
    # bar.update(c)
    c+=1
    # print(packet.layers)
    # only 100 packet if uncommneted
    # if c>50:      
    #  break    
    # print(c , " of " , n_Packets_2_device , " for file 2")
    
    if (IOTIP.split(".")[:-1] != cap_df_packet['src_ip'].split(".")[:-1]) or True: # excluding local connections (if remove or true) , we are not excluding because we are attacking from access point
      
      reqonly = True
      flag_req = cap_df_packet['tcp_flag']
      tcp_seq_num_req = cap_df_packet['tcp_seq_num']
      tcp_nxt_seq_num_req = cap_df_packet['tcp_nxt_seq_num']
      tcp_ack_num_req = cap_df_packet['tcp_ack_num']
        
      req_time = cap_df_packet['sniff_timestamp']
      length_req = cap_df_packet['packet_length']
      ttl_req = cap_df_packet['ttl']

      reqPayload = cap_df_packet['data_length']
          
      # print(packet.layers[2])
      # looping on the next packets for response
      for aftercount in range (cap_df_index,len(cap_df)): 
        if "TCP" == cap_df.loc[aftercount,"protocol"] and cap_df_packet['src_ip'] == cap_df.loc[aftercount,'dst_ip'] and cap_df_packet['dst_ip'] == cap_df.loc[aftercount,'src_ip'] and cap_df_packet['protocol'] == cap_df.loc[aftercount,'protocol']:
          tcp_nxt_seq_num_res_aftercount = cap_df.loc[aftercount,'tcp_nxt_seq_num']
          if tcp_nxt_seq_num_res_aftercount == tcp_ack_num_req:
            reqonly = False
            flag_res = cap_df_packet['tcp_flag']
            tcp_seq_num_res = cap_df_packet['tcp_seq_num']
            tcp_nxt_seq_num_res = cap_df_packet['tcp_nxt_seq_num']
            tcp_ack_num_res = cap_df_packet['tcp_ack_num']
                
            res_time = cap_df.loc[aftercount,'sniff_timestamp']
            req_res_time = float(res_time) - float(req_time)

            length_res = cap_df.loc[aftercount,'packet_length']
            ttl_res = cap_df.loc[aftercount,'ttl']
            resPayload = cap_df.loc[aftercount,'data_length']
         
            break
      
      # print(flag_req)
      if flag_req == 18 and not reqonly :
        # print(flag_req)
        
        if [cap_df_packet['src_ip'] , cap_df_packet['src_prt'] , cap_df_packet['dst_ip'] , cap_df_packet['dst_prt'] , cap_df_packet['protocol'] , flag_req , flag_res , length_req , length_res , reqPayload , resPayload , ttl_req , ttl_res] not in dualComm_unique:
          # dualComm_unique_df.loc[uniqueCount] = [resolve_hostname(packet.ip.src)[0] , srcport , resolve_hostname(packet.ip.dst)[0], dstport, packet.transport_layer]
          dualComm_unique.append([cap_df_packet['src_ip'] , cap_df_packet['src_prt'] , cap_df_packet['dst_ip'] , cap_df_packet['dst_prt'] , cap_df_packet['protocol'], flag_req , flag_res , length_req , length_res , reqPayload , resPayload , ttl_req , ttl_res])
          if req_res_time != -1:
            dualComm_unique_column_list_time_res_min.append(req_res_time)
            dualComm_unique_column_list_time_res_max.append(req_res_time)
            dualComm_unique_column_list_time_res_sum.append(req_res_time)
            dualComm_unique_column_list_repeatance.append(1)
            dualComm_unique_column_list_repeatance_starttime.append(cap_df_packet['sniff_timestamp'])
            dualComm_unique_column_list_repeatance_endtime.append(cap_df_packet['sniff_timestamp'])
                # print(cap_count)
                # print(aftercount)

          # dualComm.append([packet.sniff_timestamp, resolve_hostname(packet.ip.src)[0] , srcport , resolve_hostname(packet.ip.dst)[0], dstport, packet.transport_layer,flag_req,tcp_seq_num_req,tcp_nxt_seq_num_req,tcp_ack_num_req])
          
        else:
          row_repeated = dualComm_unique.index([cap_df_packet['src_ip'] , cap_df_packet['src_prt'] , cap_df_packet['dst_ip'] , cap_df_packet['dst_prt'] , cap_df_packet['protocol'], flag_req , flag_res , length_req , length_res , reqPayload , resPayload , ttl_req , ttl_res])
          # print()
          dualComm_unique_column_list_repeatance_endtime[row_repeated] = float(cap_df_packet['sniff_timestamp'])
          if req_res_time != -1:
            if req_res_time < dualComm_unique_column_list_time_res_min[row_repeated]:
              dualComm_unique_column_list_time_res_min[row_repeated] = req_res_time
            if req_res_time > dualComm_unique_column_list_time_res_max[row_repeated]:
              dualComm_unique_column_list_time_res_max[row_repeated] = req_res_time
            dualComm_unique_column_list_time_res_sum[row_repeated] += req_res_time
            dualComm_unique_column_list_repeatance[row_repeated] +=1
  

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

