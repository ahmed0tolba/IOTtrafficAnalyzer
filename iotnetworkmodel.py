
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

# resolve IoT server name

import socket

def resolve_hostname(addr):
    '''Try to resolve an IP to a host name and returns None
    on common failures.

    :param addr: IP address to resolve.
    :type addr: ``string``
    :returns: Host name if success else None.
    :rtype: ``string``

    :raises ValueError: If `addr` is not a valid address
    '''

    if socket.inet_aton(addr):
      try:
          name, _, _ = socket.gethostbyaddr(addr)
          translated = True
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



def analyseDeviceIP(IOTIP,studyFile,device_on=False,application_on=False,application_idel=False,attack_yes=False,attack_type="",alias_name="",device_type="",scenario=''):
  # create xlsx file , initialize xlsx column titles
  workbook = xlsxwriter.Workbook(studyFile+'.xlsx')
  worksheet = workbook.add_worksheet()
  worksheet.write(0, 0,"IPS Network Layer")
  worksheet.write(0, 1,"RemotePorts Session Layer")
  worksheet.write(0, 2,"Protocol Transport Layer")
  worksheet.write(0, 3,"MyPorts Session Layer")
  worksheet.write(0, 4,"sendReceiveRatio Transport Layer")
  
  worksheet.write(0, 5,"avg_NumOfPackets_Sent2IP_PerMinute Application Layer") 
  worksheet.write(0, 6,"avg_NumOfPackets_RecievedIP_PerMinute Application Layer") 
  worksheet.write(0, 7,"averageTTL Network Layer")
  worksheet.write(0, 8,"flow volume")
  worksheet.write(0, 9,"flow time")
  worksheet.write(0, 10,"avg_PacketsSize_Sent2IP Transport Layer") 
  worksheet.write(0, 11,"avg_PacketsSize_RecievedIP Transport Layer")  
  worksheet.write(0, 12,"flow rate")  
  worksheet.write(0, 13,"isserver")  
  worksheet.write(0, 14,"ssl length avg to IOT")  
  worksheet.write(0, 15,"ssl length min to IOT")  
  worksheet.write(0, 16,"ssl length max to IOT")  
  worksheet.write(0, 17,"ssl length std to IOT")  
  worksheet.write(0, 18,"ssl length avg from IOT") 
  worksheet.write(0, 19,"ssl length min from IOT") 
  worksheet.write(0, 20,"ssl length max from IOT")   
  worksheet.write(0, 21,"ssl length std from IOT")  

  worksheet.write(0, 22,"IP flags to IOT")  
  worksheet.write(0, 23,"IP flags from IOT")
  worksheet.write(0, 24,"TCP flags to IOT") 
  worksheet.write(0, 25,"TCP flags from IOT")  
  worksheet.write(0, 26,"device on")  
  worksheet.write(0, 27,"application on")  
  worksheet.write(0, 28,"application idle")  
  worksheet.write(0, 29,"attack yes")  
  worksheet.write(0, 30,"attack type")  
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

  print(" warning: analysing only first 100, because life is short")
  
  # column_names is a dataframe column title (not for excel but inside code)
  column_names = ["IPS" , "Ports" , "Protocol" , "PortIOT", "sendReceiveRatio", "NumRecievedPerMin", "NumSentPerMin", "avgTTL","flow volume","flow time", "avgSizeSent" 
                  ,"avgSizeRecieved","flow rate","isserver","Avg To IOT","Min to IOT","max to IOT","std to IOT","avg from IOT","min from IOT"
                  ,"max from IOT","std from IOT","IP flags to IOT","IP flags from IOT"
                  ,"TCP flags to IOT","TCP flags from IOT"
                  ,"attack yes","attack type"]
  # print('Output is',column_names)
  
  # open studyfile and filter for destination IOT IP , neglect other devices on the network
  capdest = pyshark.FileCapture(studyFile, display_filter="ip.dst == "+ IOTIP
                                )                           
  numberOf_Packets = len([packet for packet in capdest]) # number of packets to device
  
  package_duration_seconds = float(capdest[numberOf_Packets-1].sniff_timestamp) - float(capdest[0].sniff_timestamp) # capture duration in seconds , last package date - first package date
  package_duration_minutes = round(package_duration_seconds / 60,2) # file duration in minutes
  
  idx = 0 
  idy = 0

  sourceData_df =  pd.DataFrame(columns = column_names) # dataframe table containing unique sets of [server IP , server port , protocol , IOTPort , and all the column_names ] that connected to device
  sourceData = []
  # progress bar
  # bar = progressbar.ProgressBar(maxval=100, \
  #   widgets=[progressbar.Bar('=', '[', ']'), ' ', progressbar.Percentage()])
  # bar.start()
  # bar.update(0)

  sourceIPsSrcPortsProtocolDstPort=[]  # list containing unique sets of [server IP , server port , protocol , IOTPort] that connected to device - fyi: part of sourceData_df
  allPacketsSize = 0
  c1=1

  for packet in capdest: # looping on packets in pcabng file

    # bar update , if uncommented ofcorse
    # bar.update(c1)
    c1+=1
    # only 100 packet if uncommneted
    if c1>100:      
      break

    
    
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
        PacketsSize_RecievedIP_period = package_duration_minutes #float(cap_receivedIP[NumOfPackets_ReceivedIP-1].sniff_timestamp) - float(capdest[0].sniff_timestamp)

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
            # print(packet1)
            if os.name == "nt":
              TCP_flag_to_IOT = float(str(packet1.layers[2]).splitlines()[12].split("0x")[1].split()[0]) 
            else:
              TCP_flag_to_IOT = float(str(packet1.layers[2]).splitlines()[9].split("0x")[1].split()[0]) 
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
              TCP_flag_to_IOT = float(str(packet1.layers[2]).splitlines()[9].split("0x")[1].split()[0])  # 9 in colab
            
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
          avg_NumOfPackets_RecievedIP_PerMinute = 1 / package_duration_minutes
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
          receiveSend_RatioIP = float('inf')
        elif (NumOfPackets_Sent2IP!=1):       
# 4 - packets count received at IOT / sent to this server (packet count/ packet count) - IP layer  
          receiveSend_RatioIP =  round(NumOfPackets_ReceivedIP / NumOfPackets_Sent2IP,2) # receive send ratio
        else:
          receiveSend_RatioIP = 1


        
        if NumOfPackets_Sent2IP == 1 :         
          PacketsSize_Sent2IP_period_seconds = package_duration_seconds          
          # PacketsSize_Sent2IP_period = float(cap_Sent2IP[NumOfPackets_Sent2IP-1].sniff_timestamp) - float(cap_Sent2IP[0].sniff_timestamp)
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
              TCP_flag_from_IOT = float(str(packet1.layers[2]).splitlines()[9].split("0x")[1].split()[0])
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
              TCP_flag_from_IOT = float(str(packet1.layers[2]).splitlines()[9].split("0x")[1].split()[0]) # 9 in colab

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
          
          if attack_yes and not resolve_hostname(packet.ip.src)[1] and receiveSend_RatioIP == float('inf'):
            attack_yes_processed = True
          else:
            attack_yes_processed = False

          if attack_yes_processed:
            attack_type_processed = attack_type
          else:
            attack_type_processed = ""

          sourceData_df.loc[idy] = [resolve_hostname(packet.ip.src)[0] , srcport , packet.transport_layer , dstport, receiveSend_RatioIP,avg_NumOfPackets_Sent2IP_PerMinute,
                                    avg_NumOfPackets_RecievedIP_PerMinute,avgTTL,PacketsSize_Sent2IP + PacketsSize_RecievedIP,round(PacketsSize_Sent2IP_period_seconds,2),
                                    avg_PacketsSize_Sent2IP,avg_PacketsSize_RecievedIP,
                                    flowrate,resolve_hostname(packet.ip.src)[1],
                                    TLS_length_avg_Recieved_at_IOT,TLS_length_min_Recieved_at_IOT,TLS_length_max_Recieved_at_IOT,TLS_length_std_Recieved_at_IOT,
                                    TLS_length_avg_Sent_From_IOT,TLS_length_min_Sent_From_IOT,TLS_length_max_Sent_From_IOT,TLS_length_std_Sent_From_IOT,
                                    IP_flag_to_IOT,IP_flag_from_IOT
                                    ,IP_flag_to_IOT,IP_flag_from_IOT,
                                    attack_yes_processed,attack_type_processed] # add pattern to sourceData
          
          # store values in the xlsx rows
          idy+=1 # row number # all servers counter
          worksheet.write(idy, 0,resolve_hostname(packet.ip.src)[0])
          worksheet.write(idy, 1,srcport)
          worksheet.write(idy, 2,packet.transport_layer)
          worksheet.write(idy, 3,dstport)
          
          if (receiveSend_RatioIP != float('inf')):
            worksheet.write(idy, 4,receiveSend_RatioIP)
          else:
            worksheet.write(idy, 4,"inf")

          if (avg_NumOfPackets_Sent2IP_PerMinute != float('inf')):
            worksheet.write(idy, 5,avg_NumOfPackets_Sent2IP_PerMinute)
          else:
            worksheet.write(idy, 5,"inf")
          worksheet.write(idy, 6,avg_NumOfPackets_RecievedIP_PerMinute)

          worksheet.write(idy, 7,avgTTL)
          
          worksheet.write(idy, 8,PacketsSize_Sent2IP + PacketsSize_RecievedIP)
          worksheet.write(idy, 9,package_duration_minutes)

          worksheet.write(idy, 10,avg_PacketsSize_Sent2IP)
          worksheet.write(idy, 11,avg_PacketsSize_RecievedIP)
          
          worksheet.write(idy, 12,flowrate)

# 13 - check if the server contacted by IOT has a name server
          worksheet.write(idy, 13,resolve_hostname(packet.ip.src)[1])

          worksheet.write(idy, 14,TLS_length_avg_Recieved_at_IOT)
          worksheet.write(idy, 15,TLS_length_min_Recieved_at_IOT)
          worksheet.write(idy, 16,TLS_length_max_Recieved_at_IOT)
          worksheet.write(idy, 17,TLS_length_std_Recieved_at_IOT)

          worksheet.write(idy, 18,TLS_length_avg_Sent_From_IOT)
          worksheet.write(idy, 19,TLS_length_min_Sent_From_IOT)
          worksheet.write(idy, 20,TLS_length_max_Sent_From_IOT)
          worksheet.write(idy, 21,TLS_length_std_Sent_From_IOT)
          worksheet.write(idy, 22,IP_flag_to_IOT)
          worksheet.write(idy, 23,IP_flag_from_IOT)
          worksheet.write(idy, 24,TCP_flag_to_IOT)
          worksheet.write(idy, 25,TCP_flag_from_IOT)

          worksheet.write(idy, 26,device_on)
          worksheet.write(idy, 27,application_on)
          worksheet.write(idy, 28,application_idel)
          
          
          worksheet.write(idy, 29,attack_yes_processed)
          
          
          worksheet.write(idy, 30,attack_type_processed)
      idx+=1
  workbook.close()
  # close the xlsx file


  packets_initialize_tcp = pyshark.FileCapture(studyFile, display_filter= # sent packets to IP+.. 
                                      "ip.dst == " + IOTIP 
                                      + " and tcp.flags.syn == 1 "
                                      + " and tcp.flags.ack == 0 "
                                      )
  numberOf_packets_initialize_tcp = len([packet for packet in packets_initialize_tcp]) # number of packets to device

  if (numberOf_Packets == 0):
    all_packets_recieved_per_minute =0
  elif (numberOf_Packets == 1):
    all_packets_recieved_per_minute =1
  else:
    all_packets_recieved_per_minute = round(float(numberOf_Packets-1) / (float(capdest[numberOf_Packets-1].sniff_timestamp) - float(capdest[0].sniff_timestamp)) * 60,2)

  if (numberOf_packets_initialize_tcp == 0):
    initialized_tcp_per_minute = 0
  elif (numberOf_packets_initialize_tcp == 1):
    initialized_tcp_per_minute = 1
  else:
    initialized_tcp_per_minute = round(float(numberOf_packets_initialize_tcp-1) / (float(packets_initialize_tcp[numberOf_packets_initialize_tcp-1].sniff_timestamp) - float(packets_initialize_tcp[0].sniff_timestamp)) * 60,2)
    
  packets_tcp_reset = pyshark.FileCapture(studyFile, display_filter= # sent packets to IP+.. 
                                      "ip.src == " + IOTIP 
                                      + " and tcp.flags.reset == 1 "
                                      )
  numberOf_packets_tcp_reset = len([packet for packet in packets_tcp_reset]) # number of packets to device
  


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
    packets_dns_req_per_minute = round(float(numberOf_packets_dns_req-1) / (float(packets_dns_req[numberOf_packets_dns_req-1].sniff_timestamp) - float(capdest[0].sniff_timestamp)) * 60,2)


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
    packets_dns_resp_per_minute = round(float(numberOf_packets_dns_resp-1) / (float(packets_dns_resp[numberOf_packets_dns_resp-1].sniff_timestamp) - float(capdest[0].sniff_timestamp)) * 60,2)

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
    packets_ntp_req_per_minute = round(float(numberOf_packets_ntp_req-1) / (float(packets_ntp_req[numberOf_packets_ntp_req-1].sniff_timestamp) - float(capdest[0].sniff_timestamp)) * 60,2)

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
    packets_ntp_resp_per_minute = round(float(numberOf_packets_ntp_resp-1) / (float(packets_ntp_resp[numberOf_packets_ntp_resp-1].sniff_timestamp) - float(capdest[0].sniff_timestamp)) * 60,2)

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
  
  attack_yes_summary = False
  attack_type_summary = ""

  if initialized_tcp_per_minute > 10:
    attack_yes_summary = True
    attack_type_summary = "DOS"
  
  if numberOf_packets_tcp_reset > 2 and initialized_tcp_per_minute < 10:
    attack_yes_summary = True
    attack_type_summary = "reconnaissance"
  
  device_Ports_irresponsive = len(sourceData_df.loc[sourceData_df['sendReceiveRatio']==inf]['PortIOT'].value_counts())

  if device_Ports_irresponsive > 0:
    attack_yes_summary = True
    attack_type_summary = "reconnaissance"
    
  overall_analysis = {
    "all_packets_recieved_per_minute":  all_packets_recieved_per_minute,
    "initialized_tcp_per_minute": initialized_tcp_per_minute ,
    "tcp_reset": numberOf_packets_tcp_reset ,
    "ips_servers": len(sourceData_df.loc[sourceData_df['isserver']==True]['IPS'].value_counts()),
    "ips_tcp": len(sourceData_df.loc[sourceData_df['Protocol']=='TCP']['IPS'].value_counts()),
    "ips_udp": len(sourceData_df.loc[sourceData_df['Protocol']=='UDP']['IPS'].value_counts()),
    "remote Ports TCP": len(sourceData_df.loc[sourceData_df['Protocol']=='TCP']['Ports'].value_counts()),
    "device Ports TCP": len(sourceData_df.loc[sourceData_df['Protocol']=='TCP']['PortIOT'].value_counts()),
    "remote Ports UDP": len(sourceData_df.loc[sourceData_df['Protocol']=='UDP']['Ports'].value_counts()),
    "device Ports UDP": len(sourceData_df.loc[sourceData_df['Protocol']=='UDP']['PortIOT'].value_counts()),
    "device Ports irresponsive": device_Ports_irresponsive,
    "dns req": packets_dns_req_per_minute,
    "dns resp": packets_dns_resp_per_minute,
    "ntp req": packets_ntp_req_per_minute,
    "ntp resp": packets_ntp_resp_per_minute,
    "ntp resp": packets_ntp_resp_per_minute,
    "attack yes" : attack_yes_summary,
    "attack type" : attack_type_summary,

  }


  with open(studyFile+".csv", 'w') as f:
    for key in overall_analysis.keys():
        f.write("%s,%s\n"%(key,overall_analysis[key]))
  print("\n")


  analyseDeviceIPDualCommunications(IOTIP,studyFile,device_on,application_on,application_idel,attack_yes,attack_type,alias_name,device_type,scenario)

  return sourceData_df,overall_analysis

# print("\nData for plug on , plugoff-noapp-slowhttptest-success")
# destIP = "10.42.0.226" # lamp
# studyFile = '/FromDrive/MyDrive/IOTSecurityProject/plugoff-noapp-slowhttptest-success.pcapng' # lamp file with 0% light and no app
# studyFile = '/FromDrive/MyDrive/IOTSecurityProject/lampnormalusage0%noapp249.pcapng'
# sourceData_df,overall_analysis = analyseDeviceIP(destIP,studyFile)
# print(sourceData_df,overall_analysis) # analyse

def analyseDeviceIPDualCommunications(IOTIP,studyFile,device_on,application_on,application_idel,attack_yes,attack_type,alias_name,device_type,scenario=''):

  print(" warning: analysing only first 100, because life is short")

  # column_names is a dataframe column title (not for excel but inside code).
  column_names_unique = ["srcIP" ,"srcPort", "dstIP" ,"dstport","Protocol"]
  column_names = ["srcIP" ,"srcPort", "dstIP" ,"dstport","Protocol" , "reqIPflag", "resIPflag" , "reqLen", "resLen", "reqPayload", "resPayload", "reqttL","resttl","restimemin","restimeavg","restimemax", "repeatance" 
                  ,"repeatance / min","isServer","device_on","application_on","application_idel","attack_yes","attack_type","alias_name","device_type","scenario"
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
        flag_req = int(str(packet.layers[2]).splitlines()[12].split("0x")[1].split()[0])  # 9 in colab 
        tcp_seq_num_req = int(str(packet.layers[2]).splitlines()[6].split()[2])   # 5 in colab 
        tcp_nxt_seq_num_req = int(str(packet.layers[2]).splitlines()[8].split()[3])  # 6 in colab 
        tcp_ack_num_req = int(str(packet.layers[2]).splitlines()[9].split()[2]) # 7 in colab 
      else:
        flag_req = int(str(packet.layers[2]).splitlines()[9].split("0x")[1].split()[0])  # 9 in colab 
        tcp_seq_num_req = int(str(packet.layers[2]).splitlines()[5].split()[2])   # 5 in colab 
        tcp_nxt_seq_num_req = int(str(packet.layers[2]).splitlines()[6].split()[3])  # 6 in colab 
        tcp_ack_num_req = int(str(packet.layers[2]).splitlines()[7].split()[2]) # 7 in colab 
      
      packets.append([resolve_hostname(packet.ip.src)[0] , srcport , resolve_hostname(packet.ip.dst)[0], dstport, packet.transport_layer,tcp_nxt_seq_num_req])

  uniqueCount=0
  cap_count = -1
  for packet in cap: # looping on packets in pcabng file
    cap_count += 1
    # bar update , if uncommented ofcorse
    # bar.update(c)
    # c+=1
    # print(packet.layers)
    # only 100 packet if uncommneted
    # if c>100:      
    #   break

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
        # print(packet)
        # print(packet.layers)
        # print(str(packet.layers[2]))
        if os.name == "nt":
          flag_req = int(str(packet.layers[2]).splitlines()[12].split("0x")[1].split()[0])  # 9 in colab 
          tcp_seq_num_req = int(str(packet.layers[2]).splitlines()[6].split()[2])  # 5 in colab 
          tcp_nxt_seq_num_req = int(str(packet.layers[2]).splitlines()[8].split()[3])  # 6 in colab 
          tcp_ack_num_req = int(str(packet.layers[2]).splitlines()[9].split()[2])   # 7 in colab 
        else:
          flag_req = int(str(packet.layers[2]).splitlines()[9].split("0x")[1].split()[0])  # 9 in colab 
          tcp_seq_num_req = int(str(packet.layers[2]).splitlines()[5].split()[2])  # 5 in colab 
          tcp_nxt_seq_num_req = int(str(packet.layers[2]).splitlines()[6].split()[3])  # 6 in colab 
          tcp_ack_num_req = int(str(packet.layers[2]).splitlines()[7].split()[2])   # 7 in colab 
        req_time = packet.sniff_timestamp
        length_req = packet.captured_length
        ttl_req = packet['IP'].ttl
        layer2lines = str(packet.layers[2]).splitlines()
        
        if os.name == 'nt':
          line1 = 38
          line2 = 39
        else:
          line1 = 33
          line2 = 34
        if len(layer2lines)>line1 and len(packet.layers)==3:
          if len(layer2lines[line1].split("(")[-1].split()) > 1 :
            if layer2lines[line1].split("(")[-1].split()[1] == "bytes)":
              reqPayload = float(layer2lines[line1].split("(")[-1].split()[0])              
        elif len(layer2lines)>line2 and len(packet.layers)==4:
          if len(layer2lines[line2].split("(")[-1].split()) > 1 :
            if layer2lines[line2].split("(")[-1].split()[1] == "bytes)":
              reqPayload = float(layer2lines[line2].split("(")[-1].split()[0])              
        
        else:
          reqPayload = 0
          
        # print(packet.layers[2])
        # looping on the next packets for response
        for aftercount in range (cap_count,numberOf_Packets): 
          if ("TCP" in str(cap[aftercount].layers) and packet.ip.src == cap[aftercount].ip.dst and packet.ip.dst == cap[aftercount].ip.src and packet.transport_layer == cap[aftercount].transport_layer):
            tcp_nxt_seq_num_res_aftercount = int(str(cap[aftercount].layers[2]).splitlines()[8].split()[3]) # 6 in colab 
            if tcp_nxt_seq_num_res_aftercount == tcp_ack_num_req:
              reqonly = False
              if os.name == "nt":
                flag_res = int(str(cap[aftercount].layers[2]).splitlines()[12].split("0x")[1].split()[0])  # 9 in colab 
                tcp_seq_num_res = int(str(cap[aftercount].layers[2]).splitlines()[6].split()[2])  # 5 in colab 
                tcp_nxt_seq_num_res = int(str(cap[aftercount].layers[2]).splitlines()[8].split()[3]) # 6 in colab 
                tcp_ack_num_res = int(str(cap[aftercount].layers[2]).splitlines()[9].split()[2])  # 7 in colab 
              else:
                flag_res = int(str(cap[aftercount].layers[2]).splitlines()[9].split("0x")[1].split()[0])  # 9 in colab 
                tcp_seq_num_res = int(str(cap[aftercount].layers[2]).splitlines()[5].split()[2])  # 5 in colab 
                tcp_nxt_seq_num_res = int(str(cap[aftercount].layers[2]).splitlines()[6].split()[3]) # 6 in colab 
                tcp_ack_num_res = int(str(cap[aftercount].layers[2]).splitlines()[7].split()[2])  # 7 in colab 
              res_time = cap[aftercount].sniff_timestamp
              req_res_time = float(res_time) - float(req_time)

              length_res = cap[aftercount].captured_length
              ttl_res = cap[aftercount]['IP'].ttl
              layer2lines = str(cap[aftercount].layers[2]).splitlines()
              # print(len(layer2lines))
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

        if flag_req == 18 and not reqonly :
          
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

    under_attack_detected = False
    attack_type_detected =  ''
    if dualComm_unique[i][8] == 0:
      under_attack_detected = True
      attack_type_detected =  'reconnaissance'

    if (dualComm_unique_column_list_repeatance_endtime[i] != dualComm_unique_column_list_repeatance_starttime[i]):
      repeatance_per_minute = round(float(dualComm_unique_column_list_repeatance[i]-1)/( dualComm_unique_column_list_repeatance_endtime[i] - dualComm_unique_column_list_repeatance_starttime[i] )*60 , 2)
    else:
      repeatance_per_minute = float(1)/( package_duration_minutes )

    dualComm_df.loc[i] = [resolve_hostname(dualComm_unique[i][0])[0],dualComm_unique[i][1],resolve_hostname(dualComm_unique[i][2])[0],dualComm_unique[i][3],dualComm_unique[i][4],dualComm_unique[i][5],dualComm_unique[i][6],dualComm_unique[i][7],dualComm_unique[i][8] 
                          ,dualComm_unique[i][9],dualComm_unique[i][10],dualComm_unique[i][11],dualComm_unique[i][12],round(dualComm_unique_column_list_time_res_min[i],4),round(float(dualComm_unique_column_list_time_res_sum[i])/float(dualComm_unique_column_list_repeatance[i]),2)
                          ,round(dualComm_unique_column_list_time_res_max[i],2),dualComm_unique_column_list_repeatance[i] , repeatance_per_minute , isServer , 
                          device_on,application_on,application_idel,under_attack_detected,attack_type_detected,alias_name,device_type,scenario]
  
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
  dualComm_df.to_csv(studyFile+'dualcomm.csv', index=False)
  # print(ssl_layer_packekets_from_this_ip)
  # workbook = xlsxwriter.Workbook(studyFile+'.xlsx')
  # worksheet = workbook.add_worksheet()
  # worksheet.write(0, 0,"IP")
  # worksheet.write(idy, 0,resolve_hostname(packet.ip.src)[0])
  # workbook.close()
  # print(dualComm_unique_column_list_repeatance)
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

