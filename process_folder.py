import os
from iotnetworkmodelclassifynormal import analyseDeviceIP2,analyseDeviceIPDualCommunications2

# Shelly plug
directory = 'J:\IOTNetworkModel\Dataset folders with attack new\Shelly plug\processed'
IOTIP = "192.168.2.15"
devicetype = "Shelly plug"

for filename in os.listdir(directory):
        if filename[0] != "_" and filename[-7] != ".pcapng":
            full_path = os.path.join(directory, filename)
            analyseDeviceIP2(IOTIP,full_path,devicetype,savename="uploadedfiles/"+filename)

