
from flask import Flask,make_response,url_for,redirect, request, render_template,current_app, g, send_file
from sqlalchemy import false
from werkzeug.utils import secure_filename
from datetime import datetime
from iotnetworkmodel import analyseDeviceIP,analyseDeviceIPDualCommunications
from iotnetworkmodelclassifynormal import analyseDeviceIP2,analyseDeviceIPDualCommunications2
import numpy as np
from threading import Thread
import sqlite3
from os.path import exists
import pandas as pd
from glob import glob
from io import BytesIO
from zipfile import ZipFile
import os
from flask import send_file
from flask_autoindex import AutoIndex

application = Flask(__name__)

numberofrunningtasksmax = 1
num_running_processes = 0

databasename = 'static/_database.db'
files_names_table = 'files_names_table'
try:
  print(f'Checking if {databasename} exists or not...')
  conn = sqlite3.connect(databasename, uri=True)
  print(f'Database exists. Succesfully connected to {databasename}')
  conn.execute('CREATE TABLE IF NOT EXISTS ' + files_names_table + ' (id INTEGER PRIMARY KEY AUTOINCREMENT,upload_file_name TEXT UNIQUE NOT NULL,IOTIP TEXT NOT NULL,device_type TEXT, states INTEGER NOT NULL,message TEXT)')
  # status = 1 # file starting processing successfully  
  # status = 2 # file is being processed
  # status = 3 # file finished processing
  # status -1 not started , 0 finished , -2 error
  
  print(f'Succesfully Created Table {files_names_table}')

except sqlite3.OperationalError as err:
  print('Database error,see log')
  print(err)

def Analyse_cap_threads_controller(IOTIP="",devicetype="",file_store_name=""):
  connt = sqlite3.connect(databasename, uri=True)
  curt = connt.cursor()

  curt.execute('select * from '+ files_names_table +' where upload_file_name = ?', (file_store_name,))
  records = curt.fetchall()
  if len(records)==0:
    # print("not found, create record")
    sqlite_insert_query = """INSERT INTO files_names_table (upload_file_name,IOTIP, states) VALUES (?,?,?);"""
    data_tuple = (file_store_name,IOTIP, 2)
    conn = sqlite3.connect(databasename, uri=True)
    cur = conn.cursor()
    cur.execute(sqlite_insert_query,data_tuple)
    conn.commit()
    conn.close()
    t = Thread(target=analyseDeviceIP,args=[IOTIP,file_store_name,devicetype])
    t.start()
    status = 1
    
  if len(records)>0:
    # print("found")
    status = 2

  return status

def Analyse_cap_threads_controller_2(IOTIP="",devicetype="",file_store_name=""):
  connt = sqlite3.connect(databasename, uri=True)
  curt = connt.cursor()

  curt.execute('select * from '+ files_names_table +' where upload_file_name = ?', (file_store_name,))
  records = curt.fetchall()
  if len(records)==0:
    # print("not found, create record")
    sqlite_insert_query = """INSERT INTO files_names_table (upload_file_name,IOTIP, states) VALUES (?,?,?);"""
    data_tuple = (file_store_name,IOTIP, 2)
    conn = sqlite3.connect(databasename, uri=True)
    cur = conn.cursor()
    cur.execute(sqlite_insert_query,data_tuple)
    conn.commit()
    conn.close()
    t = Thread(target=analyseDeviceIP2,args=[IOTIP,file_store_name,devicetype])
    t.start()
    status = 1
    
  if len(records)>0:
    # print("found")
    status = 2

  return status


app = Flask(__name__)

@application.route('/downloadfiles',methods=['GET'])
def download():
    file_store_name_with_extension = request.args.get('file_store_name_with_extension')

    stream = BytesIO()
    with ZipFile(stream, 'w') as zf:
        for file in glob(os.path.join("uploadedFiles/", file_store_name_with_extension +'*')):
            zf.write(file, os.path.basename(file))
    stream.seek(0)

    if os.name == "nt":
      return send_file(
          stream,
          as_attachment=True,
          attachment_filename=file_store_name_with_extension+'.zip'
      )
    else:
      return send_file(
          stream,
          as_attachment=True,
          download_name=file_store_name_with_extension+'.zip'
      )

@application.route('/downloadcommunicationpattern',methods=['GET'])
def downloadcommunicationpattern():
    #For windows you need to use drive name [ex: F:/Example.pdf]
    file_store_name_with_extension = request.args.get('file_store_name_with_extension')
    path = "uploadedFiles/" + file_store_name_with_extension + "-communication pattern mapping.csv"
    if exists(path):
      return send_file(path, as_attachment=True)
    return "File not found"

@application.route('/downloadindepthpacketanalysis',methods=['GET'])
def downloadindepthpacketanalysis():
    #For windows you need to use drive name [ex: F:/Example.pdf]
    file_store_name_with_extension = request.args.get('file_store_name_with_extension')
    path = "uploadedFiles/" + file_store_name_with_extension + "-In depth packet analysis.csv"
    if exists(path):
      return send_file(path, as_attachment=True)
    return "File not found"

@application.route('/downloadnetworktrafficanalysis',methods=['GET'])
def downloadnetworktrafficanalysis():
    #For windows you need to use drive name [ex: F:/Example.pdf]
    file_store_name_with_extension = request.args.get('file_store_name_with_extension')
    path = "uploadedFiles/" + file_store_name_with_extension + "-network traffic analysis.csv"
    if exists(path):
      return send_file(path, as_attachment=True)
    return "File not found"

@application.route('/downloadiottrafficdataset',methods=['GET'])
def downloadiottrafficdataset():
    #For windows you need to use drive name [ex: F:/Example.pdf]
    file_store_name_with_extension = request.args.get('file_store_name_with_extension')
    path = "uploadedFiles/" + file_store_name_with_extension + "-IoT traffic Dataset.csv"
    if exists(path):
      return send_file(path, as_attachment=True)
    return "File not found"

def getSavedResults(file_store_name_with_extension):
  message=""
  security_comment = ""
  all_remote_ips_has_NameServer = False
  connected_to_manufacturer = False
  all_tcp_ports_are_443 = True
  ips_dst=[]
  if len("uploadedFiles/"+file_store_name_with_extension) > 5:
    depth_name = "uploadedFiles/"+file_store_name_with_extension+"-In depth packet analysis.csv"
    csv_name = "uploadedFiles/"+file_store_name_with_extension+"-network traffic analysis.csv"
    dualcomm_name = "uploadedFiles/"+file_store_name_with_extension+"-communication pattern mapping.csv"
    generate3rdFile_df_name = "uploadedFiles/"+file_store_name_with_extension+"-IoT traffic Dataset.csv"
    ips_dst_name = "uploadedFiles/"+file_store_name_with_extension+"-valid ips.csv"
    if exists(ips_dst_name):
      ips_dst = pd.read_csv(ips_dst_name).to_numpy()
      message="Invalid ip"
      print(ips_dst)
      return [],[],[],[],False,ips_dst,message,security_comment,all_remote_ips_has_NameServer,connected_to_manufacturer,all_tcp_ports_are_443
    if exists(depth_name) and exists(csv_name) and exists(dualcomm_name) and exists(generate3rdFile_df_name):
      sourceData_df = pd.read_csv(depth_name)
      sourceData = sourceData_df.to_numpy()
      # print(sourceData)
      overall_analysis_pd = pd.read_csv(csv_name)
      #print(overall_analysis_pd)
      overall_analysis_np_array = overall_analysis_pd.iloc[: , -1].to_numpy().tolist()
      # overall_analysis = [np.insert(overall_analysis_np_array ,0,round(float(overall_analysis_pd.columns.values[1])))]  
      overall_analysis_np_array.insert(0,float(overall_analysis_pd.columns.values[1]))
      overall_analysis = [overall_analysis_np_array]
      # print(overall_analysis)
      dual_analysis_pd = pd.read_csv(dualcomm_name)
      dual_analysis_np_array = dual_analysis_pd.to_numpy()
      # print(dual_analysis_np_array)
      
      generate3rdFile_df = pd.read_csv(generate3rdFile_df_name)
      generate3rdFile_df_array = generate3rdFile_df.to_numpy()

      security_comment = "No Action Required"

      if overall_analysis_pd.iloc[2,1] == overall_analysis_pd.iloc[3,1] + overall_analysis_pd.iloc[4,1]:
        all_remote_ips_has_NameServer = True
      else:        
        security_comment = "Attention Needed"
      
      if int(overall_analysis_pd.iloc[2,1]) > 0:
        connected_to_manufacturer = True
      else:        
        security_comment = "Attention Needed"

      if len(sourceData_df.loc[(sourceData_df['Protocol']=='TCP') & (sourceData_df['Dest_port_no']!=443)].value_counts()) > 0 :
        all_tcp_ports_are_443 = False
        security_comment = "Attention Needed"
         
      # dual_analysis = [np.insert(dual_analysis_np_array ,0,dual_analysis_pd.columns.values[1])]  
 
      return sourceData,overall_analysis, dual_analysis_np_array,generate3rdFile_df_array,True,ips_dst,message,security_comment,all_remote_ips_has_NameServer,connected_to_manufacturer,all_tcp_ports_are_443
    else:
      return [],[],[],[],False,ips_dst,message,security_comment,all_remote_ips_has_NameServer,connected_to_manufacturer,all_tcp_ports_are_443
  else:
    return [],[],[],[],False,ips_dst,message,security_comment,all_remote_ips_has_NameServer,connected_to_manufacturer,all_tcp_ports_are_443

@application.route('/get_Saved_Results',methods=['POST'])
def get_Saved_Results():
  if "file_store_name_with_extension" in request.cookies:    
    file_store_name_with_extension = request.cookies.get('file_store_name_with_extension')
    sourceData , overall_analysis , dual_analysis , generate3rdFile_df_array, found ,ips_dst,message,security_comment,all_remote_ips_has_NameServer,connected_to_manufacturer,all_tcp_ports_are_443= getSavedResults(file_store_name_with_extension)
    if message == "Invalid ip":
      return "-1"
    if found:
      return "1"
    else:
      return "0"
  return

@application.route('/archive')
def archive_load():
  archive=[]
  connt1 = sqlite3.connect(databasename, uri=True)
  curt1 = connt1.cursor()

  curt1.execute('select * from '+ files_names_table)
  records = curt1.fetchall()
  if len(records)!=0:
    for row in records: 
      # print(row[1]) 
      archive.append([row[0],row[1][14:],row[2]])

  # print(archive)
  connt1.close()
  return render_template('archive.html',archive=archive)

@application.route('/help')
def help_load():
  
  return render_template('help.html')

@application.route('/dataset', defaults={'req_path': ''})
@application.route('/<path:req_path>')
def dir_listing(req_path):
    
    BASE_DIR = 'static/dataset/'
    if len(req_path):
      req_path = req_path[8:]
    # Joining the base and the requested path
    abs_path = os.path.join(BASE_DIR, req_path)
    #print(abs_path)
    # Return 404 if path doesn't exist
    if not os.path.exists(abs_path):
        return abs_path +   " doesn't exist "

    # Check if path is a file and serve
    if os.path.isfile(abs_path):
        return send_file(abs_path)

    # Show directory contents
    files = os.listdir(abs_path)
    
    return render_template('dataset.html', files=files)
  

@application.route('/wp-includes/wlwmanifest.xml')
def wlwmanifest():
  
  return render_template('wp-includes/wlwmanifest.xml')
  

@application.route('/')
def index_load():
  # print("index")
  sourceData=[]
  overall_analysis=[]
  dual_analysis=[]
  generate3rdFile_df_array=[]
  success = False
  ips_dst = []
  message = ""
  security_comment = ""
  all_remote_ips_has_NameServer = False
  connected_to_manufacturer = False
  all_tcp_ports_are_443 = True
  if "file_store_name_with_extension" in request.cookies:    
    file_store_name_with_extension = request.cookies.get('file_store_name_with_extension')
    print("previous file found")    
    sourceData,overall_analysis, dual_analysis,generate3rdFile_df_array,success,ips_dst,message,security_comment,all_remote_ips_has_NameServer,connected_to_manufacturer,all_tcp_ports_are_443 = getSavedResults(file_store_name_with_extension)
    if success:
      res = make_response(render_template('index.html',sourceData=sourceData,overall_analysis=overall_analysis,dual_analysis=dual_analysis,generate3rdFile_df_array=generate3rdFile_df_array,success=success,security_comment=security_comment,all_remote_ips_has_NameServer=all_remote_ips_has_NameServer,connected_to_manufacturer=connected_to_manufacturer,all_tcp_ports_are_443=all_tcp_ports_are_443))
      res.set_cookie('viewed_results','1') 
      return res

  return render_template('index.html',sourceData=sourceData,overall_analysis=overall_analysis,dual_analysis=dual_analysis,generate3rdFile_df_array=generate3rdFile_df_array,ips_dst=ips_dst,message=message,security_comment=security_comment,all_remote_ips_has_NameServer=all_remote_ips_has_NameServer,connected_to_manufacturer=connected_to_manufacturer,all_tcp_ports_are_443=all_tcp_ports_are_443)

@application.route('/classifynormal')
def classifynormal(): # copy of index  (2)
  print("classifynormal")
  sourceData=[]
  overall_analysis=[]
  dual_analysis=[]
  generate3rdFile_df_array =[]
  success = False
  ips_dst = []
  message = ""
  security_comment = ""
  all_remote_ips_has_NameServer = False
  connected_to_manufacturer = False
  all_tcp_ports_are_443 = True
  if "file_store_name_with_extension" in request.cookies:    
    file_store_name_with_extension = request.cookies.get('file_store_name_with_extension')
    print("previous file found")    
    sourceData,overall_analysis, dual_analysis,generate3rdFile_df_array,success,ips_dst,message,security_comment,all_remote_ips_has_NameServer,connected_to_manufacturer,all_tcp_ports_are_443 = getSavedResults(file_store_name_with_extension)
    if success:
      res = make_response(render_template('classifynormal.html',sourceData=sourceData,overall_analysis=overall_analysis,dual_analysis=dual_analysis,success=success,security_comment=security_comment,all_remote_ips_has_NameServer=all_remote_ips_has_NameServer,connected_to_manufacturer=connected_to_manufacturer,all_tcp_ports_are_443=all_tcp_ports_are_443))
      res.set_cookie('viewed_results','1') 
      return res

  return render_template('classifynormal.html',sourceData=sourceData,overall_analysis=overall_analysis,dual_analysis=dual_analysis,generate3rdFile_df_array=generate3rdFile_df_array,ips_dst=ips_dst,message=message,security_comment=security_comment,all_remote_ips_has_NameServer=all_remote_ips_has_NameServer,connected_to_manufacturer=connected_to_manufacturer,all_tcp_ports_are_443=all_tcp_ports_are_443)

@application.route('/post_file_for_analysing',methods=['POST'])
def post_file_for_analysing():  
  sourceData=[]
  overall_analysis=[]
  process = True
  print("post_file_for_analysing")
  if request.method == 'POST':
    if "viewed_results" in request.cookies:    
      viewed_results = request.cookies.get('viewed_results')
      print (viewed_results)
      if viewed_results == '0':
        print(viewed_results)
        process= False

  res = make_response(render_template('index.html',status=1)) 
  # if not dontprocess:
  
  if process:
    # print("process")
    IOTIP = request.args['IOTIP']
    f = request.files['file']
    file_store_name_with_extension = secure_filename(request.args['devicetype']+str(datetime.now()))+".pcapng"
    f.save("uploadedFiles/"+file_store_name_with_extension)
    status = Analyse_cap_threads_controller(IOTIP,request.args['devicetype'],"uploadedFiles/"+file_store_name_with_extension)
    res = make_response(render_template('index.html',status=status)) 
    res.set_cookie('file_store_name_with_extension',file_store_name_with_extension) 
    res.set_cookie('viewed_results','0') 
    res.set_cookie('IOTIP',IOTIP) 
    return res 
  else:
    print("not process")
    return redirect(url_for('index_load'))
    
@application.route('/post_file_for_analysing_2',methods=['POST'])
def post_file_for_analysing_2():  
  sourceData=[]
  overall_analysis=[]
  process = True
  print("post_file_for_analysing_2")
  if request.method == 'POST':
    if "viewed_results" in request.cookies:    
      viewed_results = request.cookies.get('viewed_results')
      # print (viewed_results)
      if viewed_results == '0':
        # print(viewed_results)
        process= False

  res = make_response(render_template('index.html',status=1)) 
  # if not dontprocess:
  
  if process:
    # print("process")
    IOTIP = request.args['IOTIP']
    f = request.files['file']
    file_store_name_with_extension = secure_filename(request.args['devicetype']+str(datetime.now()))+".pcapng"
    f.save("uploadedFiles/"+file_store_name_with_extension)
    status = Analyse_cap_threads_controller_2(IOTIP,request.args['devicetype'],"uploadedFiles/"+file_store_name_with_extension)
    res = make_response(render_template('classifynormal.html',status=status)) 
    res.set_cookie('file_store_name_with_extension',file_store_name_with_extension) 
    res.set_cookie('viewed_results','0') 
    res.set_cookie('IOTIP',IOTIP) 
    return res 
  else:
    # print("not process")
    return redirect(url_for('classifynormal'))


@application.route('/delete_record',methods=['POST'])
def delete_record():
  file_store_name_with_extension = request.args.get('file_store_name_with_extension')
  # print("not found, create record")
  sqlite_insert_query = """DELETE FROM files_names_table WHERE upload_file_name = ?;"""
  data_tuple = ("uploadedFiles/"+file_store_name_with_extension,)
  print(data_tuple)
  conn = sqlite3.connect(databasename, uri=True)
  cur = conn.cursor()
  cur.execute(sqlite_insert_query,data_tuple)
  conn.commit()
  conn.close()
  return "1"

@application.route('/check_ip_valid',methods=['POST'])
def check_ip_valid():  
  ip_to_check = request.args.get('IOTIP')
  ip_numbers = ip_to_check.split(".")
  if len(ip_numbers) != 4:
    return "-1"  # invalid
  for x in ip_numbers:
    if not x.isdigit():
      return "-1"  
  if int(ip_numbers[0]) == 0 or int(ip_numbers[3]) == 0 :
    return "-1"
  for x in ip_numbers:
    if int(x) > 254 or int(x) < 0:
      return "-1" 
  return "0" 

if __name__ == '__main__': 
  application.run(debug=True,host="0.0.0.0",use_reloader=True,port=8000)