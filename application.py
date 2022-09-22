
from flask import Flask,make_response,url_for,redirect, request, render_template,current_app, g, send_file
from sqlalchemy import false
from werkzeug.utils import secure_filename
from datetime import datetime
from iotnetworkmodel import resolve_hostname,analyseDeviceIP,analyseDeviceIPDualCommunications
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

application = Flask(__name__)

numberofrunningtasksmax = 1
num_running_processes = 0

databasename = 'static/_database.db'
files_names_table = 'files_names_table'
try:
  print(f'Checking if {databasename} exists or not...')
  conn = sqlite3.connect(databasename, uri=True)
  print(f'Database exists. Succesfully connected to {databasename}')
  conn.execute('CREATE TABLE IF NOT EXISTS ' + files_names_table + ' (id INTEGER PRIMARY KEY AUTOINCREMENT,upload_file_name TEXT UNIQUE NOT NULL,IOTIP TEXT, states INTEGER NOT NULL)')
  # status = 1 # file starting processing successfully
  # status = 2 # file is being processed
  # status = 3 # file finished processing
  print(f'Succesfully Created Table {files_names_table}')

except sqlite3.OperationalError as err:
  print('Database error,see log')
  print(err)

def Analyse_cap_threads_controller(IOTIP,file_store_name):
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
    t = Thread(target=analyseDeviceIP,args=[IOTIP,file_store_name])
    t.start()
    status = 1
    
  if len(records)>0:
    # print("found")
    status = 2
  

  # sql_update_query = """Update files_names_table set states = 1,startdate = ? where searchsentense = ?"""
  # data_tuple = (datetime.datetime.now(),searchtext)
  # curt.execute(sql_update_query,data_tuple)
  # connt.commit()
  # connt.close()
  

  
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

    return send_file(
        stream,
        as_attachment=True,
        attachment_filename=file_store_name_with_extension+'.zip'
    )

def getSavedResults(file_store_name_with_extension):
  if len("uploadedFiles/"+file_store_name_with_extension) > 5:
    xlsx_name = "uploadedFiles/"+file_store_name_with_extension+".xlsx"
    csv_name = "uploadedFiles/"+file_store_name_with_extension+".csv"
    dualcomm_name = "uploadedFiles/"+file_store_name_with_extension+"dualcomm.csv"
    if exists(xlsx_name) and exists(csv_name) and exists(dualcomm_name):
      df = pd.read_excel(xlsx_name)
      sourceData = df.to_numpy()
      overall_analysis_pd = pd.read_csv(csv_name)
      overall_analysis_np_array = overall_analysis_pd.iloc[: , -1].to_numpy()

      overall_analysis = [np.insert(overall_analysis_np_array ,0,overall_analysis_pd.columns.values[1])]  
      dual_analysis_pd = pd.read_csv(dualcomm_name)
      dual_analysis_np_array = dual_analysis_pd.to_numpy()

      # dual_analysis = [np.insert(dual_analysis_np_array ,0,dual_analysis_pd.columns.values[1])]  

      return sourceData,overall_analysis, dual_analysis_np_array,True
    else:
      return [],[],[],False
  else:
    return [],[],[],False

@application.route('/get_Saved_Results',methods=['POST'])
def get_Saved_Results():
  if "file_store_name_with_extension" in request.cookies:    
    file_store_name_with_extension = request.cookies.get('file_store_name_with_extension')
    sourceData , overall_analysis , dual_analysis , found = getSavedResults(file_store_name_with_extension)
    if found:
      return "1"
    else:
      return "0"
  return

@application.route('/')
def index_load():
  print("hi2")
  sourceData=[]
  overall_analysis=[]
  dual_analysis=[]
  success = False
  if "file_store_name_with_extension" in request.cookies:    
    file_store_name_with_extension = request.cookies.get('file_store_name_with_extension')
    print("previous file found")    
    sourceData,overall_analysis, dual_analysis,success = getSavedResults(file_store_name_with_extension)
    if success:
      res = make_response(render_template('index.html',sourceData=sourceData,overall_analysis=overall_analysis,dual_analysis=dual_analysis,success=success))
      res.set_cookie('viewed_results','1') 
      return res

  return render_template('index.html',sourceData=sourceData,overall_analysis=overall_analysis,dual_analysis=dual_analysis)

@application.route('/post_file_for_analysing',methods=['POST'])
def post_file_for_analysing():  
  sourceData=[]
  overall_analysis=[]
  process = True
  # print("process ",process)
  if request.method == 'POST':
    if "viewed_results" in request.cookies:    
      viewed_results = request.cookies.get('viewed_results')
      print (viewed_results)
      if viewed_results == '0':
        print(viewed_results)
        process= False
        # print("process ",process)

  print("process ",process)
  # res = make_response(render_template('index.html')) 
  # if (not dontprocess):
  print("hi")
  # file_store_name_with_extension = file_store_name_abs+".pcapng"
  res = make_response(render_template('index.html',status=1)) 
  # if not dontprocess:
  
  if process:
    print("process")
    IOTIP = request.args['IOTIP']
    f = request.files['file']
    file_store_name_with_extension = secure_filename(str(datetime.now()))+".pcapng"
    f.save("uploadedFiles/"+file_store_name_with_extension)
    status = Analyse_cap_threads_controller(IOTIP,"uploadedFiles/"+file_store_name_with_extension)
    res = make_response(render_template('index.html',status=status)) 
    res.set_cookie('file_store_name_with_extension',file_store_name_with_extension) 
    res.set_cookie('viewed_results','0') 
    return res 
  else:
    print("not process")
    # file_store_name_with_extension = "uploadedFiles/"+request.cookies.get('file_store_name_with_extension')
    # sourceData,overall_analysis,success = getSavedResults(file_store_name_with_extension)
    
    # res = make_response(render_template('index.html',sourceData=sourceData,overall_analysis=overall_analysis,success=success))
    # if success:
    #   res.set_cookie('viewed_results','1') 
    return redirect(url_for('index_load'))
    

  # sourceData,overall_analysis = analyseDeviceIP(IOTIP,file_store_name)
  # print(sourceData.to_numpy())
  # print(type(sourceData.to_numpy()))

  # print(overall_analysis_list_data)
  # print(type(overall_analysis_list_data))
  # overall_analysis_list_data = [np.array([item[1] for item in list(overall_analysis.items())])]
  # return render_template('index.html',sourceData = sourceData.to_numpy(),overall_analysis=overall_analysis_list_data)#,message=message,hiddenmessage=hiddenmessage,goodImage=goodImage,serverStates=serverStates)
    
  # return render_template('index.html')



@application.route('/results',methods=['POST','GET'])
def results():
  return render_template('results.html')

if __name__ == '__main__': 
  application.run(debug=True,host="0.0.0.0",use_reloader=True,port=80)