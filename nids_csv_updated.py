import numpy as np
import sys
from sklearn.metrics import accuracy_score, confusion_matrix
import pandas as pd
from sklearn.preprocessing import LabelEncoder
from sklearn.preprocessing import MinMaxScaler
import sklearn
from sklearn.neighbors import KNeighborsClassifier
import os
#from google.colab import drive
from sklearn.preprocessing import LabelEncoder
from sklearn.preprocessing import Normalizer
import tensorflow as tf
import pickle
#Uploaded_files\fs_test.csv
path='Uploaded_files/'
val=sys.argv[1]
path+=sys.argv[2];
#path='/content/gdrive/My Drive/fs_test.csv'
f=open(path)
data_Validate=pd.read_csv(f)
columns = (['protocol_type','service','flag','logged_in','count','srv_serror_rate','srv_rerror_rate','same_srv_rate','diff_srv_rate','dst_host_count','dst_host_srv_count','dst_host_same_srv_rate','dst_host_diff_srv_rate','dst_host_same_src_port_rate','dst_host_serror_rate','dst_host_rerror_rate'])
data_Validate.columns=columns
protocol_type_le = LabelEncoder()
service_le = LabelEncoder()
flag_le = LabelEncoder()
data_Validate['protocol_type'] = protocol_type_le.fit_transform(data_Validate['protocol_type'])
data_Validate['service'] = service_le.fit_transform(data_Validate['service'])
data_Validate['flag'] = flag_le.fit_transform(data_Validate['flag'])
df_validate=data_Validate.copy(deep=True)
x_validate=df_validate.copy(deep=True)
label_encoder = LabelEncoder() 
scaler=MinMaxScaler()
x1=x_validate.copy(deep=True)
scaler=MinMaxScaler()
scaler.fit(x1)
scaled_data=scaler.transform(x1)
scaled_data=pd.DataFrame(scaled_data)
scaled_data.columns= x1.columns
x_validate=pd.DataFrame(scaled_data)
print(x_validate.shape)
if(val=='knn'):
  knn_bin = pickle.load(open('knn_binary_class.sav', 'rb'))
  knn_multi = pickle.load(open('knn_multi_class.sav', 'rb'))
  x_predict_bin=knn_bin.predict(x_validate) 
  x_predict_multi=knn_multi.predict(x_validate) 
  l=[]
  for i in x_predict_bin:
    if(i == 0):
      l.append('Normal')
    else:
      l.append('Attack')
  l=np.array(l)
  df_validate['binary class']=l
  df_validate['multi class']=x_predict_multi
  df_validate.to_csv(path,index=False)
elif(val=='rf'):
  rf_bin = pickle.load(open('random_forest_binary_class.sav', 'rb'))
  rf_multi = pickle.load(open('random_forest_multi_class.sav', 'rb'))
  x_predict_bin=rf_bin.predict(x_validate) 
  x_predict_multi=rf_multi.predict(x_validate) 
  l=[]
  for i in x_predict_bin:
    if(i == 0):
      l.append('Normal')
    else:
      l.append('Attack')
  l=np.array(l)
  df_validate['binary class']=l
  df_validate['multi class']=x_predict_multi
  df_validate.to_csv(path,index=False)
elif(val=='cnn'):
  x_validate=df_validate.iloc[:,0:16]
  scaler = Normalizer().fit(x_validate)
  x_validate = scaler.transform(x_validate)
  np.set_printoptions(precision=3)
  cnn_bin=tf.keras.models.load_model('latest_cnn_bin.h5')
  cnn_multi=tf.keras.models.load_model('latest_cnn_multiclass.h5')
  x_validate = np.reshape(x_validate, (x_validate.shape[0],1,x_validate.shape[1]))
  x_predict_bin=cnn_bin.predict(x_validate,verbose=False)
  x_validate=df_validate.iloc[:,0:16]
  scaler = Normalizer().fit(x_validate)
  x_validate = scaler.transform(x_validate)
  np.set_printoptions(precision=3)
  x_validate = np.reshape(x_validate, (x_validate.shape[0],x_validate.shape[1],1))
  x_predict_multi=cnn_multi.predict(x_validate,verbose=False)
  l=[]
  l1=[]
  for i in x_predict_multi:
    te=[]
    for j in i:
      te.append(round(j))
    l.append(te)
  res=[]
  for i in l:
    if(i[0]==1):
        res.append('Dos')
    elif(i[1]==1):
        res.append('Normal')
    elif(i[2]==1):
        res.append('Probe')
    elif(i[3]==1):
        res.append('R2L')
    elif(i[4]==1):
        res.append('U2R')
    else:
        res.append('Normal')
  l=np.array(res)
  l1=[]
  for i in x_predict_bin:
    for j in i:
        l1.append(round(j))
  res=[]
  for i in l1:
    if(i==0):
        res.append('Normal')
    else:
        res.append('Attack')
  l1=np.array(res)
  df_validate['binary class']=l1
  print(l)
  df_validate['multi class']=l
  df_validate.to_csv(path,index=False)
elif(val=='lstm'):
  lstm_bin=tf.keras.models.load_model('lstm_latest_bin.h5')
  lstm_multi=tf.keras.models.load_model('lstm_latest_multiclass.h5')
  x_validate=df_validate.iloc[:,0:16]
  scaler = Normalizer().fit(x_validate)
  x_validate = scaler.transform(x_validate)
  np.set_printoptions(precision=3)
  x_validate = np.reshape(x_validate, (x_validate.shape[0],1, x_validate.shape[1]))
  x_predict_bin=lstm_bin.predict(x_validate,verbose=False)
  x_predict_multi=lstm_multi.predict(x_validate,verbose=False)
  l=[]
  l1=[]
  for i in x_predict_multi:
    te=[]
    for j in i:
      te.append(round(j))
    l.append(te)
  res=[]
  for i in l:
    if(i[0]==1):
        res.append('Dos')
    elif(i[1]==1):
        res.append('Normal')
    elif(i[2]==1):
        res.append('Probe')
    elif(i[3]==1):
        res.append('R2L')
    elif(i[4]==1):
        res.append('U2R')
    else:
        res.append('Normal')
  l=np.array(res)
  l1=[]
  for i in x_predict_bin:
    for j in i:
        l1.append(round(j))
  res=[]
  for i in l1:
    if(i==0):
        res.append('Normal')
    else:
        res.append('Attack')
  l1=np.array(res)
  df_validate['binary class']=l1
  df_validate['multi class']=l
  df_validate.to_csv(path,index=False)
print('completed')
  
  


