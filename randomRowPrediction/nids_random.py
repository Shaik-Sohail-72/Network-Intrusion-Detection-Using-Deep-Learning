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
import tensorflow as tf
import pickle
data_Validate=pd.read_csv('fs_new validation project.csv')
columns = (['protocol_type','service','flag','logged_in','count','srv_serror_rate','srv_rerror_rate','same_srv_rate','diff_srv_rate','dst_host_count','dst_host_srv_count','dst_host_same_srv_rate','dst_host_diff_srv_rate','dst_host_same_src_port_rate','dst_host_serror_rate','dst_host_rerror_rate','attack'])
data_Validate.columns=columns
protocol_type_le = LabelEncoder()
service_le = LabelEncoder()
flag_le = LabelEncoder()
data_Validate['protocol_type'] = protocol_type_le.fit_transform(data_Validate['protocol_type'])
data_Validate['service'] = service_le.fit_transform(data_Validate['service'])
data_Validate['flag'] = flag_le.fit_transform(data_Validate['flag'])
df_validate=data_Validate.copy(deep=True)
x_validate=df_validate.drop(['attack'],axis=1)

label_encoder = LabelEncoder() 
scaler=MinMaxScaler()
x1=x_validate.copy(deep=True)
scaler=MinMaxScaler()
scaler.fit(x1)
scaled_data=scaler.transform(x1)
scaled_data=pd.DataFrame(scaled_data)
scaled_data.columns= x1.columns
x_validate=scaled_data

knn_bin = pickle.load(open('knn_fs_bin.sav', 'rb'))
knn_multi = pickle.load(open('knn_fs.sav', 'rb'))
randfor_bin = pickle.load(open('randomfor_fs_bin.sav', 'rb'))
randfor_multi = pickle.load(open('randomfor_fs_multi.sav', 'rb'))
cnn_bin= tf.keras.models.load_model('cnn_fs_bin.h5')
cnn_multi= tf.keras.models.load_model('cnn_fs_multi.h5')
lstm_bin= tf.keras.models.load_model('lstm_fs_bin_class.h5')
lstm_multi= tf.keras.models.load_model('lstm_fs_multi_class.h5')

def advance():
    print("KNN ALGORITHM:")
    tp=x_validate.sample()
    val_knn=knn_bin.predict(tp)
    if(val_knn==1):
        print('Binary class Type: ATTACK')
        tp_knn=knn_multi.predict(tp)
        print('Multi class Type:',tp_knn)
        if(tp_knn=='dos'):
            print('A Denial-of-Service (DoS) attack is an attack meant to shut down a machine or network, making it inaccessible to its intended users. DoS attacks accomplish this by flooding the target with traffic, or sending it information that triggers a crash. In both instances, the DoS attack deprives legitimate users (i.e. employees, members, or account holders) of the service or resource they expected.')
        elif(tp_knn=='probe'):
            print('Probing is another type of attack in which the intruder scans network devices to determine weakness in topology design or some opened ports and then use them in the future for illegal access to personal information.')
        elif(tp_knn=='r2l'):
            print('Remote to user (R2L) is a type of computer network attacks, in which an intruder sends set of packets to another computer or server over a network where he/she does not have permission to access as a local user.')
        elif(tp_knn=='u2r'):
            print('User to root attacks (U2R) is an another type of attack where the intruder tries to access the network resources as a normal user,  and after several attempts, the intruder becomes as a full access user.')
    elif(val_knn==0):
        print('Binary class Type: NORMAL')
        tp_knn=knn_multi.predict(tp)
        print('Multi class Type:',tp_knn)
        if(tp_knn=='normal'):
            print('this is safe.')

    print("RANDOM FOREST ALGORITHM:")    
    val_randfor=randfor_bin.predict(tp)
    if(val_randfor==1):
        print('Binary class Type: ATTACK')
        tp_randfor=randfor_multi.predict(tp)
        print('Multi class type:',tp_randfor)
        if(tp_randfor=='Dos'):
            print('A Denial-of-Service (DoS) attack is an attack meant to shut down a machine or network, making it inaccessible to its intended users. DoS attacks accomplish this by flooding the target with traffic, or sending it information that triggers a crash. In both instances, the DoS attack deprives legitimate users (i.e. employees, members, or account holders) of the service or resource they expected.')
        elif(tp_randfor=='Probe'):
            print('Probing is another type of attack in which the intruder scans network devices to determine weakness in topology design or some opened ports and then use them in the future for illegal access to personal information.')
        elif(tp_randfor=='R2L'):
            print('Remote to user (R2L) is a type of computer network attacks, in which an intruder sends set of packets to another computer or server over a network where he/she does not have permission to access as a local user.')
        elif(tp_randfor=='U2R'):
            print('User to root attacks (U2R) is an another type of attack where the intruder tries to access the network resources as a normal user,  and after several attempts, the intruder becomes as a full access user.')
    elif(val_randfor==0):
        print('Binary class Type: NORMAL')
        tp_randfor=randfor_multi.predict(tp)
        print('Multi class Type:',tp_randfor)
        if(tp_randfor=='normal'):
            print('this is safe.')

    print("CNN ALGORITHM:")
    val_cnn=cnn_bin.predict(tp,verbose=0)
    for i in val_cnn:
        for j in i:
            val_cnn=round(j)
    if(val_cnn==1):
        print('Binary class Type: ATTACK')
        tp_cnn=cnn_multi.predict(tp,verbose=0)
        l=[]
        for i in tp_cnn:
            for j in i:
                l.append(round(j))
        if(l[1]==1):
            print('Multi class Type:Dos')
            print('A Denial-of-Service (DoS) attack is an attack meant to shut down a machine or network, making it inaccessible to its intended users. DoS attacks accomplish this by flooding the target with traffic, or sending it information that triggers a crash. In both instances, the DoS attack deprives legitimate users (i.e. employees, members, or account holders) of the service or resource they expected.')
        elif(l[2]==1):
            print('Multi class Type:Probe')
            print('Probing is another type of attack in which the intruder scans network devices to determine weakness in topology design or some opened ports and then use them in the future for illegal access to personal information.')
        elif(l[4]==1):
            print('Multi class Type:R2L')
            print('Remote to user (R2L) is a type of computer network attacks, in which an intruder sends set of packets to another computer or server over a network where he/she does not have permission to access as a local user.')
        elif(l[3]==1):
            print('Multi class Type:U2R')
            print('User to root attacks (U2R) is an another type of attack where the intruder tries to access the network resources as a normal user,  and after several attempts, the intruder becomes as a full access user.')
        elif(l[0]==1):
            print('Multi class Type:NORMAL')
            print('This is safe')
        else:
            print("Multi class Type:can't be predicted")
            print('Unknown!')
    elif(val_cnn==0):
        print('Binary class Type: NORMAL')
        tp_cnn=cnn_multi.predict(tp,verbose=0)
        l=[]
        for i in tp_cnn:
            for j in i:
                l.append(round(j))
        if(l[1]==1):
            print('Multi class Type:Dos')
            print('A Denial-of-Service (DoS) attack is an attack meant to shut down a machine or network, making it inaccessible to its intended users. DoS attacks accomplish this by flooding the target with traffic, or sending it information that triggers a crash. In both instances, the DoS attack deprives legitimate users (i.e. employees, members, or account holders) of the service or resource they expected.')
        elif(l[2]==1):
            print('Multi class Type:Probe')
            print('Probing is another type of attack in which the intruder scans network devices to determine weakness in topology design or some opened ports and then use them in the future for illegal access to personal information.')
        elif(l[4]==1):
            print('Multi class Type:R2L')
            print('Remote to user (R2L) is a type of computer network attacks, in which an intruder sends set of packets to another computer or server over a network where he/she does not have permission to access as a local user.')
        elif(l[3]==1):
            print('Multi class Type:U2R')
            print('User to root attacks (U2R) is an another type of attack where the intruder tries to access the network resources as a normal user,  and after several attempts, the intruder becomes as a full access user.')
        elif(l[0]==1):
            print('Multi class Type:Normal')
            print('This is safe')
        else:
            print("Multi class Type:can't be predicted")
            print('Unknown!')

    print("LSTM ALGORITHM:")
    val_lstm=lstm_bin.predict(tp,verbose=0)
    for i in val_lstm:
        for j in i:
            val_lstm=round(j)
    if(val_lstm==1):
        print('Binary class Type: ATTACK')
        tp_lstm=lstm_multi.predict(tp,verbose=0)
        l=[]
        for i in tp_lstm:
            for j in i:
                l.append(round(j))
        if(l[1]==1):
            print('Multi class Type:Dos')
            print('A Denial-of-Service (DoS) attack is an attack meant to shut down a machine or network, making it inaccessible to its intended users. DoS attacks accomplish this by flooding the target with traffic, or sending it information that triggers a crash. In both instances, the DoS attack deprives legitimate users (i.e. employees, members, or account holders) of the service or resource they expected.')
        elif(l[2]==1):
            print('Multi class Type:Probe')
            print('Probing is another type of attack in which the intruder scans network devices to determine weakness in topology design or some opened ports and then use them in the future for illegal access to personal information.')
        elif(l[4]==1):
            print('Multi class Type:R2L')
            print('Remote to user (R2L) is a type of computer network attacks, in which an intruder sends set of packets to another computer or server over a network where he/she does not have permission to access as a local user.')
        elif(l[3]==1):
            print('Multi class Type:U2R')
            print('User to root attacks (U2R) is an another type of attack where the intruder tries to access the network resources as a normal user,  and after several attempts, the intruder becomes as a full access user.')
        elif(l[0]==1):
            print('Multi class Type:normal')
            print('This is safe')
        else:
            print("Multi class Type:can't be predicted")
            print('Unknown!')
    elif(round(val_lstm)==0):
        print('Binary class Type: NORMAL')
        tp_lstm=lstm_multi.predict(tp,verbose=0)
        l=[]
        for i in tp_lstm:
            for j in i:
                l.append(round(j))
        if(l[1]==1):
            print('Multi class Type:Dos')
            print('A Denial-of-Service (DoS) attack is an attack meant to shut down a machine or network, making it inaccessible to its intended users. DoS attacks accomplish this by flooding the target with traffic, or sending it information that triggers a crash. In both instances, the DoS attack deprives legitimate users (i.e. employees, members, or account holders) of the service or resource they expected.')
        elif(l[2]==1):
            print('Multi class Type:Probe')
            print('Probing is another type of attack in which the intruder scans network devices to determine weakness in topology design or some opened ports and then use them in the future for illegal access to personal information.')
        elif(l[4]==1):
            print('Multi class Type:R2L')
            print('Remote to user (R2L) is a type of computer network attacks, in which an intruder sends set of packets to another computer or server over a network where he/she does not have permission to access as a local user.')
        elif(l[3]==1):
            print('Multi class Type:U2R')
            print('User to root attacks (U2R) is an another type of attack where the intruder tries to access the network resources as a normal user,  and after several attempts, the intruder becomes as a full access user.')
        elif(l[0]==1):
            print('Multi class Type:normal')
            print('This is safe')
        else:
            print("Multi class Type:can't be predicted")
            print('Unknown!')

advance()
            
    
    
