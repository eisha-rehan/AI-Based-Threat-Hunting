import pandas as pd
import numpy as np
from sklearn.model_selection import StratifiedKFold
from sklearn.metrics import accuracy_score


#change path of all csv files accordingly.
PATHS = [
    '/Users/fatimaanwar/Documents/Semester 7/Info Sec/Project/testdata-intrusion/Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv',
    '/Users/fatimaanwar/Documents/Semester 7/Info Sec/Project/testdata-intrusion/Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv',
    '/Users/fatimaanwar/Documents/Semester 7/Info Sec/Project/testdata-intrusion/Friday-WorkingHours-Morning.pcap_ISCX.csv',
    '/Users/fatimaanwar/Documents/Semester 7/Info Sec/Project/testdata-intrusion/Monday-WorkingHours.pcap_ISCX.csv',
    '/Users/fatimaanwar/Documents/Semester 7/Info Sec/Project/testdata-intrusion/Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv',
    '/Users/fatimaanwar/Documents/Semester 7/Info Sec/Project/testdata-intrusion/Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv',
    '/Users/fatimaanwar/Documents/Semester 7/Info Sec/Project/testdata-intrusion/Tuesday-WorkingHours.pcap_ISCX.csv',
    '/Users/fatimaanwar/Documents/Semester 7/Info Sec/Project/testdata-intrusion/Wednesday-workingHours.pcap_ISCX.csv'
    
]
df = pd.read_csv(PATHS[0])
for i in range(1,len(PATHS)):
    temp = pd.read_csv(PATHS[i])
    df = pd.concat([df,temp])


m = df.loc[df[' Flow Packets/s'] != np.inf,' Flow Packets/s'].max()
df[' Flow Packets/s'].replace(np.inf,m,inplace=True)
m = df.loc[df['Flow Bytes/s'] != np.inf,'Flow Bytes/s'].max()
df['Flow Bytes/s'].replace(np.inf,m,inplace=True)

null_values = df.isna().sum()
null_values[null_values >0]

null_index = np.where(df['Flow Bytes/s'].isnull())[0]
df.dropna(inplace = True)


temp = df[df[' Label'] == 'BENIGN']
temp[' Destination Port'].describe()
temp = temp.sample(frac = 0.1)


df = df[df[' Label'] != 'BENIGN']
df = pd.concat([df,temp])



df['folds'] = 0
skf = StratifiedKFold(n_splits=10, random_state=42, shuffle=True)
for i, (_, test_index) in enumerate(skf.split(df[[' Destination Port']], df[' Label'])):
    df.iloc[test_index, -1] = i


col = [' Destination Port', ' Flow Duration', ' Total Fwd Packets',
       ' Total Backward Packets', 'Total Length of Fwd Packets',
       ' Total Length of Bwd Packets', ' Fwd Packet Length Max',
       ' Fwd Packet Length Min', ' Fwd Packet Length Mean',
       ' Fwd Packet Length Std', 'Bwd Packet Length Max',
       ' Bwd Packet Length Min', ' Bwd Packet Length Mean',
       ' Bwd Packet Length Std', 'Flow Bytes/s', ' Flow Packets/s',
       ' Flow IAT Mean', ' Flow IAT Std', ' Flow IAT Max', ' Flow IAT Min',
       'Fwd IAT Total', ' Fwd IAT Mean', ' Fwd IAT Std', ' Fwd IAT Max',
       ' Fwd IAT Min', 'Bwd IAT Total', ' Bwd IAT Mean', ' Bwd IAT Std',
       ' Bwd IAT Max', ' Bwd IAT Min', 'Fwd PSH Flags', ' Bwd PSH Flags',
       ' Fwd URG Flags', ' Bwd URG Flags', ' Fwd Header Length',
       ' Bwd Header Length', 'Fwd Packets/s', ' Bwd Packets/s',
       ' Min Packet Length', ' Max Packet Length', ' Packet Length Mean',
       ' Packet Length Std', ' Packet Length Variance', 'FIN Flag Count',
       ' SYN Flag Count', ' RST Flag Count', ' PSH Flag Count',
       ' ACK Flag Count', ' URG Flag Count', ' CWE Flag Count',
       ' ECE Flag Count', ' Down/Up Ratio', ' Average Packet Size',
       ' Avg Fwd Segment Size', ' Avg Bwd Segment Size',
       ' Fwd Header Length.1', 'Fwd Avg Bytes/Bulk', ' Fwd Avg Packets/Bulk',
       ' Fwd Avg Bulk Rate', ' Bwd Avg Bytes/Bulk', ' Bwd Avg Packets/Bulk',
       'Bwd Avg Bulk Rate', 'Subflow Fwd Packets', ' Subflow Fwd Bytes',
       ' Subflow Bwd Packets', ' Subflow Bwd Bytes', 'Init_Win_bytes_forward',
       ' Init_Win_bytes_backward', ' act_data_pkt_fwd',
       ' min_seg_size_forward', 'Active Mean', ' Active Std', ' Active Max',
       ' Active Min', 'Idle Mean', ' Idle Std', ' Idle Max', ' Idle Min']


train_df= df[df['folds'] != 5]
valid_df = df[df['folds'] == 5]


from sklearn.preprocessing import MinMaxScaler
scaler = MinMaxScaler()
train_df[col] = scaler.fit_transform(train_df[col])
valid_df[col] = scaler.transform(valid_df[col])


X_train = train_df[col]
y_train = train_df[' Label']
X_test = valid_df[col]
y_test = valid_df[' Label']


import pickle

with open('/Users/fatimaanwar/Documents/Semester 7/Info Sec/Project/AI-Based-Threat-Hunting/KNN_Model.pkl', 'rb') as f:  #path of .pkl file
    model = pickle.load(f)

value = X_test[:1].values.tolist()
pred = model.predict(X_test[:1])
print(f"The prediction for ", value, " is: ",pred[0])