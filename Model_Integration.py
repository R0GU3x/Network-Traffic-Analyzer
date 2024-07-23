import pandas as pd
import numpy as np
import pickle
from sklearn.preprocessing import LabelEncoder, StandardScaler
from sklearn.compose import ColumnTransformer
import ipaddress
import time

a = time.time()

# Load pre-trained models
with open('preprocessor.pkl', 'rb') as file:
    preprocessor = pickle.load(file)
with open('iso_forest_model.pkl', 'rb') as file:
    iso_forest_model = pickle.load(file)

# Preprocess the captured packet
def preprocess_packet(data):
    df = pd.DataFrame([data])
    
    # Encode categorical features
    le_proto = LabelEncoder()
    le_flag = LabelEncoder()
    df['proto'] = le_proto.fit_transform(df['proto'])
    df['flag'] = le_flag.fit_transform(df['flag'])

    def ip_to_int(ip_str):
        return int(ipaddress.ip_address(ip_str))

    df['src_ip'] = df['src_ip'].apply(ip_to_int)
    df['dst_ip'] = df['dst_ip'].apply(ip_to_int)

    # Add additional features
    df['src_ip_count'] = df.groupby('src_ip')['src_ip'].transform('count')
    df['dst_ip_count'] = df.groupby('dst_ip')['dst_ip'].transform('count')
    df['src_port_count'] = df.groupby('src_port')['src_port'].transform('count')
    df['dst_port_count'] = df.groupby('dst_port')['dst_port'].transform('count')
    df['data_transfer_rate'] = df['size'] / (df['ttl'] + 1)  # Avoid division by zero
    df['src_dst_ip_pair'] = df['src_ip'].astype(str) + '-' + df['dst_ip'].astype(str)
    df['Total'] = df.groupby('src_dst_ip_pair')['src_dst_ip_pair'].transform('count')
    
    # Ensure all required columns are present
    required_columns = [
        'serial', 'src_ip', 'dst_ip', 'src_port', 'dst_port', 'proto', 'flag', 'ttl', 'size',
        'src_ip_count', 'dst_ip_count', 'src_port_count', 'dst_port_count', 'data_transfer_rate', 'Total', 'time'
    ]
    for col in required_columns:
        if col not in df.columns:
            df[col] = 0  # Add missing columns with default value 0
    
    # Handle missing values
    df.fillna(0, inplace=True)
    
    # Ensure correct data types
    df = df.astype({
        'serial': 'int', 'src_ip': 'object', 'dst_ip': 'object', 'src_port': 'int', 'dst_port': 'int',
        'proto': 'int', 'flag': 'int', 'ttl': 'int', 'size': 'int', 'src_ip_count': 'int',
        'dst_ip_count': 'int', 'src_port_count': 'int', 'dst_port_count': 'int',
        'data_transfer_rate': 'float', 'Total': 'int', 'time': 'int'
    })

    return df

# Function to fetch real-time data and make predictions
def run(data):
    df = preprocess_packet(data)
    # print(df)
    
    # Print DataFrame columns and shapes before transformation
    # print("DataFrame columns and types before transformation:")
    # print(df.dtypes)
    # print("DataFrame shape before transformation:", df.shape)
    
    # Apply preprocessing transformations
    try:
        df_features = preprocessor.transform(df)
    except:
        return None
    
    # Print DataFrame shape after transformation
    # print("DataFrame shape after transformation:", df_features.shape)
    
    # Ensure the transformed data matches the model's expected input
    # print("Features after preprocessing:")
    # print(pd.DataFrame(df_features).head())
    
    # Make predictions with Isolation Forest
    df['predictions'] = iso_forest_model.predict(df_features)
    
    # Convert predictions to 0 (normal) and 1 (anomaly)
    df['predictions'] = df['predictions'].apply(lambda x: 1 if x == -1 else 0)
    
    # Store predictions in MySQL
    # store_predictions(df)

    alert = df.loc[0, 'alert']
    return alert

# def alert(predictions, serials):
#     alerts = []
#     for pred, serial in zip(predictions, serials):
#         alerts.append((pred, serial))
#     # Get the alerts
#     # alerts = alert(test_anomalies, serials_test)
#     return alerts

# Function to store predictions in MySQL
# def store_predictions(df):
#     alert = df.loc[0, 'alert']
#     print(alert)
    # Uncomment and configure the following code to store data in MySQL
    # import mysql.connector
    # conn = mysql.connector.connect(
    #     host='your_mysql_host',
    #     user='your_mysql_user',
    #     password='your_mysql_password',
    #     database='your_database'
    # )
    # cursor = conn.cursor()
    # for index, row in df.iterrows():
    #     sql = """INSERT INTO predictions_table (
    #                 time, src_ip, src_port, dst_ip, dst_port, proto, flag, ttl, size, alert,
    #                 src_ip_count, dst_ip_count, src_port_count, dst_port_count, data_transfer_rate, Total,
    #                 predictions
    #              ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)"""
    #     cursor.execute(sql, tuple(row))
    # conn.commit()
    # cursor.close()
    # conn.close()


# ================ TCP ===================
# data = {
#     'serial': 1, 
#     'time': 1721386942648.6956, 
#     'src_ip': '51.116.253.169', 
#     'src_port': 443, 
#     'dst_ip': '10.224.10.43', 
#     'dst_port': 60005, 
#     'proto': 'tcp', 
#     'flag': 'PSH ACK', 
#     'ttl': 109, 
#     'size': 335, 
#     'alert': 0
# }

# ============ UDP ========================
# data = {'serial': 1, 
#  'time': 1721434600973.1804, 
#  'src_ip': '10.224.10.149', 
#  'src_port': 56885, 
#  'dst_ip': '239.255.255.250', 
#  'dst_port': 3702, 
#  'proto': 'udp', 
#  'flag': 'VAIBS', 
#  'ttl': 1, 
#  'size': 698, 
#  'alert': 0}

# print(run(data))

# b = time.time() - a
# print(b%60)