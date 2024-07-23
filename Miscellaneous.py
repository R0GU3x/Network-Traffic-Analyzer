import csv
import os
import ipaddress

def write_dict_to_csv(data:dict):
    file = 'output.csv'
    file_exists = os.path.isfile(file) and os.path.getsize(file) > 0
    headers = data.keys()
    with open(file, 'a', newline='') as file:
        writer = csv.DictWriter(file, fieldnames=headers)
        if not file_exists:
            writer.writeheader()
        writer.writerow(data)

def fetch_all_ip_files():
    def is_valid_ip(ip_str):
        try:
            ipaddress.ip_address(ip_str)
            return True
        except ValueError:
            return False
    
    for file in os.listdir('IP Blacklist'):
        with open('blacklist.txt', 'a') as f1:
            with open(os.path.join('IP Blacklist', file), 'r') as f2:
                data = f2.readlines()
                new_data = [i.split()[0].split('/')[0] for i in data]
            for i in new_data:
                if is_valid_ip(i):
                    f1.write(i + '\n')

# ================================================
# ================================================

# import pandas as pd
# from sklearn.preprocessing import StandardScaler
# import joblib
# from sqlalchemy import create_engine
# import pymysql
# import time

# # Load your pre-trained models
# kmeans = joblib.load('kmeans_model.pkl')
# iso_forest = joblib.load('iso_forest_model.pkl')

# # Database connection details
# DB_USER = 'username'
# DB_PASSWORD = 'password'
# DB_HOST = 'host'
# DB_NAME = 'db_name'
# TABLE_NAME = 'network_analysis'

# # Create database engine
# engine = create_engine(f'mysql+pymysql://{DB_USER}:{DB_PASSWORD}@{DB_HOST}/{DB_NAME}')

# def preprocess_data(data_dict):
#     df = pd.DataFrame([data_dict])
    
#     # Example preprocessing steps
#     df['time'] = pd.to_datetime(df['time'])
#     df = df.dropna()
    
#     # Feature scaling
#     scaler = StandardScaler()
#     df[['src_ip_count', 'dst_ip_count', 'src_port_count', 'dst_port_count', 'data_transfer_rate', 'total_datapacket']] = scaler.fit_transform(
#         df[['src_ip_count', 'dst_ip_count', 'src_port_count', 'dst_port_count', 'data_transfer_rate', 'total_datapacket']])
    
#     return df

# def run_ml_models(df):
#     df['kmeans_cluster'] = kmeans.predict(df)
#     df['anomaly_score'] = iso_forest.decision_function(df)
#     df['is_anomaly'] = iso_forest.predict(df)
#     return df

# def push_to_mysql(df):
#     df.to_sql(TABLE_NAME, engine, if_exists='append', index=False)

# # Simulated continuous data extraction
# while True:
#     # Replace this with your actual data extraction logic
#     data_dict = {
#         'serial': '12345',
#         'time': '2024-07-17 12:34:56',
#         'src_ip': '192.168.1.1',
#         'src_port': 12345,
#         'dst_ip': '192.168.1.2',
#         'dst_port': 80,
#         'proto': 'TCP',
#         'flag': 'S',
#         'ttl': 64,
#         'size': 1500,
#         'alert': 0,
#         'cluster': 0,
#         'src_ip_count': 10,
#         'dst_ip_count': 5,
#         'src_port_count': 3,
#         'dst_port_count': 2,
#         'data_transfer_rate': 1000,
#         'src_dst_ip_pair': '192.168.1.1_192.168.1.2',
#         'src_dst_ip_pair_count': 1,
#         'total_datapacket': 20
#     }

#     # Preprocess data
#     df = preprocess_data(data_dict)

#     # Run ML models
#     df = run_ml_models(df)

#     # Push to MySQL
#     push_to_mysql(df)

#     # Wait for a while before processing the next data point
#     time.sleep(1)  # Adjust the sleep time based on your data extraction rate

