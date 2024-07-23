import pandas as pd
from sklearn.preprocessing import StandardScaler
from sklearn.ensemble import IsolationForest
from sklearn.cluster import KMeans
from sklearn.model_selection import train_test_split
import PreProcessing
from sklearn.preprocessing import StandardScaler, OneHotEncoder , LabelEncoder
import ipaddress
# from your_preprocessing_script import preprocess_packet

# Preprocess the packet data
def preprocess_packet(packet:dict):
    # Extract features from the packet
    # features = [
    #     packet['time'],
    #     packet['src_ip'],
    #     packet['src_port'],
    #     packet['dst_ip'],
    #     packet['dst_port'],
    #     packet['proto'],
    #     packet['flag'],
    #     packet['ttl'],
    #     packet['size']
    # ]
    features = list(packet.values())
    # Create a pandas dataframe from the features
    df = pd.DataFrame(features, columns=list(packet.keys()))
    # Scale the features using StandardScaler
    # scaler = StandardScaler()
    # df_scaled = scaler.fit_transform(df)
    # pre_process = PreProcessing.ML()

    def ip_to_int(self, ip_str):
        return int(ipaddress.ip_address(ip_str))
    
    le = LabelEncoder()
    df['proto'] = le.fit_transform(df['proto'])
    df['flag'] = le.fit_transform(df['flag'])

    df['src_ip'] = df['src_ip'].apply(ip_to_int)
    df['dst_ip'] = df['dst_ip'].apply(ip_to_int)

    df['src_ip_count'] = df.groupby('src_ip')['src_ip'].transform('count')
    df['dst_ip_count'] = df.groupby('dst_ip')['dst_ip'].transform('count')
    df['src_port_count'] = df.groupby('src_port')['src_port'].transform('count')
    df['dst_port_count'] = df.groupby('dst_port')['dst_port'].transform('count')

    df['data_transfer_rate'] = df['size'] / df['ttl']
    # Interaction features
    df['src_dst_ip_pair'] = df['src_ip'].astype(str) + '-' + df['dst_ip'].astype(str)
    df['Total'] = df.groupby('src_dst_ip_pair')['src_dst_ip_pair'].transform('count')
    
    # pre_process.run(df)

    # return df

# # Train the machine learning model
def train_model(packet_data):
    # Split the data into training and testing sets
    X_train, X_test, y_train, y_test = train_test_split(packet_data.drop('alert', axis=1), packet_data['alert'], test_size=0.2, random_state=42)
    # Create an Isolation Forest model
    if_model = IsolationForest(contamination=0.1)
    if_model.fit(X_train)
    # Create a KMeans model
    km_model = KMeans(n_clusters=3)
    km_model.fit(X_train)
    # Create a processor model (assuming it's a custom model)
    proc_model = 
    proc_model.fit(X_train)
    # Combine the models using a voting classifier
    from sklearn.ensemble import VotingClassifier
    voting_model = VotingClassifier(estimators=[('if', if_model), ('km', km_model), ('proc', proc_model)])
    voting_model.fit(X_train, y_train)
    return voting_model

# Use the trained model to predict the alert status
def predict_alert(packet, model):
    # Preprocess the packet data
    packet_data = preprocess_packet(packet)
    # Predict the alert status using the trained model
    prediction = model.predict(packet_data)
    if prediction[0] == 1:
        return packet['serial']
    else:
        return None

# Example usage
packet = {'serial': 1, 'time': 1721293041143.477, 'src_ip': '2409:40c0:4f:b415:14ec:1642:c419:74d9', 'src_port': 60309, 'dst_ip': '64:ff9b::14d4:5875', 'dst_port': 443, 'proto': 'tcp', 'flag': 'ACK', 'ttl': -1, 'size': 75, 'alert': 0}
r = preprocess_packet(packet)
print(r)
# model = train_model(packet)  # assuming packet_data is a pandas dataframe containing the preprocessed packet data
# result = predict_alert(packet, model)
# print(result)  # Output: 1 if alert is true, None otherwise