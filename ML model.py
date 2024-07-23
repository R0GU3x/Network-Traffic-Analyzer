#!/usr/bin/env python
# coding: utf-8

import pandas as pd
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.preprocessing import StandardScaler, OneHotEncoder, LabelEncoder
from sklearn.compose import ColumnTransformer
from sklearn.pipeline import Pipeline
from sklearn.ensemble import IsolationForest
from sklearn.metrics import classification_report, accuracy_score, confusion_matrix
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
import ipaddress
import pickle

# Load dataset
df = pd.read_csv(r"Final Dataset.csv")

# Check for blank entries
def check_blank_entries(df):
    blank_entries = [entry for entry in df if all(value.strip() == '' for value in entry)]
    return blank_entries

blank_entries = check_blank_entries(df)
print(blank_entries)

# Label Encoding the categorical values
le = LabelEncoder()
df['proto'] = le.fit_transform(df['proto'])
df['flag'] = le.fit_transform(df['flag'])

# Convert IP addresses to numerical representations
def ip_to_int(ip_str):
    return int(ipaddress.ip_address(ip_str))

df['src_ip'] = df['src_ip'].apply(ip_to_int)
df['dst_ip'] = df['dst_ip'].apply(ip_to_int)

# Addition of some more attributes
df['src_ip_count'] = df.groupby('src_ip')['src_ip'].transform('count')
df['dst_ip_count'] = df.groupby('dst_ip')['dst_ip'].transform('count')
df['src_port_count'] = df.groupby('src_port')['src_port'].transform('count')
df['dst_port_count'] = df.groupby('dst_port')['dst_port'].transform('count')

# Derived feature: data transfer rate (size over ttl)
df['data_transfer_rate'] = df['size'] / (df['ttl'] + 1)  # Avoid division by zero

# Interaction features
df['src_dst_ip_pair'] = df['src_ip'].astype(str) + '-' + df['dst_ip'].astype(str)
df['Total'] = df.groupby('src_dst_ip_pair')['src_dst_ip_pair'].transform('count')

# Drop duplicate rows based on 'src_dst_ip_pair'
df = df.drop_duplicates(subset='src_dst_ip_pair')

# Drop 'src_dst_ip_pair' column
df.drop('src_dst_ip_pair', axis=1, inplace=True)

# Replace infinite values and handle large values
df.replace([np.inf, -np.inf], np.nan, inplace=True)  # Replace infinities with NaN
df.fillna(0, inplace=True)  # Replace NaNs with 0 or another value as needed

# Verify data types and ranges
print(df.describe())

# Data analysis
y = df['alert']
counts = y.value_counts()
plt.pie(counts, autopct='%2.2f%%', labels=counts.index)
plt.show()

corr_matrix = df.corr()
plt.figure(figsize=(10, 8))
sns.heatmap(corr_matrix, annot=True, cmap="coolwarm", square=True)
plt.title("Correlation Matrix")
plt.show()

plt.figure(figsize=(10, 6))
sns.histplot(df['alert'], bins=20, kde=True)
plt.title('Histogram of alert')
plt.xlabel('Alert')
plt.ylabel('Frequency')
plt.show()

plt.figure(figsize=(16, 9))
plt.title('Unclustered Data')
plt.grid()
plt.xlabel('flag')
plt.ylabel('ttl')
plt.scatter(df['flag'], df['ttl'], color='red', marker='>')
plt.show()

plt.figure(figsize=(8, 6))
plt.hist(df['alert'], bins=20, color='skyblue')
plt.xlabel('Alert')
plt.ylabel('Frequency')
plt.title('Distribution of Alert')
plt.grid(True)
plt.show()

sns.pairplot(df, vars=['alert', 'Total', 'flag', 'time'])
plt.show()

# Model Training for anomaly detection
X = df.drop(columns=['alert'])
y = df['alert']

# Define numerical and categorical features
numerical_features = ['src_port', 'dst_port', 'ttl', 'size', 'src_ip_count', 'dst_ip_count', 'src_port_count', 'dst_port_count', 'data_transfer_rate', 'Total']
categorical_features = ['proto', 'flag', 'src_ip', 'dst_ip']

# Define preprocessing pipeline
preprocessor = ColumnTransformer(
    transformers=[
        ('num', StandardScaler(), numerical_features),
        ('cat', OneHotEncoder(handle_unknown='ignore'), categorical_features)
    ])

# Train-Test Split
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.3, random_state=1729)

# Apply preprocessing
X_train_scaled = preprocessor.fit_transform(X_train)
X_test_scaled = preprocessor.transform(X_test)

# Perform Isolation Forest anomaly detection
iso_forest = IsolationForest(contamination=0.5, random_state=1729)

# Cross-validation for model evaluation
cross_val_scores = cross_val_score(iso_forest, X_train_scaled, y_train, cv=6, scoring='accuracy')
print(f'Cross-Validation Accuracy Scores: {cross_val_scores}')
print(f'Average Cross-Validation Accuracy: {cross_val_scores.mean()}')

iso_forest.fit(X_train_scaled)

# Predict anomalies
train_anomalies = iso_forest.predict(X_train_scaled)
test_anomalies = iso_forest.predict(X_test_scaled)

# Convert to 0 (normal) and 1 (anomaly)
train_anomalies = [1 if x == -1 else 0 for x in train_anomalies]
test_anomalies = [1 if x == -1 else 0 for x in test_anomalies]

# Convert back to DataFrame for comparison
y_test_anomalies = pd.Series(test_anomalies, index=X_test.index)
y_train_anomalies = pd.Series(train_anomalies, index=X_train.index)

# Reset index for alignment
y_test = y_test.reset_index(drop=True)
y_train = y_train.reset_index(drop=True)

# # Calculate training accuracy
#train_accuracy = accuracy_score(y_train, y_train_anomalies)
#print(f'Training Accuracy: {train_accuracy}')

# Define the alert function
def alert(predictions, serials):
    alerts = []
    for pred, serial in zip(predictions, serials):
        alerts.append((pred, serial))
    return alerts

# Extract serials from the original data
serials_test = X_test['serial']

# Get the alerts
alerts = alert(test_anomalies, serials_test)

# Print anomaly detection metrics
print("Anomaly Detection Metrics:")
print(f'Test Accuracy: {accuracy_score(y_test, y_test_anomalies)}')
print('Classification Report:')
print(classification_report(y_test, y_test_anomalies))
print('Confusion Matrix:')
print(confusion_matrix(y_test, y_test_anomalies))

# Print the alerts
print('Alerts:')
for alert_value, serial in alerts:
    print(f'Alert Value: {alert_value}, Serial: {serial}')

# Exporting models using pickle
with open('preprocessor.pkl', 'wb') as file:
    pickle.dump(preprocessor, file)

with open('iso_forest_model.pkl', 'wb') as file:
    pickle.dump(iso_forest, file)