# Wireless Networks and Communication Project

## Overview
This project is a team effort aimed at building an intelligent system for detecting and preventing network attacks and threats using artificial intelligence and machine learning. By analyzing detailed traffic logs and packet metadata, the system identifies patterns of malicious behavior such as port scanning, unusual packet flows, or suspicious connection states.

The core idea is to leverage predictive models that learn from historical traffic data to proactively detect anomalies and potential intrusions. This approach supports in-depth traffic analysis and enables real-time threat prevention, contributing to stronger and smarter network security infrastructures.

## Features
- **Binary Classification**: Distinguishes between benign and malicious traffic.
- **Multi-class Classification**: Identifies specific attack types among malicious samples.
- **Real-time Monitoring**: Processes live network traffic logs for anomaly detection.
- **SQLite Logging**: Stores processed traffic data and predictions in a database.
- **Data Preprocessing**: Handles missing values, one-hot encoding, and scaling.

## Dataset
The project uses the IoT-23 dataset, which is preprocessed and available on [Kaggle](https://www.kaggle.com/datasets/engraqeel/iot23preprocesseddata). The dataset includes various types of network traffic, both benign and malicious, with detailed metadata.

## Tools and Libraries
- Python 3.11
- Pandas
- NumPy
- Matplotlib
- Scikit-learn
- XGBoost
- SQLite
- Joblib

## How to Run
1. Install the required libraries:
   ```bash
   pip install -r requirements.txt
   ```
2. Load the dataset and preprocess it.
3. Train the hierarchical classification model.
4. Use the monitoring script to analyze live traffic logs.

## Team Members
This project is a collaborative effort by a team of developers and researchers dedicated to advancing network security through machine learning.

## Acknowledgments
Special thanks to the creators of the IoT-23 dataset and the open-source community for providing the tools and resources that made this project possible.