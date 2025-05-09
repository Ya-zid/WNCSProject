# ==============================================================================
# FINAL WORKING MONITORING SCRIPT
# ==============================================================================
import time
import os
import pandas as pd
from datetime import datetime

# Define Zeek log fields EXACTLY as they appear in your conn.log
ZEEK_FIELDS = [
    "ts", "uid", "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p",
    "proto", "service", "duration", "orig_bytes", "resp_bytes", "conn_state",
    "local_orig", "local_resp", "missed_bytes", "history", "orig_pkts",
    "orig_ip_bytes", "resp_pkts", "resp_ip_bytes", "tunnel_parents", "ip_proto"
]

def run_inference(pipeline, log_file="./../zeek_logs/conn.log"):
    """Run real-time inference on Zeek conn.log"""
    print("="*50)
    print("Starting Network Traffic Monitor")
    print(f"Monitoring: {os.path.abspath(log_file)}")
    print("="*50 + "\n")
    
    # Initialize state
    last_position = 0
    last_benign_time = datetime.now()
    
    try:
        while True:
            try:
                # Check if file exists and get its size
                if not os.path.exists(log_file):
                    print(f"⚠️ Waiting for log file... ({datetime.now().strftime('%H:%M:%S')})")
                    time.sleep(2)
                    continue
                
                current_size = os.path.getsize(log_file)
                
                # If file shrunk (rotation), reset position
                if current_size < last_position:
                    print("🔁 Detected log rotation - resetting position")
                    last_position = 0
                
                # Only read if file has grown
                if current_size > last_position:
                    with open(log_file, 'r') as f:
                        f.seek(last_position)
                        new_lines = f.readlines()
                        last_position = f.tell()
                        
                        for line in new_lines:
                            if line.startswith('#') or not line.strip():
                                continue
                                
                            try:
                                values = line.strip().split('\t')
                                if len(values) != len(ZEEK_FIELDS):
                                    continue
                                    
                                row = dict(zip(ZEEK_FIELDS, values))
                                
                                # DEBUG: Uncomment to see raw data
                                # print(f"Processing: {row['id.orig_h']}:{row['id.orig_p']} -> {row['id.resp_h']}:{row['id.resp_p']}")
                                
                                # Prepare input features
                                features = {
                                    'proto': row['proto'],
                                    'duration': float(row['duration']) if row['duration'] != '-' else 0,
                                    'orig_bytes': int(row['orig_bytes']) if row['orig_bytes'] != '-' else 0,
                                    'resp_bytes': int(row['resp_bytes']) if row['resp_bytes'] != '-' else 0,
                                    'conn_state': row['conn_state'],
                                    'missed_bytes': int(row['missed_bytes']) if row['missed_bytes'] != '-' else 0,
                                    'orig_pkts': int(row['orig_pkts']) if row['orig_pkts'] != '-' else 0,
                                    'orig_ip_bytes': int(row['orig_ip_bytes']) if row['orig_ip_bytes'] != '-' else 0,
                                    'resp_pkts': int(row['resp_pkts']) if row['resp_pkts'] != '-' else 0,
                                    'resp_ip_bytes': int(row['resp_ip_bytes']) if row['resp_ip_bytes'] != '-' else 0
                                }
                                
                                # Make prediction
                                input_df = pd.DataFrame([features])
                                prediction = pipeline.predict(input_df)[0]
                                
                                # Handle output
                                current_time = datetime.now()
                                if prediction.startswith("Malicious"):
                                    print(f"\n🚨 ALERT: {prediction}")
                                    print(f"  Time: {row['ts']}")
                                    print(f"  Connection: {row['id.orig_h']}:{row['id.orig_p']} → {row['id.resp_h']}:{row['id.resp_p']}")
                                    print(f"  Protocol: {row['proto']} | Duration: {row['duration']}s")
                                elif (current_time - last_benign_time).seconds >= 10:  # Show every 10 sec
                                    print(f"✅ Normal traffic ({current_time.strftime('%H:%M:%S')})")
                                    last_benign_time = current_time
                                    
                            except Exception as e:
                                print(f"⚠️ Error processing line: {str(e)}")
                                continue
                
                time.sleep(1)  # Check for new lines every second
                
            except Exception as e:
                print(f"⚠️ File error: {str(e)}")
                time.sleep(5)
                
    except KeyboardInterrupt:
        print("\n🛑 Stopping monitor...")

# Main execution
print("Loading model...")
try:
    pipeline = joblib.load("hierarchical_pipeline.joblib")
    print("✅ Model loaded successfully!")
    
    log_path = "./../zeek_logs/conn.log"
    if not os.path.exists(log_path):
        print(f"\n❌ Error: Log file not found at {os.path.abspath(log_path)}")
        print("Please verify:")
        print("1. Zeek is running: `ps aux | grep zeek`")
        print("2. The log directory exists: `ls -la ./../zeek_logs/`")
    else:
        print(f"Found log file at {os.path.abspath(log_path)}")
        print(f"Current size: {os.path.getsize(log_path)} bytes")
        print("\nStarting monitoring (Press Ctrl+C to stop)...")
        run_inference(pipeline)
        
except Exception as e:
    print(f"❌ Failed to load model: {str(e)}")