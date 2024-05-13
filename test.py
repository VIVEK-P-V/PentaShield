import csv
import os
import nmap
from prettytable import PrettyTable
import numpy as np
import torch
import torch.nn as nn
import torch.optim as optim
from sklearn.preprocessing import LabelEncoder
import subprocess
from torch.utils.data import Dataset
from sklearn.feature_extraction.text import CountVectorizer
from pathlib import Path
import re
import sys

# LSTM model for port state prediction
class PortStateLSTM(nn.Module):
    def __init__(self, input_size, hidden_size, output_size):
        super(PortStateLSTM, self).__init__()
        self.lstm = nn.LSTM(input_size, hidden_size, batch_first=True)
        self.fc = nn.Linear(hidden_size, output_size)
        self.sigmoid = nn.Sigmoid()

    def forward(self, x):
        out, _ = self.lstm(x)
        out = self.fc(out[:, -1, :])
        out = self.sigmoid(out)
        return out

def run_nmap_scan(target):
    try:
        nm = nmap.PortScanner()
        nm.scan(hosts=target, arguments='-Pn -sV')  # Run service version detection
        return nm.all_hosts(), nm[target]['tcp']
    except Exception as e:
        print("Error performing network scan:", str(e))
        return None, None

def save_to_csv(hosts, services, output_folder):
    output_folder = "TEST_output"
    os.makedirs(output_folder, exist_ok=True)

    filename = os.path.join(output_folder, "nmap_scan_results.csv")
    with open(filename, mode='w', newline='') as file:
        writer = csv.writer(file)
        writer.writerow(["IP", "Port", "Service", "State", "Product", "Version"])
        for host in hosts:
            for port, service_info in services.items():
                writer.writerow([host, port, service_info['name'], service_info['state'], service_info['product'], service_info['version']])
    print(f"\nPredicting.......\n")

def preprocess_data(services):
    X = []
    y = []
    service_encoder = LabelEncoder()
    service_names = [service_info['name'] for service_info in services.values()]
    service_encoder.fit(service_names)

    for port, service_info in services.items():
        port_name = service_info['name']
        state = 1 if service_info['state'] == 'open' else 0
        X.append([port, service_encoder.transform([port_name])[0]])
        y.append(state)

    return np.array(X), np.array(y), service_encoder

def train_lstm_model(X, y, input_size, hidden_size, output_size, epochs=100, batch_size=32):
    model = PortStateLSTM(input_size, hidden_size, output_size)
    criterion = nn.BCELoss()
    optimizer = optim.Adam(model.parameters(), lr=0.001)

    X_tensor = torch.tensor(X, dtype=torch.float32)
    y_tensor = torch.tensor(y, dtype=torch.float32)

    dataset = torch.utils.data.TensorDataset(X_tensor, y_tensor)
    dataloader = torch.utils.data.DataLoader(dataset, batch_size=batch_size, shuffle=True)

    for epoch in range(epochs):
        for inputs, targets in dataloader:
            optimizer.zero_grad()
            outputs = model(inputs.unsqueeze(1))
            loss = criterion(outputs, targets.unsqueeze(1))
            loss.backward()
            optimizer.step()
        print(f"Epoch [{epoch+1}/{epochs}], Loss: {loss.item()}")

    return model, service_encoder

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 test.py <target_ip>")
        sys.exit(1)

    target_ip = sys.argv[1]
    hosts, services = run_nmap_scan(target_ip)
    if hosts and services:
        save_to_csv(hosts, services, "TEST_output")

        X, y, service_encoder = preprocess_data(services)
        input_size = X.shape[1]
        hidden_size = 64
        output_size = 1

        model, service_encoder = train_lstm_model(X, y, input_size, hidden_size, output_size)

        # Load the saved model
        model_path = "LSTM_model/port_state_lstm.pth"
        checkpoint = torch.load(model_path, map_location=torch.device('cpu'))
        model.load_state_dict(checkpoint['model_state_dict'])
        service_encoder = checkpoint['service_encoder']

        # Make predictions
        model.eval()
        X_tensor = torch.tensor(X, dtype=torch.float32)
        predictions = model(X_tensor.unsqueeze(1)).squeeze(1).round().detach().numpy()

        # Print the results in a table
        print("Predicted output using Trained model:")
        table = PrettyTable()
        table.field_names = ["PORT", "STATE", "SERVICE", "PRODUCT", "VERSION"]

        for i, (port, service_info) in enumerate(services.items()):
            port_name = service_info['name']
            service_product = service_info['product']
            service_version = service_info['version']
            predicted_state = "open" if predictions[i] else "closed"
            table.add_row([f"{port}", predicted_state, port_name, service_product, service_version])

        print(table)

# Define LSTM model architecture using PyTorch
class LSTMModel(nn.Module):
    def __init__(self, input_size, hidden_size, output_size):
        super(LSTMModel, self).__init__()
        self.hidden_size = hidden_size
        self.lstm = nn.LSTM(input_size, hidden_size)
        self.fc = nn.Linear(hidden_size, output_size)
        self.sigmoid = nn.Sigmoid()

    def forward(self, input):
        lstm_out, _ = self.lstm(input.view(len(input), 1, -1))
        output = self.fc(lstm_out[-1])
        output = self.sigmoid(output)
        return output

# Custom dataset for exploits
class ExploitDataset(Dataset):
    def __init__(self, exploits, labels):
        self.exploits = exploits
        self.labels = labels

    def __len__(self):
        return len(self.exploits)

    def __getitem__(self, idx):
        exploit = self.exploits[idx]
        label = self.labels[idx]
        return exploit, label

# Function to predict vulnerability
def predict_vulnerability(input_string, vectorizer, model):
    exploit_vector = torch.tensor(vectorizer.transform([input_string]).toarray(), dtype=torch.float32)
    output = model(exploit_vector)
    prediction = output.item()
    return prediction

# Function to run Metasploit
def run_metasploit(exploit_name, ip_address):
    if exploit_name.startswith("auxiliary"):
        exploit_cmd = f"use {exploit_name}"
    elif "exploit/" in exploit_name:
        exploit_cmd = f"use {exploit_name}"
    else:
        exploit_cmd = f"use exploit/{exploit_name}"

    # Set RHOST
    rhost_cmd = f"set RHOST {ip_address}"

    # Interact with Metasploit
    msf_process = subprocess.Popen(["msfconsole", "-q", "-x", exploit_cmd, "-x", rhost_cmd], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True)
    output, _ = msf_process.communicate(input="run\nexit\n")

    print(output)  # Print the output for debugging purposes

# Function to generate exploit report in HTML format
def generate_exploit_report(exploit_name, port, service, product, version, vulnerable, ip_address):
    exploit_info_cmd = f"info {exploit_name}"
    msf_process = subprocess.Popen(["msfconsole", "-q", "-x", exploit_info_cmd], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True)
    output, _ = msf_process.communicate(input="exit\n")

    # Remove unwanted parts from the output
    output = re.sub(r'\[0m\r?\n?', '', output)
    output = re.sub(r'\r?\n?View the full module info with the \[32minfo -d\[0m command.', '', output)
    output = re.sub(r'\[\?1034h\[4mmsf6\[0m \[0m> \[0m', '', output)

    report_entry = f"""
    <div>
        <h1>Exploit Information</h1>
        <p>Exploit Name: {exploit_name}</p>
        <p>Port: {port}</p>
        <p>Service: {service}</p>
        <p>Product: {product}</p>
        <p>Version: {version}</p>
        <p>Vulnerable: {vulnerable}</p>
        <pre>{output}</pre>
    </div>
    """

    return report_entry

def create_main_report_page(reports, ip_address):
    report_dir = Path("reports")
    report_dir.mkdir(exist_ok=True)

    main_report = f"""
<!DOCTYPE html>
<html>
<head>
    <title>Report</title>
    <link rel="icon" href="{{ url_for('static', filename='favicon.ico') }}" type="image/x-icon">
    <style>
        body {{
            font-family: Arial, sans-serif;
            margin: 20px;
        }}
        h1 {{
            color: #333;
        }}
        p {{
            color: #666;
        }}
        pre {{
            background-color: #f5f5f5;
            padding: 10px;
            border-radius: 5px;
            overflow-x: auto;
        }}
        div {{
            margin-bottom: 40px;
            border: 1px solid #ddd;
            padding: 20px;
            border-radius: 5px;
        }}
    </style>
</head>
<body>
    <h1>Report List</h1>
    <h1>IP: {ip_address}</h1>
    {"".join(reports)}
</body>
</html>
    """

    main_report_file = report_dir / "index.html"
    with open(main_report_file, "w", encoding="utf-8") as f:
        f.write(main_report)

    print(f"Main report page generated: {main_report_file}")

# Load trained model
model_path = os.path.join('exploit_detection_model', 'exploit_detection_model.pth')
model = LSTMModel(input_size=86, hidden_size=32, output_size=1)
model.load_state_dict(torch.load(model_path))
model.eval()

# Load CSV file containing Nmap scan results
nmap_results = []
nmap_results_path = os.path.join('TEST_output', 'nmap_scan_results.csv')  # Updated path
with open(nmap_results_path, 'r') as csvfile:
    reader = csv.DictReader(csvfile)
    for row in reader:
        nmap_results.append(row)

# Load CSV file containing exploit data
exploit_data = []
dataset_dir = 'dataset'
exp_csv_path = os.path.join(dataset_dir, 'exp.csv')
with open(exp_csv_path, 'r', encoding='utf-8') as exploit_file:
    reader = csv.DictReader(exploit_file)
    for row in reader:
        exploit_data.append(row)

# Tokenize and vectorize exploit data
exploits = []
for row in exploit_data:
    exploit_info = f"Exploit: {row['Exploit']}, Product: {row['Product']}, Version: {row['Version']}, Service: {row['Service']}, Port: {row['Port']}"
    exploits.append(exploit_info)

vectorizer = CountVectorizer(max_features=86)
vectorizer.fit(exploits)

# Iterate through Nmap scan results and predict vulnerability
reports = []
for result in nmap_results:
    ip_address = result['IP']
    input_string = f"Port: {result['Port']}, Service: {result['Service']}, State: {result['State']}, Product: {result['Product']}, Version: {result['Version']}"
    prediction = predict_vulnerability(input_string, vectorizer, model)
    if prediction > 0.5:  # If prediction probability is above 0.5, consider it as a vulnerability
        print("\n\tVulnerability Detected!\n")
        exploit_run = False  # Flag to track if an exploit has been run
        # Find corresponding exploit name from the dataset and run Metasploit
        for exploit_entry in exploit_data:
            if (
                (not exploit_entry['Port'] or exploit_entry['Port'] == result['Port'])
                and (not exploit_entry['Service'] or exploit_entry['Service'] == result['Service'])
                and (not exploit_entry['Product'] or exploit_entry['Product'] == result['Product'])
                and (not exploit_entry['Version'] or exploit_entry['Version'] == result['Version'])
            ):
                exploit_name = exploit_entry['Exploit']
                print("\t[*] Running Exploit or Auxiliary:", exploit_name + "\n")
                run_metasploit(exploit_name, ip_address)
                exploit_run = True

                # Generate exploit report in HTML format
                report_entry = generate_exploit_report(exploit_name, result['Port'], result['Service'], result['Product'], result['Version'], vulnerable=True, ip_address=ip_address)
                reports.append(report_entry)
                break  # Break out of the loop after running the first matching exploit

        if not exploit_run:
            print("No matching exploit found for this entry.")
    else:
        print("No Vulnerability Detected for this entry.")

# Create main report page
create_main_report_page(reports, ip_address)
