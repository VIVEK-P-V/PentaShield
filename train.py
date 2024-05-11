import csv
import os
import sys
import nmap
import numpy as np
import torch
import torch.nn as nn
import torch.optim as optim
from prettytable import PrettyTable
from torch.utils.data import Dataset, DataLoader
from sklearn.feature_extraction.text import CountVectorizer
from sklearn.preprocessing import LabelEncoder

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

def load_data_from_csv(csv_file):
    data = []
    with open(csv_file, 'r') as file:
        reader = csv.reader(file)
        next(reader)  # Skip header row
        for row in reader:
            IP, Port, Service, State, Product, Version = row
            data.append((IP, int(Port), State, Service, Product, Version))
    return data

def save_to_csv(hosts, services, output_folder):
    filename = os.path.join(output_folder, "nmap_scan_results.csv")
    try:
        os.remove(filename)  # Remove the existing file
    except FileNotFoundError:
        pass  # Ignore if the file doesn't exist

    with open(filename, mode='w', newline='') as file:
        writer = csv.writer(file)
        writer.writerow(["IP", "Port", "Service", "State", "Product", "Version"])
        for host in hosts:
            for port, service_info in services.items():
                writer.writerow([host, port, service_info['name'], service_info['state'], service_info['product'], service_info['version']])

def preprocess_data(data, service_encoder=None):
    X = []
    y = []
    if service_encoder is None:
        service_encoder = LabelEncoder()
        service_names = [row[3] for row in data]
        service_encoder.fit(service_names)

    for ip, port, state, service, version in data:
        port_name = service
        state_value = 1 if state == 'open' else 0
        X.append([port, service_encoder.transform([port_name])[0]])
        y.append(state_value)

    return np.array(X), np.array(y), service_encoder

def preprocess2_data(data, service_encoder=None):
    X = []
    y = []
    if service_encoder is None:
        service_encoder = LabelEncoder()
        service_names = [row[3] for row in data]
        service_encoder.fit(service_names)

    for IP, Port, State, Service, Product, Version in data:
        port_name = Service
        state_value = 1 if State == 'open' else 0
        X.append([Port, service_encoder.transform([port_name])[0]])
        y.append(state_value)

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
    train_option = sys.argv[1]

    if train_option == '1':
        target_ip = sys.argv[2]
        hosts, services = run_nmap_scan(target_ip)
        if hosts and services:
            output_folder = "TRAIN_output"
            if not os.path.exists(output_folder):
                os.makedirs(output_folder)

            save_to_csv(hosts, services, output_folder)

            data = [(ip, port, service_info['state'], service_info['name'], service_info['product'] + ' ' + service_info['version'])
                    for ip in hosts for port, service_info in services.items()]
            X, y, service_encoder = preprocess_data(data)

    elif train_option == '2':
        csv_file = "dataset/nmapdataset.csv"
        data = load_data_from_csv(csv_file)
        X, y, service_encoder = preprocess2_data(data)

    else:
        print("Invalid option. Exiting...")
        sys.exit(1)

    print("\n\nTraining NMAP...\n")
    input_size = X.shape[1]
    hidden_size = 64
    output_size = 1

    model, service_encoder = train_lstm_model(X, y, input_size, hidden_size, output_size)

    model_folder = "LSTM_model"
    if not os.path.exists(model_folder):
        os.makedirs(model_folder)

    model_path = os.path.join(model_folder, "port_state_lstm.pth")
    torch.save({
        'model_state_dict': model.state_dict(),
        'service_encoder': service_encoder
    }, model_path)
    print(f"\nNMAP model saved successfully to {model_path}.\n")


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

# Initialize LSTM model
    print("\nExploiting Training ...\n")
input_size = 86  # Adjusted input size to match the input data size
hidden_size = 32
output_size = 1  # Binary classification (vulnerability or not)
model = LSTMModel(input_size, hidden_size, output_size)

# Define loss function and optimizer
criterion = nn.BCELoss()
optimizer = optim.Adam(model.parameters(), lr=0.001)

# Tokenize and vectorize exploit data
exploits = []
labels = []
dataset_dir = 'dataset'
exp_csv_path = os.path.join(dataset_dir, 'exp.csv')
with open(exp_csv_path, 'r', encoding='utf-8') as exploit_file:
    reader = csv.DictReader(exploit_file)
    for row in reader:
        exploit_info = f"Exploit: {row['Exploit']}, Product: {row['Product']}, Version: {row['Version']}, Service: {row['Service']}"
        exploits.append(exploit_info)
        labels.append([1])  # Assuming all exploits are vulnerabilities

vectorizer = CountVectorizer(max_features=input_size)
vectorizer.fit(exploits)

# Convert exploits and labels into tensors
exploits_tensor = torch.tensor(vectorizer.transform(exploits).toarray(), dtype=torch.float32)
labels_tensor = torch.tensor(labels, dtype=torch.float32)

# Create DataLoader for training
exploit_dataset = ExploitDataset(exploits_tensor, labels_tensor)
train_loader = DataLoader(exploit_dataset, batch_size=1, shuffle=True)

epochs=100
# Training loop
for epoch in range(epochs):
    model.train()
    running_loss = 0.0
    for exploit, label in train_loader:
        optimizer.zero_grad()
        exploit_string = ' '.join([str(exp) for exp in exploit])  # Convert elements to string and join them
        exploit_vector = torch.tensor(vectorizer.transform([exploit_string]).toarray(), dtype=torch.float32)
        output = model(exploit_vector)
        loss = criterion(output.squeeze(), label.squeeze())  # Squeeze both output and label tensors
        loss.backward()
        optimizer.step()
        running_loss += loss.item()
    print(f"Epoch [{epoch+1}/{epochs}], Loss: {loss.item()}")

# Create the 'exploit_detection_model' folder if it doesn't exist
model_dir = 'exploit_detection_model'
if not os.path.exists(model_dir):
    os.makedirs(model_dir)

# Save model
model_path = os.path.join(model_dir, 'exploit_detection_model.pth')
torch.save(model.state_dict(), model_path)
print(f"\nEXPLOIT model saved successfully to {model_path}.\n")



