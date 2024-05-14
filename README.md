
# PentaShield

PentaShield is a comprehensive security solution designed to protect networks and data from various cyber threats. This project includes modules for data processing, model training, and deployment to ensure robust protection and easy integration.
## Features

- Data Handling: Processes and manages datasets for training and testing.
- Machine Learning: Implements models for threat detection.
- Web Interface: Provides a user-friendly web interface for interaction and monitoring.
- Automation: Uses scripts for automating various tasks.
- Remote input: Mobile devices can be used for giving input IP address.


## Project Structure
- `dataset/` : Contains data files used for training and testing.
- `static/` : Houses static files for the web interface.
- `templates/` : Contains HTML templates for the web interface.
- `.gitignore` : Specifies files to be ignored by Git.
- `app.py` : Main application file for running the web interface.
- `ngrok_runner.py` & `ngrok_runner.sh` : Scripts for running and managing ngrok for secure tunnels.
- `requirements.txt` : Lists dependencies required for the project.
- `test.py` : Script for testing the functionalities.
- `train.py` : Script for training the machine learning models.
## Tech Stack

- **Programming Language**: Python
- **Web Framework**: Flask
- **Machine Learning**: Scikit-learn, Pytorch
- **Data Handling**: Pandas, NumPy
- **Frontend**: HTML, CSS, JavaScript
- **Deployment**: Ngrok
- **Version Control**: Git


## Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/VIVEK-P-V/PentaShield.git
   cd PentaShield
   ```

2. Install the required packages:
    ```bash
   pip install -r requirements.txt
   ```

3. Run the application:
    ```bash
   python3 app.py
   ```
    
## Usage

- **Data Preparation** : Place your datasets in the dataset/ directory.
- **Model Training** : Execute `train.py` to train the models using the prepared data.
- **Testing** : Use `test.py` to validate the trained models.
- **Run Application** : Start the web application with `app.py` and access the interface for monitoring and managing threats.


## Authors

- [@VIVEK-P-V](https://github.com/VIVEK-P-V)
- [@sreeram3015](https://github.com/sreeram3015)
- [@hariPRO6](https://github.com/hariPRO6)
- [@VivekMenon10](https://github.com/VivekMenon10)


