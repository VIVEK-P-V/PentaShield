from flask import Flask, render_template, request, redirect, url_for, send_from_directory
import subprocess
import re
import os

app = Flask(__name__)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/train', methods=['GET', 'POST'])
def train():
    if request.method == 'POST':
        train_option = request.form.get('train_option')
        output = ""
        if train_option == '1':
            target_ip = request.form.get('target_ip')
            args = ['python3', 'train.py', '1', target_ip]
            process = subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            output = process.stdout
        elif train_option == '2':
            args = ['python3', 'train.py', '2']
            process = subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            output = process.stdout
        else:
            return redirect(url_for('train'))
        return render_template('train.html', output=output)
    return render_template('train.html')

@app.route('/test', methods=['GET', 'POST'])
def test():
    if request.method == 'POST':
        target_ip = request.form.get('target_ip')
        args = ['python3', 'test.py', target_ip]
        process = subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        output = process.stdout

        # Remove ASCII color codes and Metasploit prompt from the output
        output = re.sub(r'\x1b\[[0-9;]*m', '', output)
        output = re.sub(r'\[\?1034h', '', output)

        return render_template('test.html', output=output)
    return render_template('test.html')

@app.route('/report')
def report():
    report_path = os.path.join(os.path.dirname(__file__), 'reports', 'index.html')
    return send_from_directory(os.path.dirname(report_path), 'index.html')

if __name__ == '__main__':
    app.run(debug=True)
