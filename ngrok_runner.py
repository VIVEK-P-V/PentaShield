import subprocess

def run_bash_script(script_path):
    try:
        # Execute the Bash script
        subprocess.run(['bash', script_path], check=True)
        print("Bash script executed successfully.")
    except subprocess.CalledProcessError as e:
        print("Error running Bash script:", e)

if __name__ == "__main__":
    # Provide the path to your Bash script
    script_path = "ngrok_runner.sh"

    # Run the Bash script
    run_bash_script(script_path)

