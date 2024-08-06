import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin
import time

def fetch_specific_size_readme_files(base_url):
    visited_urls = set()
    total_scanned = 0  # Compteur pour le nombre total de fichiers/dossiers scannés
    
    def recursive_fetch(url):
        nonlocal total_scanned
        if url in visited_urls:
            return
        visited_urls.add(url)
        
        try:
            response = requests.get(url)
            if response.status_code == 200:
                soup = BeautifulSoup(response.text, 'html.parser')
                links = soup.find_all('a', href=True)
                
                for link in links:
                    full_url = urljoin(url, link['href'])
                    
                    total_scanned += 1
                    
                    # Filtrer uniquement les fichiers README
                    if link['href'].endswith('README'):
                        readme_response = requests.get(full_url)
                        
                        if readme_response.status_code == 200:
                            content = readme_response.text
                            size = len(content)
                            
                            # Vérifier si la taille est supérieure à 34 caractères
                            if size > 34:
                                print(f"\nFichier README trouvé avec une taille supérieure à 34 caractères ({size} caractères):")
                                print(content)
                                print(f"Adresse du fichier : {url}")
                                print(f"\nTotal de fichiers/dossiers scannés: {total_scanned}")
                                return
                        else:
                            time.sleep(5)
                    elif full_url.endswith('/'):
                        recursive_fetch(full_url)
            else:
                time.sleep(5)
        except Exception as e:
            time.sleep(5)

    recursive_fetch(base_url)

# Utilisation de la fonction pour récupérer les fichiers README de tailles spécifiques
fetch_specific_size_readme_files("http://192.168.56.101/.hidden/")