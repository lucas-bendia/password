#Lucas Bendia
import re
import hashlib

# Définition de la fonction pour vérifier la sécurité du mot de passe
def verifier_mot_de_passe(mot_de_passe):
    # Vérification de la longueur du mot de passe
    if len(mot_de_passe) < 8:
        return "Le mot de passe doit contenir au moins 8 caractères."  # Retourne un message si le mot de passe est trop court
    # Vérification de la présence d'une lettre minuscule
    elif not re.search("[a-z]", mot_de_passe):
        return "Le mot de passe doit contenir au moins une lettre minuscule."  # Retourne un message si le mot de passe ne contient pas de lettre minuscule
    # Vérification de la présence d'une lettre majuscule
    elif not re.search("[A-Z]", mot_de_passe):
        return "Le mot de passe doit contenir au moins une lettre majuscule."  # Retourne un message si le mot de passe ne contient pas de lettre majuscule
    # Vérification de la présence d'un chiffre
    elif not re.search("[0-9]", mot_de_passe):
        return "Le mot de passe doit contenir au moins un chiffre."  # Retourne un message si le mot de passe ne contient pas de chiffre
    # Vérification de la présence d'un caractère spécial
    elif not re.search("[!@#$%^&*]", mot_de_passe):
        return "Le mot de passe doit contenir au moins un caractère spécial (!, @, #, $, %, ^, &, *)."  # Retourne un message si le mot de passe ne contient pas de caractère spécial
    # Si toutes les conditions sont remplies, le mot de passe est considéré comme sécurisé
    else:
        return "Le mot de passe est sécurisé."  # Retourne un message indiquant que le mot de passe est sécurisé

# Boucle qui demande un mot de passe jusqu'à ce qu'un mot de passe valide soit entré
while True:
    mot_de_passe = input("Veuillez choisir un mot de passe: ")  # Demande à l'utilisateur de choisir un mot de passe
    resultat = verifier_mot_de_passe(mot_de_passe)  # Vérifie la sécurité du mot de passe choisi
    print(resultat)
    if resultat == "Le mot de passe est sécurisé.":
        break  # Si le mot de passe est sécurisé, la boucle se termine

# Cryptage du mot de passe avec SHA-256
h = hashlib.sha256(mot_de_passe.encode())  # Crée un objet de hachage SHA-256 et alimente cet objet avec le mot de passe
mot_de_passe_crypte = h.hexdigest()  # Obtient le condensat du mot de passe
print("Votre mot de passe crypté est : ", mot_de_passe_crypte)  # Imprime le mot de passe crypté

#Lucas Bendia