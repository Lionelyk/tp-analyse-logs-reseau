 TP - Analyseur Simplifié de Logs Réseau

 Description

Ce projet consiste à développer un mini outil d’analyse de logs réseau simulant le travail d’un centre de supervision (NOC).

L’objectif est d’exploiter un fichier de traces réseau afin d’en extraire des statistiques pertinentes et de détecter des comportements suspects.

Le programme a été réalisé en deux versions :
- Version C
- Version Python

Les deux versions produisent des résultats identiques.


Structure du projet
tp-analyse-logs-reseau/

	analyse_logs.c
	analyse_logs.py
	network_log.txt
	 rapport_analyse.txt
	README.txt


 Fonctionnalités
Le programme permet de :

- Lire un fichier de logs réseau
- Calculer :
Nombre total de connexions
Nombre total de succès
  - Nombre total d’échecs
  - Port le plus utilisé
  - Adresse IP la plus active
- Détecter les IP suspectes  
  (plus de 5 échecs sur un même port)
- Générer un rapport structuré dans `rapport_analyse.txt`
- Afficher les résultats à l’écran

 Format du fichier d’entrée

Chaque ligne du fichier `network_log.txt` respecte le format :

DATE;HEURE;IP_SOURCE;PORT;PROTOCOLE;STATUT

Exemple :
2026-02-10;08:45:12;192.168.1.10;22;TCP;ECHEC
Le champ `STATUT` peut être :
- SUCCES
- ECHEC

 Exécution - Version C
 Compilation
Dans le terminal :
gcc analyse_logs.c -o analyse_logs
Exécution
Sous Windows :
analyse_logs.exe
Sous Linux / Mac :
./analyse_logs

 Exécution - Version Python
Lancer le script
python analyse_logs.py
ou
python3 analyse_logs.py

Rapport généré
Un fichier nommé :
rapport_analyse.txt
est automatiquement généré.
Il contient :
•	Résumé statistique
•	Liste des IP suspectes
•	Top 3 des ports les plus utilisés

Technologies utilisées
•	Langage C (struct, malloc, realloc, free, strtok, strcmp)
•	Python (listes, dictionnaires, fonctions)
•	GCC (compilation C)
•	VS Code

 AUTEUR
Nom : YAV KABEY LIONEL
Cours : Langage c et python 
Date : Février 2026



