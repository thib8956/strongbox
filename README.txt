Strongbox : Sujet Cryptographie n°9 
======================================  
Auteur: Alexandre Colicchio, Andy Chabalier, Philippe Letaif, Thibaud Gasser  
------------------------------------------------------------------------------------------  

A partir de la racine du projet, on retrouve un ensemble de ressources permettant des exemples d'utilisation du projet.  
\strongbox-server\src\main\resources\sample  Il sera fait reference a ce dossier par "sample".  

Pour lancer le serveur, executez la classe StrongboxHttpsServer.  

le serveur sera donc lancé en local, sur le port d'ecoute 8000.  

Une fois le client affiché, vous pouvez rechercher une clé, en ajouter ou en supprimer.  

Pour le projet, le mot de passe est "password".  

Rechercher une clé  
____________________

Entrez la clé publique (Dont des exemples trouvable dans le dossier Sample) et le mot de passe.  

Vous recevrez la clé privé correspondante avec son format et l'algorithme de cryptage.  

Ajouter une clé
_____________________  

Afin d'ajouter une clé dans le KeyStore, il sera nessesaire de fournir:  

1. L'alias (nessesaire pour supprimer la clé)    
2. Le certificat (Trouvable dans sample)  
3. La clé privée a ajouter.  
4. Le mot de passe.  

Supprimer une clé
__________________

Entrez l'alias correspondant a la clé et le mot de passe.

Elle sera ainsi supprimée et liberera l'alias.