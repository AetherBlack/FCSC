# Chapardeur de mots de passe

Points : 168 (Dynamique)

```
Un ami vous demande de l'aide pour déterminer si l'email qu'il
vient d'ouvrir au sujet du Covid-19 était malveillant et si
c'était le cas, ce qu'il risque.

Il prétend avoir essayé d'ouvrir le fichier joint à cet mail sans y
parvenir. Peu de temps après, une fenêtre liée à l'anti-virus a
indiqué, entre autre, le mot KPOT v2.0 mais rien d'apparent
n'est arrivé en dehors de cela.

Après une analyse préliminaire, votre ami vous informe qu'il
est probable que ce malware ait été légèrement modifié, étant
donné que le contenu potentiellement exfiltré (des parties du
format de texte et de fichier avant chiffrement) ne semble
plus prédictible. Il vous recommande donc de chercher
d'autres éléments pour parvenir à l'aider.

Vous disposez d'une capture réseau de son trafic pour l'aider
à déterminer si des données ont bien été volées et lui dire s'il
doit rapidement changer ses mots de passe !

SHA256(pws.pcap) = 98e3b5f1fa4105ecdad4880cab6a7216c5bb3275d7367d1309ab0a0d7411475d - 463MB
```

## Analyse

Le fichier à analyser est une capture réseau.

Une petite analyse s'impose. Je peux trouver dans l'onglet ```Statistiques``` de ```Wireshark``` plein d'informations intéressantes que je vais pouvoir exploiter.

Voici celles que j'ai décidé de retenir.

```
@IP les plus redondantes
192.168.4.129
194.71.11.142

IP que 192.168.4.129 contact le plus par ordre décroissant <src|dst> :
194.71.11.142
50.62.109.1
151.101.121.140

Flux:
192.168.4.129 -> 194.71.11.142 : 14448 Paquets (TCP, TLSv1.3)
192.168.4.129 -> 50.62.109.1 : 3721 Paquets (TCP, HTTP)
192.168.4.129 -> 151.101.121.140 : 2665 Paquets (TCP, TLSv1.2)

151.101.121.140 -> 192.168.4.129 : 4103 Paquets (TCP, TLSv1.2)
50.62.109.1 -> 192.168.4.129 : 5767 Paquets (TCP, HTTP)
194.71.11.142 -> 192.168.4.129 : 21360 Paquets (TCP, TLSv1.3)
```

En voyant ces informations, je me dis qu'il est peu probable que j'ai à analyser un traffic TLSv1.3. Alors je décide de faire des recherches sur le mot ```KPOT v2.0```.

Très vite, je tombe sur un lien fort intéressant qui explique step by step le fonctionnement de ce virus.

cf : [New KPOT v2.0 stealer brings zero persistence and in-memory features to silently steal credentials](https://www.proofpoint.com/us/threat-insight/post/new-kpot-v20-stealer-brings-zero-persistence-and-memory-features-silently-steal)

### Fonctionnement du malware

Après avoir lu l'article je sais que :

 * Le virus envoie une première requête http au serveur C&C à la page ```gate.php```.
 * Le serveur envoie un message encodé en base64 contenant les extensions de fichier à analyser.
 * Le malware répond ensuite avec les mots de passes ou autres informations qu'il a pu récupérer sur la machine.
 * Les messages envoyés entre le serveur et le client sont XORé avec la même clé. La clé est contenue dans le malware et a une taille de 16 caractères.
 * Le message envoyé par le serveur contient un pattern tel-que : ```|16 '1' ou '0' qui représente les actions à effectuer par le malware.|__DELIMM__|@IP externe du client|__DELIMM__appdata__GRABBER__*.log,*.txt,__ GRABBER __%appdata%__GRABBER__0__GRABBER__1024__DELIMM__desktop_txt__GRABBER__*.txt,__ GRABBER __%userprofile%\Desktop__GRABBER__0__GRABBER__150__DELIMM____DELIMM____DELIMM__```

## Recherche du serveur C&C

Avec ces informations, je vais pouvoir rechercher dans la capture une requête faite sur la page ```gate.php``` pour récupérer ensuite l'@IP du serveur distant.

Un rapide Ctrl+F et je trouve plusieurs @IP requêtées :
 * 198.54.117.197
 * 104.27.140.49
 * 185.25.51.81
 * 203.0.113.42

Deux requêtes sont envoyées à destination du serveur ```203.0.113.42``` contre une seule sur les autres IP. Je filtre sur celle-ci.

Filtre : ```ip.src == 203.0.113.42 || ip.dst == 203.0.113.42```

En analysant les paquets affichés, je trouve une ressemblance avec les informations de l'article lu précédemment.

Je récupère donc le message du serveur encodé en base64 :

```
RHVdQ1V8BFVHAgRSAGNZRisbKDYoBXgpKW0HUgl8WUZMal1HXWIGU0Vtaid0HiE7ORszEhQ8UQUCU2o8dgApNDYBPiw7ZhsIGVUZSR8mEAJYGzM0Ng13JjNgajwUMxgGECUYEkETaiMkc3chdAA3KUQbMzQ2DXcmM2BqPABiWkIrGyg2KAV4KSltUQZCORwZBBsYCxATaiMkc3chdAA3KV5qGAsQYGo7MWB0IXMXOikrYRkAAT5FFhlUXA9UdzQyETcHBws8ajsxYHQhcxc6KSt0MywjHnQmNHdnPG5iNykwASA6KQFqOyltcSZ9GyU7KxszLCAJeS07f2o8
```

## Déchiffrement du message envoyé par le serveur

J'écris son contenu dans un fichier et lance ```xortool``` pour essayer de retrouver la clé.

Malheureusement, il ne m'en ressort qu'une partie. Mais assez pour me donner d'autres idées !

Je décide de scripter un tool qui va XORer les 16 premiers caractères avec '0' puis '1' pour m'afficher la liste des clés possibles.

Je serai en possession pour chaque index de la clé du XOR de deux possibilités.

J'ajoute ensuite un pattern de 16 caractères que je vais XORer avec chacun des index de ma clé pour trouver le bon caractère.

Pattern : ```__DELIMM__A.B.C.```

*Je n'ai compris qu'après le déchiffrement du message que A.B.C.D correspondait à l'@IP Public du client*

Une fois la clé retrouvée, je n'aurai plus qu'à XORer tout le message et vérifier qu'il soit bien conforme.

Voici mon code :

```python
#!/usr/bin/python3

import os
import sys

PATTERN_SRV_REQUEST = "__DELIMM__A.B.C."

#Get the content of the file
with open("/home/aether/Documents/FCSC/Forensics/C2MDP/requests/srv_decode.txt", "rb") as f:
    data = bytearray(f.read())

#Get the content of the file
with open("/home/aether/Documents/FCSC/Forensics/C2MDP/requests/srv_decode.txt", "rb") as f:
    data_to_decode = f.read()

#Get the xored key
xored_key = data[:16]

#Var possible key
list_key = ["", ""]

for _key in xored_key:
    list_key[0] += chr(_key ^ ord("0"))

for _key in xored_key:
    list_key[1] += chr(_key ^ ord("1"))

for index in range(16):
    print("[+] Possible {0} char : {1} | {2}".format(index + 1, list_key[0][index], list_key[1][index]))

print("[+] List char : {0} | {1}".format(list_key[0], list_key[1]))

#Tentative de retrouver la cle
rkey = list()
pkey = "tDls"

recover_data = data[16:32]

partial_plaintext = ["", ""]

for elem in range(16):

    partial_plaintext[0] += chr(recover_data[elem] ^ ord(list_key[0][elem]))
    partial_plaintext[1] += chr(recover_data[elem] ^ ord(list_key[1][elem]))

print("[+] Plaintext : {0} | {1}".format(partial_plaintext[0], partial_plaintext[1]))

print("[+] Key : ", end='')

for _key in range(16):
    if PATTERN_SRV_REQUEST[_key] == partial_plaintext[0][_key]:
        sys.stdout.write(list_key[0][_key])
        sys.stdout.flush()
        rkey.append(list_key[0][_key])
    else:
        sys.stdout.write(list_key[1][_key])
        sys.stdout.flush()
        rkey.append(list_key[1][_key])
print("")

#Patch key
rkey[15] = list_key[0][15]
rkey = "".join(rkey)

print("[+] Patched key : {0}".format(rkey))

# Decode file
save_data = bytes()

for _elem in range(len(data_to_decode)):
    save_data += bytes(chr(data_to_decode[_elem] ^ ord(rkey[_elem % 16])).encode())

with open("srv_requests.txt", "wb") as f:
    f.write(save_data)

print("[+] Serveur requests :\n=> {0}".format(os.popen("cat srv_requests.txt").read()))
```

Je me suis rendu compte après mon premier output qu'un caractère n'était pas bon dans la clé.
D'où le changement du dernier caractère de la clé.

cf : ```rkey[15] = list_key[0][15]```

Après ce patch j'ai relancé à nouveau mon script :

```
[+] Possible 1 char : t | u
[+] Possible 2 char : E | D
[+] Possible 3 char : m | l
[+] Possible 4 char : s | r
[+] Possible 5 char : e | d
[+] Possible 6 char : L | M
[+] Possible 7 char : 4 | 5
[+] Possible 8 char : e | d
[+] Possible 9 char : w | v
[+] Possible 10 char : 2 | 3
[+] Possible 11 char : 4 | 5
[+] Possible 12 char : b | c
[+] Possible 13 char : 0 | 1
[+] Possible 14 char : S | R
[+] Possible 15 char : i | h
[+] Possible 16 char : v | w
[+] List char : tEmseL4ew24b0Siv | uDlrdM5dv35c1Rhw
[+] Plaintext : _^EEMILL^_309/00 | ^_DDLHMM_^218.11
[+] Key : tDlsdL5dv25c1Rhw
[+] Patched key : tDlsdL5dv25c1Rhv
[+] Serveur requests :
=> 0110101110111110__DELIMM__218.108.149.373__DELIMM__appdata__GRABBER__*.log,*.txt,__GRABBER__%appdata%__GRABBER__0__GRABBER__1024__DELIMM__desktop_txt__GRABBER__*.txt,__GRABBER__%userprofile%\Desktop__GRABBER__0__GRABBER__0__DELIMM____DELIMM____DELIMM__
```

Cette fois-ci j'ai une sortie correcte.

La clé serait donc : ```tDlsdL5dv25c1Rhv```

Je peux maintenant essayer la clé sur la requête du client.

## Déchiffrement du message envoyé par le client

Je retourne sur ma capture réseau et récupère le contenu de la réponse envoyée par le client :

```
0000   00 00 6c 00 00 00 00 00 6c 00 00 01 08 00 45 00   ..l.....l.....E.
0010   00 c7 83 eb 40 00 40 06 b4 f1 c0 a8 04 81 cb 00   .Ç.ë@.@.´ñÀ¨..Ë.
0020   71 2a 85 f6 00 50 0d 52 a8 d5 ea 0f e8 9c 80 18   q*.ö.P.R¨Õê.è...
0030   00 ed 14 09 00 00 01 01 08 0a c2 9a 15 29 3c 93   .í........Â..)<.
0040   b2 9a 2b 00 3e 32 34 09 74 31 29 62 49 16 42 60   ².+.>24.t1)bI.B` #
0050   18 13 01 36 3d 06 01 7e 78 50 1a 13 15 43 63 66   ...6=..~xP...Ccf #
0060   1b 05 01 36 5f 09 49 1a 5a 10 04 57 18 22 5c 63   ...6_.I.Z..W."\c #
0070   45 33 00 69 1a 1c 55 2f 04 32 19 46 47 06 55 20   E3.i..U/.2.FG.U  #
0080   5c 06 11 25 19 2c 22 0f 66 27 7c 49 01 55 08 37   \..%.,".f'|I.U.7 # Partie intéressante
0090   50 47 42 7c 5b 42 5c 75 0c 52 13 51 0d 50 50 6b   PGB|[B\u.R.Q.PPk #
00a0   5a 17 17 20 5a 15 01 7a 57 5d 15 02 06 00 07 31   Z.. Z..zW].....1 #
00b0   0d 12 46 25 5f 12 53 29 02 05 44 02 0d 5a 53 67   ..F%_.S)..D..ZSg #
00c0   5b 42 16 25 0d 16 5d 7b 54 53 0b 38 6a 27 63 13   [B.%..]{TS.8j'c. #
00d0   38 33 35 11 33                                    835.3            #
```

J'écris les bytes dans un fichier et code un programme qui pourra XORer chaque caractère du fichier par la clé.

```python
#!/usr/bin/python3

import os

with open("/home/aether/Documents/FCSC/Forensics/C2MDP/requests/client_req.txt", "rb") as f:
    data = bytearray(f.read())

#Cle
KEY = "tDlsdL5dv25c1Rhv"

#Variable pour le plaintext
plaintext = bytes()

#XOR de chaque caractère
for _elem in range(len(data)):
    plaintext += bytes(chr(data[_elem] ^ ord(KEY[_elem % 16])).encode())

#Enregistrement dans un fichier
with open("client_plain.txt", "wb") as f:
    f.write(plaintext)

#Affichage du contenue
print("[+] File content\n=> {0}".format(os.popen("cat client_plain.txt").read()))
```

output :

```
[+] File content
=> _DRAPEAU_P|us2peurQue2M4l!  R4ssur3z-Votre-Am1-Et-vo1c1Votredr4peau_FCSC
{469e8168718996ec83a92acd6fe6b9c03c6ced2a3a7e7a2089b534baae97a7}
_DRAPEAU_y
```

flag: ```FCSC{469e8168718996ec83a92acd6fe6b9c03c6ced2a3a7e7a2089b534baae97a7}```
