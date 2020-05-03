# Académie de l'investigation - Premiers artéfacts

Points : 107 (Dynamique)

```
Pour avancer dans l'analyse, vous devez retrouver :

    Le nom de processus ayant le PID 1254.
    La commande exacte qui a été exécutée le 2020-03-26 23:29:19 UTC.
    Le nombre d'IP-DST unique en communications TCP établies (état ESTABLISHED) lors du dump.

Format du flag : FCSC{nom_du_processus:une_commande:n}

Le fichier de dump à analyser est identique au challenge C'est la rentrée.
```

## Pré-requis

Pour ce challenge, il fallait créer un profil pour pouvoir accèder aux informations de la machine sur ```volatility```.

J'ai donc créé une ```Debian 11 Alpha 2``` qui comportait déjà le kernel linux 5.4.0-4-amd64.

J'ai ensuite installé les paquets linux-image, linux-headers, linux-kbuild et linux-compiler. Je les ai téléchargés avec un ```wget``` puis les ai installés avec la commande ```dpkg -i```.

*Au moment où j'écris cela, les paquets que j'avais téléchargés en version 5.4.0-4 ont été remplacés sur le site par la version 5.5.0-4.*
*Je vous mets quand même le site, cela peut toujours servir : https://git.sdxlive.com/DR/plain/Debian/pool/stable/l/linux/*

Une fois les paquets installés, j'ai booté sur le système avec le kernel en 5.4.0-4 et j'ai téléchargé ```volatility``` pour fabriquer mon profil.

Le profil créé, j'ai pu le télécharger et le tester sur ma machine.

## Recherche du process PID 1254

En listant toutes les commandes de ```volatility``` pour Linux, je tombe sur quatre d'entre elles plutôt intéressantes pour cette partie :

 * linux_psaux    	Gathers processes along with full command line and start time
 * linux_psenv    	Gathers processes along with their static environment variables
 * linux_psscan   	Scan physical memory for processes 
 * linux_pstree   	Shows the parent/child relationship between processes

J'essaye chacune d'entre elles.

### linux_psaux

Cette commande renvoie beaucoup de pid mais pas celui que je cherche.

```
[snip]
1251   1001   1001                                                                   
1257   1001   1001                                                                   
1263   1001   1001                                                                   
1265   1001   1001   xfwm4 --display :0.0 --sm-client-id 261c061fc-dabb-4cf0-9228-cdd5ad56d476
[snip]
```

### linux_psenv

Cette commande renvoie les variables d'environnement utilisées par les programmes.

Je me suis donc dit que je pourrais potentiellement le trouver ici.

```
[snip]
at-spi-bus-laun   1242   
dbus-daemon       1247   
xfconfd           1251   
at-spi2-registr   1257   
gpg-agent         1263
[snip]
```

Mais toujours rien...

### linux_psscan

Cette commande affiche beaucoup, beaucoup trop de lignes, j'essaye de faire un ```| grep``` pour voir si le processus ne s'y cache pas.

```
[ aether@ysera  ~/Documents/FCSC/Forensics/AI-CLR  % ] vol -f dmp.mem --profile=LinuxDebian11-kernel_5_4_0-4x64 linux_psscan | grep 1254
Volatility Foundation Volatility Framework 2.6
0x000000003fdccd80 pool-xfconfd         1254            -               -1              -1     0x0fd08ee88ee08ec0 -
```

Bingo ! J'ai le nom du process avec le PID 1254

## Commande exécutée le 2020-03-26 23:29:19 UTC

Etant donné que je cherche une commande, je vais directement utiliser le plugin ```linux_bash``` qui affiche les commandes executées.

```bash
[ aether@ysera  ~/Documents/FCSC/Forensics/AI-CLR  % ] vol -f dmp.mem --profile=LinuxDebian11-kernel_5_4_0-4x64 linux_bash
Volatility Foundation Volatility Framework 2.6
Pid      Name                 Command Time                   Command
-------- -------------------- ------------------------------ -------
    1523 bash                 2020-03-26 23:24:18 UTC+0000   rm .bash_history 
    1523 bash                 2020-03-26 23:24:18 UTC+0000   exit
    1523 bash                 2020-03-26 23:24:18 UTC+0000   vim /home/Lesage/.bash_history 
    1523 bash                 2020-03-26 23:24:27 UTC+0000   ss -laupt
    1523 bash                 2020-03-26 23:26:06 UTC+0000   rkhunter -c
    1523 bash                 2020-03-26 23:29:19 UTC+0000   nmap -sS -sV 10.42.42.0/24
    1523 bash                 2020-03-26 23:31:31 UTC+0000   ?+??U
    1523 bash                 2020-03-26 23:31:31 UTC+0000   ip -c addr
    1523 bash                 2020-03-26 23:38:00 UTC+0000   swapoff -a
    1523 bash                 2020-03-26 23:38:05 UTC+0000   swapon -a
    1523 bash                 2020-03-26 23:40:18 UTC+0000   ls
    1523 bash                 2020-03-26 23:40:23 UTC+0000   cat LiME.txt 
    1523 bash                 2020-03-26 23:40:33 UTC+0000   cd LiME/src/
    1523 bash                 2020-03-26 23:40:54 UTC+0000   
    1523 bash                 2020-03-26 23:40:54 UTC+0000   insmod lime-5.4.0-4-amd64.ko "path=/dmp.mem format=lime timeout=0"
```

Parfait ! La commande executée à ```2020-03-26 23:29:19 UTC``` est donc ```nmap -sS -sV 10.42.42.0/24```.

## Nombre d'IP-DST unique en communication TCP établies

Pour cette partie, je vais utiliser le plugin ```linux_netscan``` qui renvoie toutes les connexions de la machine.

J'en profite pour faire un ```| grep ESTABLISHED``` car seulement les connexions établies sont demandées.

```bash
[ aether@ysera  ~/Documents/FCSC/Forensics/AI-CLR  % ] vol -f dmp.mem --profile=LinuxDebian11-kernel_5_4_0-4x64 linux_netscan | grep ESTABLISHED
Volatility Foundation Volatility Framework 2.6
9d72830a8000 TCP      10.42.42.131    :58772 185.199.111.154 :  443 ESTABLISHED    
9d72830a88c0 TCP      10.42.42.131    :45652 35.190.72.21    :  443 ESTABLISHED    
9d72830a9a40 TCP      10.42.42.131    :53190 104.124.192.89  :  443 ESTABLISHED    
9d72830abd40 TCP      10.42.42.131    :55226 151.101.121.140 :  443 ESTABLISHED    
9d72830ad780 TCP      10.42.42.131    :50612 104.93.255.199  :  443 ESTABLISHED    
9d72830af1c0 TCP      10.42.42.131    :38184 216.58.213.142  :  443 ESTABLISHED    
9d7284eba300 TCP      10.42.42.131    :37252 163.172.182.147 :  443 ESTABLISHED    
9d7284fe9180 TCP      127.0.0.1       :38498 127.0.0.1       :34243 ESTABLISHED    
9d7284fe9a40 TCP      10.42.42.131    :57000 10.42.42.134    :   22 ESTABLISHED    
9d7284feb480 TCP      10.42.42.131    :51858 10.42.42.128    :  445 ESTABLISHED    
9d7284fef1c0 TCP      10.42.42.131    :55224 151.101.121.140 :  443 ESTABLISHED    
9d7293778000 TCP      10.42.42.131    :47100 216.58.206.226  :  443 ESTABLISHED    
9d729377cec0 TCP      10.42.42.131    :47106 216.58.206.226  :  443 ESTABLISHED    
9d72c0acb480 TCP      10.42.42.131    :36970 116.203.52.118  :  443 ESTABLISHED    
9d72c1503d40 TCP      127.0.0.1       :34243 127.0.0.1       :38498 ESTABLISHED    
9d72c1bc1280 TCP      fd:6663:7363:1000:c10b:6374:25f:dc37:36280 fd:6663:7363:1000:55cf:b9c6:f41d:cc24:58014 ESTABLISHED    
9d72c23fcec0 TCP      10.42.42.131    :38186 216.58.213.142  :  443 ESTABLISHED    
9d72c23fe040 TCP      10.42.42.131    :47104 216.58.206.226  :  443 ESTABLISHED    
9d72c23fe900 TCP      10.42.42.131    :47102 216.58.206.226  :  443 ESTABLISHED
```

Je supprime le garbage pour garder seulement les adresses IP de destination.

```
185.199.111.154    
35.190.72.21       
104.124.192.89     
151.101.121.140    
104.93.255.199     
216.58.213.142     
163.172.182.147    
127.0.0.1          
10.42.42.134       
10.42.42.128       
151.101.121.140    
216.58.206.226     
216.58.206.226     
116.203.52.118     
127.0.0.1          
fd:6663:7363:1000:55cf:b9c6:f41d:cc24    
216.58.213.142    
216.58.206.226    
216.58.206.226
```

Il ne me reste plus qu'à supprimer les doublons.

```
185.199.111.154     
35.190.72.21        
104.124.192.89          
104.93.255.199            
163.172.182.147                
10.42.42.134        
10.42.42.128        
151.101.121.140           
116.203.52.118      
127.0.0.1           
fd:6663:7363:1000:55cf:b9c6:f41d:cc24    
216.58.213.142      
216.58.206.226
```

Je me retrouve donc avec une liste de 13 @IP-DST.

## Flag

PID = "pool-xfconfd"
command = "nmap -sS -sV 10.42.42.0/24"
ip_dst = "13"

Format du flag : FCSC{nom_du_processus:une_commande:n}

flag: ```FCSC{pool-xfconfd:nmap -sS -sV 10.42.42.0/24:13}```
