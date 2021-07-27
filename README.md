# Cepeda_API

| Routes                 	|        Function        	| Secured 	|
|------------------------	|:----------------------:	|---------	|
|          /test         	|     testing req/res    	|  false  	|
|          /new          	|    adds new contact    	|   true  	|
| /get/:id               	|   gets contact by id   	|   true  	|
| /delete/:id            	|  delete contact by id  	|   true  	|
| /update/:id            	|  update contact by id  	|   true  	|
|          /all          	|    get all contacts    	|   true  	|
| /search/:via           	| search contact by name 	|   true  	|
| /login/:user/:password 	|    login via params    	|  false  	|
| /login_nuke            	|     login via body     	|   semi  	|
| /secure/:message       	|  testing token verify  	|   true  	|
