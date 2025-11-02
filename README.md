# TAREA-3
Este repositorio tiene como objetivo usar scripts y liberías de Python para poder realizar actividades de ejecución pasiva (Resolución DNS y WHOIS públicas, recolección de certificados TLS públicos y solicitudes HTTP GET limitadas) y ejecución activa (escaneo ligero de nmap limitado a escaneo de puertos abiertos) éticamente y con permiso explícito.

# EL USO DEL CÓDIGO, O CUALQUIER OTRO ARCHIVO PERTENECIENTE A ESTE REPOSITORIO DE MANERA NO LEGAL/ÉTICA CAE EN RESPONSABILIDAD DE QUIEN LO USE. CÓDIGO CREADO CON FINES ÚNICAMENTE EDUCATIVOS. EL USO AJENO A ESCANEO DE DOMINIOS CON EL PERMISO EXPLÍCITO ESTÁ PROHIBIDO.

Dependencias requeridas:

* os 
* pathlib
* logging
* sys
* getpass
* argparse
* csv
* json
* subprocess
* datetime
* whois
* requests
* time
* re
* requests
* dnspython

## REQUIERE TENER UNA API KEY DE SHODAN LA CUAL PUEDA PROPORCIONAR.

# ¿Cómo manejar al apartado de actividades activas? 

Por defecto, el código **JAMÁS** va a ejecutar la función activa (escaneo con nmap para ver puertos abiertos) sin la confirmación explícita del usuario ejecutándolo, así asegurando el no ejecutarse de forma accidental.

