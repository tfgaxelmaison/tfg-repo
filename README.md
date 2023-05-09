# tfg-repo
Repositorio con el código utilizado para mi TFG de Phishing y Evasión de mecanismos antivirus en sistemas Windows

## Resumen del contenido

El contenido mostrado en este repositorio es todo el código utilizado para mi TFG en la Universidad Politécnica de Valencia, llamado **Phishing y mecanismos de evasión de antivirus en sistemas Windows**, en concreto aquí reside el código perteneciente a la parte de *Evasión de antivirus*.

La finalidad es crear una herramienta que permita evadir completamente cualquier antivirus y que se capaz de ejecutar un shellcode de manera eficaz y sin ninguna alerta o bloqueo del sistema antimalware.

Para ello se ha procedido a realizar 5 tareas diferentes para el mismo shellcode:
Creación manual del shellcode para sistemas Windows 11.
Creación manual de un encoder para el shellcode.
Creación manual de un decoder en ensamblador para el shellcode, que decodee el shellcode automáticamente en memoria.
Creación manual de un cifrado para el shellcode.
Creación manual de la herramienta que desencripte el shellcode y lo inyecte en la memoria de un proceso remoto

### Creación manual del shellcode

En la carpeta *Shellcode Ensamblador* se encuentra tanto el código en ensamblador del shellcode como sus respectivos opcodes o código hexadecimal

El shellcode se ha creado totalmente desde cero manualmente, se ha utilizado el PEB para descubrir la dirección base del kernel32.dll, se han parseado los PE Headers de esta librería para coger la dirección de memoria de GetProcAddress, y finalmente se ha utilizado esta función para coger LoadLibrary, y ya finalmente utilizar estas dos funciones para cargar las funciones y liberías necesarias.
Exactamente se ha creado un reverse tcp shell utilizando la librería ws2_32.dll.

### Creación manual de un encoder para el shellcode

En la carpeta *Encoding de shellcode* se encuentra el programa en C que realiza el encoding del shellcode.

Se trata de un encoder sencillo, simplemente realiza un XOR a todos los bytes del shellcode, le suma a todos los bytes 0x6 y después les vuelve a realizar otro XOR.

### Creación manual de un decoder en ensamblador para el shellcode, que decodee el shellcode automáticamente en memoria.

En la carpeta *Shellcode decoder ensamblador* se encuentra tanto el código en ensamblador del shellcode decoder como sus respectivos opcodes o código hexadecimal

Simplemente realiza el proceso inverso hecho en el encoding, pero todo en ensamblador, donde en la variable *mitextoescrito* se encuentra el shellcode encodeado, el programa desencodea automáticamente este string.
Se ha realizado en ensamblador, para así pasar este decoder también a su vez a shellcode, y poder inyectarlo en la memoria de un proceso para que pueda ser desencodeado en memoria, y no antes de su inyección, evitando así tareas de anáslisis dinámico del antivirus.


### Creación manual de un cifrado para el shellcode

En la carpeta *Cifrado de shellcode* se encuentra el programa en C que realiza el encriptado del shellcode.

Se ha utilizado la librería tiny-Aes-C para cifrar el shellcode del decoder utilizando el protocolo AES, este será el shellcode encriptado utilizado para la inyección.

### Creación manual de la herramienta que desencripte el shellcode y lo inyecte en la memoria de un proceso remoto

En *Inyección de Codigo" se encuentra el programa en C que realiza la descenriptación y inyección del shellcode.

Finalmente llega la herramienta final, se trata de un inyector típico con desencriptación.
Se utiliza nuevamente la librería tiny-AES-C para desencripta el shellcode, se reserva espacio en memoria en un proceos no protegido, se escribe el shellcode en ese espacio y finalmente se crea un thread remoto que tenga la dirección de inicio del shellcode para ejecutarse.
Esta herramienta es capaz de bypassear cualquier hook y anaálisis dinámico de un antiviturus, ya que no se han utilizado APIs para realizar la inyección, como OpenProcess o WriteProcessMemory, sinó que se han utilizado directamente las syscalls del propio sistema operativo.
Por tanto ningún hook que realice un antivirus a las apis de la librería user32.dll o ntdll.dll nos afectaría, evadiendo así cualquier hook y análisis dinámico.
