# Laboratorio-3-SO---Gestion-de-Memoria
---
# 1) Espacio de direcciones

## Actividad 1.1: Programa base
<img width="746" height="234" alt="image" src="https://github.com/user-attachments/assets/f261b1e0-ed26-475d-8725-dc345d54e323" />

## Actividad 1.2: Visualizar los mapas de memoria de un proceso
<img width="1110" height="967" alt="Captura de pantalla 2026-04-30 102834" src="https://github.com/user-attachments/assets/0fbf4f76-9a49-498b-8600-0ae8cf5c3451" />

## Actividad 1.3: Exploración de `/proc/[pid]/maps`

### Punto 1: Analisis de las regiones text, heap y stack 

Mientras el proceso `mem_map` esperaba el ENTER, se leyó su mapa de memoria con:

```bash
cat /proc/$(pgrep mem_map)/maps
```

Se identificaron las siguientes regiones:

####  Región TEXT (código)
```text
55f554dc8000-55f554dc9000    r-xp    00001000    08:20    58513    /home/equipo/proyectosC/LAB SO/LAB03/mem_map
```

| Campo | Valor |
|-------|-------|
| Rango | `55f554dc8000` – `55f554dc9000` |
| Permisos | `r-xp` |

**Permisos:** lectura (`r`) y ejecución (`x`), **sin escritura**.

**¿Por qué?** Esta región contiene el código máquina del programa (instrucciones). No necesita ser escrita en tiempo de ejecución. Prohibir la escritura es una medida de seguridad que evita que código malicioso modifique las instrucciones en memoria (*code injection*).

---

####  Región HEAP
```text
55f5726ea000-55f57270b000   rw-p   00000000   00:00   0   [heap]
```


| Campo | Valor |
|-------|-------|
| Rango | `55f5726ea000` – `55f57270b000` |
| Permisos | `rw-p` |

**Permisos:** lectura (`r`) y escritura (`w`), **sin ejecución**.

**¿Por qué?** El heap almacena datos dinámicos creados con `malloc`. Deben poder leerse y modificarse. Sin embargo, no debe tener permiso de ejecución, ya que permitir ejecutar código desde el heap facilitaría ataques como buffer overflows o inyección de shellcode; esto se evita mediante la protección **NX/DEP** — *No eXecute / Data Execution Prevention*.

---

####  Región STACK
```text
7fffb3845000-7fffb3866000   rw-p   00000000   00:00   0   [stack]
```

| Campo | Valor |
|-------|-------|
| Rango | `7fffb3845000` – `7fffb3866000` |
| Permisos | `rw-p` |

**Permisos:** lectura (`r`) y escritura (`w`), **sin ejecución**.

**¿Por qué?** El stack almacena variables locales y direcciones de retorno de funciones. Al igual que el heap, necesita lectura y escritura, pero no ejecución. La protección NX también aplica aquí para prevenir ataques de tipo *stack overflow* con inyección de shellcode.

---

#### Resumen comparativo

| Región | Permisos | r | w | x | Razón principal |
|--------|----------|---|---|---|-----------------|
| text   | `r-xp`   | Si | No | Si | Solo se ejecuta, no se modifica |
| heap   | `rw-p`   | Si | Si | No | Datos dinámicos, no ejecutables |
| stack  | `rw-p`   | Si | Si | No | Variables locales, no ejecutables |

> **La `p` al final de los permisos indica que la región es **privada** (*copy-on-write*),**
> **es decir, si el proceso la modifica, el SO le da una copia propia sin afectar a otros procesos.**

---

#### ¿Por qué difieren los permisos?

Cada región tiene un propósito distinto, y el SO aplica el principio de **mínimo privilegio**:
solo se otorgan los permisos estrictamente necesarios para que cada región funcione.
Esto se conoce como la política **W⊕X** (*Write XOR Execute*): una región puede ser
escribible o ejecutable, pero no ambas al mismo tiempo, lo que reduce drásticamente
la superficie de ataque ante exploits de memoria.

### Punto 2: Comparación de direcciones impresas vs rangos de `/proc/maps`

Al ejecutar el programa, se obtuvieron las siguientes direcciones virtuales:

```bash
PID del proceso  : 4405
Dir. codigo (main) : 0x55f554dc8209
Dir. global_var    : 0x55f554dcb010
Dir. local_var     : 0x7fffb386327c
Dir. heap_var      : 0x55f5726ea2a0
```

A continuación se compara cada dirección con los rangos del mapa de memoria:

---

####  `main` → Región TEXT

| | Valor |
|---|---|
| Dirección impresa | `0x55f554dc8209` |
| Rango en `/proc/maps` | `55f554dc8000` – `55f554dc9000` |
| Permisos | `r-xp` |
| Región | **text (código)** |

`0x55f554dc8209` cae dentro del rango `[55f554dc8000, 55f554dc9000)` 

`main` es una función, por tanto su dirección pertenece al segmento de código
del ejecutable, que es de solo lectura y ejecución.

---

####  `global_var` → Región DATA

| | Valor |
|---|---|
| Dirección impresa | `0x55f554dcb010` |
| Rango en `/proc/maps` | `55f554dcb000` – `55f554dcc000` |
| Permisos | `rw-p` |
| Región | **data (variables globales inicializadas)** |

`0x55f554dcb010` cae dentro del rango `[55f554dcb000, 55f554dcc000)` 

`global_var` fue declarada como `int global_var = 42`, es decir, una variable
global **inicializada**, por lo que el compilador la ubica en el segmento `.data`,
que tiene permisos de lectura y escritura pero no de ejecución.

---

####  `local_var` → Región STACK

| | Valor |
|---|---|
| Dirección impresa | `0x7fffb386327c` |
| Rango en `/proc/maps` | `7fffb3845000` – `7fffb3866000` |
| Permisos | `rw-p` |
| Región | **stack** |

`0x7fffb386327c` cae dentro del rango `[7fffb3845000, 7fffb3866000)` 

`local_var` es una variable local declarada dentro de `main`, por lo que el
compilador la asigna automáticamente en el stack. Nótese que las direcciones
del stack son las más altas del espacio de usuario, cerca de `0x7fff...`.

---

####  `heap_var` → Región HEAP

| | Valor |
|---|---|
| Dirección impresa | `0x55f5726ea2a0` |
| Rango en `/proc/maps` | `55f5726ea000` – `55f57270b000` |
| Permisos | `rw-p` |
| Región | **heap** |

`0x55f5726ea2a0` cae dentro del rango `[55f5726ea000, 55f57270b000)` 

`heap_var` fue creada con `malloc()`, que solicita memoria dinámica al SO.
Esta memoria se asigna en el heap, que crece hacia direcciones más altas
a medida que se hacen más llamadas a `malloc`.

---

#### Resumen comparativo

| Variable | Dirección virtual | Región | Permisos |
|---|---|---|---|
| `main` | `0x55f554dc8209` | text | `r-xp` |
| `global_var` | `0x55f554dcb010` | data | `rw-p` |
| `local_var` | `0x7fffb386327c` | stack | `rw-p` |
| `heap_var` | `0x55f5726ea2a0` | heap | `rw-p` |

> **El stack crece hacia **direcciones bajas** y el heap hacia **direcciones altas**,**
> **dejando un amplio espacio libre entre ambos para que cada uno pueda crecer**
> **sin colisionar inmediatamente.**

### Punto 3: Otras regiones en el mapa de memoria

Además de las regiones principales (text, data, heap, stack), en la salida de
`/proc/maps` aparecen otras regiones correspondientes a bibliotecas y zonas
especiales del kernel:

---


#### `libc.so.6` — Biblioteca estándar de C
```text
7f1fbb842000-7f1fbb86a000    r--p   ...   /usr/lib/x86_64-linux-gnu/libc.so.6
7f1fbb86a000-7f1fbb9f2000    r-xp   ...   /usr/lib/x86_64-linux-gnu/libc.so.6
7f1fbb9f2000-7f1fbba41000    r--p   ...   /usr/lib/x86_64-linux-gnu/libc.so.6
7f1fbba41000-7f1fbba45000    r--p   ...   /usr/lib/x86_64-linux-gnu/libc.so.6
7f1fbba45000-7f1fbba47000    rw-p   ...   /usr/lib/x86_64-linux-gnu/libc.so.6
```

| Subregión | Permisos | Contenido |
|---|---|---|
| `r--p` | solo lectura | metadatos y datos de solo lectura |
| `r-xp` | lectura + ejecución | código ejecutable de libc |
| `rw-p` | lectura + escritura | datos globales de libc |

**¿Qué función cumple?**
Es la biblioteca estándar de C. Contiene la implementación de funciones que
el programa usa directamente como `printf`, `malloc`, `free`, `getchar` y
`getpid`. En lugar de compilar estas funciones dentro del ejecutable, el SO
las carga dinámicamente en memoria y las comparte entre todos los procesos
que las necesiten.

---

####  `ld-linux-x86-64.so.2` — Enlazador dinámico
```text
7f1fbba5b000-7f1fbba5c000   r--p   ...   /usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2
7f1fbba5c000-7f1fbba87000   r-xp   ...   /usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2
7f1fbba87000-7f1fbba91000   r--p   ...   /usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2
7f1fbba91000-7f1fbba93000   r--p   ...   /usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2
7f1fbba93000-7f1fbba95000   rw-p   ...   /usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2
```

**¿Qué función cumple?**
Es el **enlazador dinámico** (*dynamic linker/loader*). Se encarga de:

- Cargar en memoria todas las bibliotecas compartidas (`.so`) que el programa necesita antes de que `main` empiece a ejecutarse.
- Resolver los símbolos (funciones y variables) de dichas bibliotecas, conectándolos con las llamadas del programa.
- Es lo primero que ejecuta el kernel al lanzar el proceso, incluso antes que el propio `main`.

---

####  `[vdso]` — Virtual Dynamic Shared Object
```text
7fffb3970000-7fffb3972000   r-xp   00000000   00:00   0   [vdso]
```

| Campo | Valor |
|---|---|
| Permisos | `r-xp` |
| Ubicación | cerca del stack, en direcciones altas |

**¿Qué función cumple?**
Es una pequeña biblioteca que el **kernel mapea automáticamente** en el espacio
de cada proceso. Permite que ciertas llamadas al sistema frecuentes (como
`gettimeofday` o `clock_gettime`) se ejecuten **sin hacer una syscall real**,
es decir, sin cambiar al modo kernel. Esto reduce drásticamente el costo de
esas operaciones.

---

####  `[vvar]` — Variables del kernel compartidas
```text
7fffb396c000-7fffb3970000   r--p   00000000   00:00   0   [vvar]
```

| Campo | Valor |
|---|---|
| Permisos | `r--p` |

**¿Qué función cumple?**
Es una región de **solo lectura** donde el kernel expone ciertas variables
internas (como el tiempo actual del sistema) directamente en el espacio del
proceso. El `[vdso]` lee desde `[vvar]` para responder llamadas como
`clock_gettime` sin necesidad de entrar al kernel. El proceso puede leer
estos datos pero **nunca modificarlos**.

---

####  Regiones anónimas `[ anon ]`
```text
7f1fbba47000-7f1fbba59000   rw-p   ...   [ anon ]
7f1fbba59000-7f1fbba5b000   rw-p   ...   [ anon ]
```

**¿Qué función cumple?**
Son regiones de memoria privada sin respaldo en ningún archivo en disco.
Generalmente las usa `libc` internamente para sus propias estructuras de
datos (como el administrador del heap de `malloc`). Aparecen como `anon`
porque no están asociadas a ningún archivo mapeado.

---

#### Resumen de todas las regiones

| Región | Permisos | Función |
|---|---|---|
| `mem_map` (text) | `r-xp` | Código ejecutable del programa |
| `mem_map` (data) | `rw-p` | Variables globales inicializadas |
| `[heap]` | `rw-p` | Memoria dinámica (`malloc`) |
| `libc.so.6` | `r-xp / rw-p` | Biblioteca estándar de C |
| `ld-linux-x86-64.so.2` | `r-xp / rw-p` | Enlazador dinámico |
| `[stack]` | `rw-p` | Variables locales y retornos de función |
| `[vdso]` | `r-xp` | Syscalls rápidas sin entrar al kernel |
| `[vvar]` | `r--p` | Variables del kernel de solo lectura |
| `[ anon ]` | `rw-p` | Uso interno de bibliotecas |

> Nota: en algunos sistemas más antiguos puede aparecer también `[vsyscall]`,
> que es el predecesor de `[vdso]`. Cumple una función similar pero con un
> mecanismo menos eficiente y seguro. En kernels modernos fue reemplazado
> completamente por `[vdso]`.

### Punto 4: ¿Son las direcciones virtuales iguales a las físicas?

No. Todas las direcciones vistas hasta ahora, tanto las impresas por el
programa en C como las de `/proc/maps` y `pmap`, son direcciones virtuales.
Nunca coinciden necesariamente con las direcciones físicas reales en la RAM.

---

#### El concepto de Address Space (OSTEP)

El libro OSTEP  define el espacio de direcciones virtual (*address space*) como la abstracción que el SO le
presenta a cada proceso: la ilusión de que tiene toda la memoria para sí solo,
organizada de forma contigua y privada.

Cada proceso tiene su propio espacio de direcciones virtual, completamente
independiente del de los demás procesos. Por eso dos procesos distintos pueden
tener una variable en la misma dirección virtual sin que haya
ningún conflicto. Cada una apunta a una ubicación física diferente en RAM.

La traducción la realiza el hardware mediante la MMU (*Memory Management
Unit*), usando las tablas de páginas (*page tables*) que mantiene el kernel
para cada proceso:

```text
Proceso (usuario)
│
│  dirección virtual (lo que ve el programa)
▼
┌─────────────┐
│     MMU     │  ← hardware del procesador
│  (page table│
│   lookup)   │
└─────────────┘
│
│  dirección física (ubicación real en RAM)
▼
RAM física
```
---

## Actividad 1.4 : Comparar espacios de dos procesos simultáneos

Se ejecutaron dos instancias de `mem_map` simultáneamente en dos terminales
distintas, obteniendo las siguientes salidas:

#### Salidas obtenidas

<img width="732" height="158" alt="image" src="https://github.com/user-attachments/assets/192b20f8-be4c-4065-a51b-5709e7082b3a" />

**Proceso A (PID 520):**
```bash
PID del proceso  : 520
Dir. codigo (main) : 0x559b40b0a209
Dir. global_var    : 0x559b40b0d010
Dir. local_var     : 0x7ffe8d22188c
Dir. heap_var      : 0x559b4e0062a0
```

<img width="732" height="160" alt="image" src="https://github.com/user-attachments/assets/19335a9d-5c30-4501-8b15-fe0c2be36113" />

**Proceso B (PID 521):**
```bash
PID del proceso  : 521
Dir. codigo (main) : 0x5562978a8209
Dir. global_var    : 0x5562978ab010
Dir. local_var     : 0x7ffc3f32919c
Dir. heap_var      : 0x5562d13f92a0
```

---

#### Tabla comparativa de direcciones

| Variable | Proceso A (PID 520) | Proceso B (PID 521) | ¿Iguales? |
|---|---|---|---|
| `main` | `0x559b40b0a209` | `0x5562978a8209` |  No |
| `global_var` | `0x559b40b0d010` | `0x5562978ab010` |  No |
| `local_var` | `0x7ffe8d22188c` | `0x7ffc3f32919c` |  No |
| `heap_var` | `0x559b4e0062a0` | `0x5562d13f92a0` |  No |

> Nota: en sistemas **sin ASLR** (*Address Space Layout Randomization*) las
> direcciones virtuales de `main` y `global_var` suelen coincidir entre
> instancias del mismo ejecutable, ya que el SO las cargaría siempre en la
> misma posición virtual. En este caso difieren porque Linux tiene **ASLR
> activado por defecto**, lo que aleatoriza la base del ejecutable en cada
> ejecución para dificultar ataques de tipo *return-oriented programming*.

---

### Punto 1: ¿Son las mismas direcciones virtuales? Conclusión sobre aislamiento

Las direcciones virtuales no son iguales entre los dos procesos. Esto
demuestra dos conceptos fundamentales:

**1. Cada proceso tiene su propio espacio de direcciones virtual independiente.**
Aunque ambos procesos ejecutan el mismo binario `mem_map`, el SO le asigna
a cada uno su propio mapa de memoria completamente separado. No comparten
ninguna dirección virtual (salvo regiones de solo lectura como `libc`, que
el kernel puede mapear en la misma dirección física pero con diferentes
entradas en cada tabla de páginas).

**2. El aislamiento es total.**
Ningún proceso puede "ver" el espacio de direcciones del otro. Desde la
perspectiva del Proceso A, la dirección `0x5562978ab010` (donde vive
`global_var` del Proceso B) simplemente no existe o apunta a una región
completamente diferente de su propio espacio virtual. El SO garantiza este
aislamiento mediante las **tablas de páginas individuales** que mantiene
para cada proceso.

```
Proceso A (PID 520)          Proceso B (PID 521)
────────────────────         ────────────────────
0x559b40b0d010 → global_var  0x5562978ab010 → global_var
       │                            │
       ▼                            ▼
 frame físico X                frame físico Y
 (RAM: distinta ubicación)     (RAM: distinta ubicación)
```

**Conclusión:** el espacio de direcciones virtual es una abstracción privada
por proceso. Dos procesos con la misma dirección virtual apuntan a ubicaciones
físicas completamente distintas en RAM. Esto es el núcleo del concepto de
*address space* descrito en OSTEP.

---

### Punto 2: ¿Podría el Proceso A leer o modificar la variable global del Proceso B?

**No. Es imposible desde el espacio de usuario.**

#### Razones:

**1. Tablas de páginas separadas**
Cada proceso tiene su propia tabla de páginas gestionada por el kernel. Cuando
el Proceso A accede a cualquier dirección virtual, la MMU consulta únicamente
*su* tabla de páginas. La dirección virtual `0x5562978ab010` (donde vive
`global_var` del Proceso B) o bien no tiene entrada en la tabla del Proceso A,
o apunta a un frame físico completamente distinto. En ambos casos, el Proceso A
**nunca llega** a la memoria física del Proceso B.

**2. Protección por hardware (MMU)**
Si el Proceso A intentara acceder a una página que no tiene mapeada, la MMU
generaría un **segmentation fault** (`SIGSEGV`) y el kernel terminaría el
proceso inmediatamente. Este control lo ejerce el hardware, no solo el SO,
por lo que no puede ser evadido desde código de usuario.

**3. ASLR como capa adicional**
Incluso si un atacante conociera la dirección virtual de `global_var` en el
Proceso B, esa dirección no tiene ningún significado en el espacio del Proceso A.
Las direcciones virtuales son locales a cada proceso.

#### Resumen

| Pregunta | Respuesta |
|---|---|
| ¿Puede el Proceso A leer `global_var` del Proceso B por su dirección virtual? |  No |
| ¿Por qué? | Tablas de páginas separadas + protección por MMU |
| ¿Qué pasaría si lo intentara? | `SIGSEGV` — el kernel terminaría el proceso |
| ¿Existe alguna forma de compartir memoria? |  Sí, mediante IPC controlado por el kernel |

> Este mecanismo de aislamiento es lo que hace que un proceso con errores o
> comportamiento malicioso no pueda corromper la memoria de otros procesos
> ni la del propio kernel. Es uno de los pilares de seguridad y estabilidad
> de los sistemas operativos modernos.

---

# 2) API de memoria
## Actividad 2.1: Programa base
<img width="1307" height="431" alt="image" src="https://github.com/user-attachments/assets/21114ec0-7888-4784-ad92-82487ac44a76" />

## Atividad 2.2: Uso correcto de malloc y free
### Punto 1
**¿Reporta errores o fugas de memoria?**

No. La ejecución es completamente limpia, confirmado por dos líneas clave:

- **`All heap blocks were freed -- no leaks are possible`** → ninguna fuga de memoria.
- **`ERROR SUMMARY: 0 errors from 0 contexts`** → ningún error de acceso a memoria.

### Análisis del HEAP SUMMARY

| Campo | Valor | Significado |
|---|---|---|
| `in use at exit` | 0 bytes en 0 bloques | No quedó ningún bloque sin liberar al terminar el programa |
| `total heap usage` | 3 allocs, 3 frees | Cada asignación tuvo su correspondiente liberación |
| `bytes allocated` | 1,144 bytes | Total acumulado durante toda la ejecución |

Aunque el código solo llama explícitamente a `malloc` y `realloc`, Valgrind reporta **3 allocs** porque la librería estándar de C (`stdio`) también reserva un buffer interno al usar `printf`. El desglose aproximado es:

- `malloc` inicial → 40 bytes (10 enteros)
- `realloc` → 80 bytes (20 enteros)
- Buffer interno de `stdio` → ~1,024 bytes

### ¿Qué significa "All heap blocks were freed"?

Este mensaje indica que cada byte reservado dinámicamente fue correctamente liberado antes de que el programa terminara. Valgrind rastrea cada llamada a `malloc`/`realloc` y verifica que exista un `free` correspondiente. Al confirmar que el balance es cero (`3 allocs == 3 frees` y `in use at exit: 0 bytes`), garantiza que no hay fugas de memoria posibles.

> **Nota:** Si se hubiera omitido el `free(arr)` al final del programa, Valgrind habría reportado algo como:
> ```
> LEAK SUMMARY:
>    definitely lost: 80 bytes in 1 blocks
> ```
> indicando exactamente cuántos bytes y en cuántos bloques se produjo la fuga.

---
### Punto 2
**¿Por qué usar `sizeof(int)` en lugar del literal `4`?**

Escribir `malloc(n * 4)` asume que un `int` **siempre** ocupa 4 bytes. Esto es falso en términos
del estándar C: el tamaño de `int` depende de la arquitectura y el compilador.

**¿Cuánto puede medir un `int` según la arquitectura?**

| Arquitectura / Plataforma | Tamaño de `int` |
|---|---|
| x86 / x86-64 (PC moderno) | 4 bytes |
| AVR (microcontroladores Arduino) | 2 bytes |
| Algunos sistemas embebidos de 8/16 bits | 2 bytes |
| Cray (supercomputadoras antiguas) | 8 bytes |

El estándar C solo garantiza que `int` tiene al menos 16 bits. El resto depende
de la implementación.

**Ventaja de `sizeof(int)`**

`sizeof` es evaluado en tiempo de compilación por el compilador, quien conoce exactamente
cuánto ocupa cada tipo en esa arquitectura específica. Esto significa:

- Mismo código fuente compila y funciona correctamente en cualquier plataforma.
- Si en una arquitectura `int` mide 2 bytes, `sizeof(int)` retorna `2` automáticamente.
- No hay que buscar y reemplazar literales numéricos al portar el código.

**Regla general**

> Nunca asumir el tamaño de un tipo de dato en C. Siempre usar `sizeof` para que
> el compilador determine el tamaño correcto en cada plataforma.

Esto aplica no solo a `int`, sino a cualquier tipo: `double`, `long`, structs, etc.

### Punto 3
**¿Qué devuelve `malloc` cuando no hay memoria disponible?**

Cuando el sistema no puede satisfacer la solicitud de memoria, `malloc` devuelve **`NULL`**
(un puntero nulo, es decir, la dirección `0x0`). No lanza una excepción ni detiene el programa:
simplemente retorna `NULL` y continúa.

**¿Por qué es crítico verificar ese valor?**

Si no se verifica y se intenta usar el puntero `NULL` como si fuera memoria válida, ocurre
una desreferenciación de puntero nulo, lo cual produce:

| Consecuencia | Descripción |
|---|---|
| **Segmentation Fault** | El SO detecta el acceso a dirección inválida y mata el proceso |
| **Comportamiento indefinido** | El estándar C no garantiza nada; puede pasar cualquier cosa |
| **Corrupción de datos** | En sistemas sin protección de memoria podría sobrescribir datos ajenos |
| **Vulnerabilidad de seguridad** | Atacantes pueden explotar la falta de validación para ejecutar código arbitrario |


**¿Cuándo puede fallar `malloc`?**

- El sistema no tiene suficiente memoria RAM + swap disponible.
- El proceso alcanzó su límite de memoria asignado por el SO.
- El heap está fragmentado y no hay un bloque contiguo del tamaño solicitado.
- Se solicita un tamaño absurdamente grande (ej: `malloc(-1)` que por desbordamiento
se convierte en un número enorme).

> **Regla crítica:** Toda llamada a `malloc`, `realloc` o `calloc` debe ir seguida
> de una verificación de `NULL`. Omitirla es un error de programación, no una optimización.

---
## Actividad 2.3 Código bon bugs de memoria
<img width="1062" height="203" alt="image" src="https://github.com/user-attachments/assets/8b06f71f-65c3-4334-9994-9c534014fe21" />
<img width="1096" height="875" alt="image" src="https://github.com/user-attachments/assets/14649ab8-2775-4a10-a196-29940c44f6e6" />

## Actividad 2.4: Identificar y corregir errores de memoria
### Punto 1: Mensajes de Valgrind y su correspondencia con cada error
#### Error 1 — Buffer Overflow (desbordamiento de búfer)
**Mensaje de Valgrind:**
```text
==3406== Invalid write of size 4
==3406==    at 0x1091E3: main (buggy_mem.c:10)
==3406==  Address 0x4a74054 is 0 bytes after a block of size 20 alloc'd
==3406==    at 0x4846828: malloc (in /usr/libexec/valgrind/vgpreload_memcheck-amd64-linux.so)
==3406==    by 0x1091BE: main (buggy_mem.c:8)
```
**Causa en el código:**
```c
int *p = malloc(5 * sizeof(int));  // bloque válido: índices 0..4
for (int i = 0; i <= 5; i++)       //  i=5 queda fuera del bloque
    p[i] = i;
```

El operador `<=` hace que el bucle escriba en `p[5]`, una posición que está **0 bytes después**
del bloque reservado (de ahí el mensaje *"0 bytes after a block of size 20"*). Valgrind lo
detecta como una **escritura inválida de 4 bytes**.

---

#### Error 2 — Memory Leak (fuga de memoria)

**Mensaje de Valgrind:**
```text
==3406== 100 bytes in 1 blocks are definitely lost in loss record 1 of 1
==3406==    at 0x4846828: malloc (in /usr/libexec/valgrind/vgpreload_memcheck-amd64-linux.so)
==3406==    by 0x1091F8: main (buggy_mem.c:13)
==3406== LEAK SUMMARY:
==3406==    definitely lost: 100 bytes in 1 blocks
```
**Causa en el código:**
```c
char *q = malloc(100);   // se reservan 100 bytes
strcpy(q, "hola mundo");
printf("%s\n", q);
//  nunca se llama free(q)
```

El puntero `q` nunca es liberado. Valgrind lo clasifica como *"definitely lost"*: el programa
terminó y esos 100 bytes quedaron reservados sin que nadie los devolviera al sistema.

---

#### Error 3 — Use-After-Free (uso después de liberar)

**Mensaje de Valgrind:**
```text
==3406== Invalid read of size 4
==3406==    at 0x109231: main (buggy_mem.c:19)
==3406==  Address 0x4a74040 is 0 bytes inside a block of size 20 free'd
==3406==    at 0x484988F: free (in /usr/libexec/valgrind/vgpreload_memcheck-amd64-linux.so)
==3406==    by 0x10922C: main (buggy_mem.c:18)
==3406==  Block was alloc'd at
==3406==    at 0x4846828: malloc (...)
==3406==    by 0x1091BE: main (buggy_mem.c:8)
```

**Causa en el código:**
```c
free(p);                          // se libera el bloque
printf("p[0] = %d\n", p[0]);     //  se lee memoria ya liberada
```

Después de `free(p)`, el bloque ya no le pertenece al programa. Valgrind detecta una
**lectura inválida de 4 bytes** dentro de un bloque que ya fue liberado, e incluso indica
en qué línea se hizo el `free` y dónde se hizo el `malloc` original.

---

### Resumen de errores detectados

| # | Error | Tipo | Detectado por | Línea |
|---|---|---|---|---|
| 1 | `p[5] = 5` fuera del bloque | Buffer Overflow | `Invalid write of size 4` | buggy_mem.c:10 |
| 2 | `q` nunca liberado | Memory Leak | `definitely lost: 100 bytes` | buggy_mem.c:13 |
| 3 | Lectura de `p` tras `free` | Use-After-Free | `Invalid read of size 4` | buggy_mem.c:19 |

> **ERROR SUMMARY: 3 errors from 3 contexts** — cada error clásico tiene exactamente
> un mensaje correspondiente en la salida de Valgrind.

### Punto 2: buggy_mem_fixed.c (Programa corregido)
```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main() {

    int *p = malloc(5 * sizeof(int));
    for (int i = 0; i < 5; i++) /* Corregido: < en vez de <= */
    p[i] = i;

    
    char *q = malloc(100);
    strcpy(q, "hola mundo");
    printf("%s\n", q);
    free(q); /* Corregido: se libera la memoria de q para evitar memory leak */

    
    printf("p[0] = %d\n", p[0]); /* Corregido: se accede a p antes de liberarla */
    free(p);
    
    
    return 0;
}
```
#### Verificación con Valgrind del programa corregido:

<img width="1384" height="433" alt="image" src="https://github.com/user-attachments/assets/faf3e02e-cb23-42af-aa59-d52d43cd7ac4" />

La salida de Valgrind confirma que todas las correcciones fueron efectivas:

- **`in use at exit: 0 bytes in 0 blocks`** → no quedó ningún bloque sin liberar.
- **`3 allocs, 3 frees`** → cada `malloc` tiene su `free` correspondiente.
- **`All heap blocks were freed -- no leaks are possible`** → sin fugas de memoria.
- **`ERROR SUMMARY: 0 errors from 0 contexts`** → sin buffer overflows ni use-after-free.

El programa corregido pasa la verificación de Valgrind con cero errores y cero fugas.

### Punto 3: Consecuencias de un use-after-free en términos de seguridad y estabilidad

#### ¿Qué ocurre internamente?

Cuando se llama `free(p)`, el bloque de memoria se devuelve al administrador del heap,
quien puede asignarlo a cualquier otra parte del programa en cualquier momento. Sin embargo,
el puntero `p` sigue apuntando a esa misma dirección. Si se accede a `p` después del `free`,
se está leyendo o escribiendo memoria que ya no le pertenece al programa.

#### Consecuencias en estabilidad

| Escenario | Consecuencia |
|---|---|
| El bloque aún no fue reasignado | La lectura devuelve basura; el programa continúa con datos incorrectos |
| El bloque fue reasignado a otra variable | Se corrompen datos de otra parte del programa, produciendo fallos impredecibles |
| Se escribe sobre memoria liberada | Puede corromper las estructuras internas del heap, causando crashes posteriores |
| El SO detecta el acceso inválido | Segmentation Fault y terminación abrupta del proceso |

El problema más peligroso para la estabilidad es que **el crash no ocurre necesariamente
en el punto del use-after-free**, sino mucho después, cuando la corrupción ya se propagó.
Esto hace que estos bugs sean extremadamente difíciles de diagnosticar sin herramientas
como Valgrind.

#### Consecuencias en seguridad

Un use-after-free es una vulnerabilidad crítica ampliamente explotada. Los vectores de
ataque más comunes son:

- **Heap spraying:** el atacante provoca que el bloque liberado sea reasignado con datos
que él controla. Cuando el programa accede al puntero colgante, ejecuta código malicioso.
- **Escalación de privilegios:** si el bloque liberado pertenecía a una estructura con
permisos o credenciales, el atacante puede sustituir esos valores.
- **Ejecución de código arbitrario:** en entornos sin protecciones modernas, un atacante
puede redirigir el flujo de ejecución del programa hacia shellcode propio.

> Los use-after-free son tan graves que tienen su propia categoría en el catálogo de
> vulnerabilidades internacionales: **CWE-416**. Han sido la causa raíz de
> vulnerabilidades críticas en navegadores, kernels de sistemas operativos y software
> de producción ampliamente usado.

#### Buenas prácticas para prevenirlos

```c
free(p);
p = NULL;  // anular el puntero después de liberar
           // un acceso posterior causará Segfault inmediato y detectable,
           // en lugar de comportamiento indefinido silencioso
```

Anular el puntero tras el `free` no elimina el bug, pero convierte un error silencioso
e impredecible en un fallo inmediato y localizable.

---
# 3) Traducción de direcciones — Base & Bounds

## Actividad: Base & Bounds — Análisis
### Punto 1: Compilar y ejecutar

<img width="1068" height="351" alt="image" src="https://github.com/user-attachments/assets/d5729e4c-0abe-4a12-8ccd-0971eb544d80" />

#### Salida completa del programa:
```text
--- Proceso A (base=32, bounds=64) ---
VA=  0 -> PA= 32
VA= 10 -> PA= 42
VA= 63 -> PA= 95
[EXCEPCION] VA=64 viola bounds=64
[EXCEPCION] VA=100 viola bounds=64
--- Proceso B (base=128, bounds=80) ---
VA=  0 -> PA=128
VA= 10 -> PA=138
VA= 63 -> PA=191
VA= 64 -> PA=192
[EXCEPCION] VA=100 viola bounds=80
```
#### ¿Qué ocurre al acceder a VA=64 y VA=100 en el Proceso A?

El Proceso A tiene `base=32` y `bounds=64`, lo que significa que sus direcciones virtuales
válidas van de `0` a `63` (64 posiciones en total). La traducción funciona así:
```text
PA = base + VA  →  solo si  0 <= VA < bounds
```

| VA | ¿Válido? | Cálculo | Resultado |
|---|---|---|---|
| 0  | Si | 32 + 0  | PA = 32  |
| 10 | Si | 32 + 10 | PA = 42  |
| 63 | Si | 32 + 63 | PA = 95  |
| 64 | No | 64 >= 64 | EXCEPCIÓN |
| 100 | No | 100 >= 64 | EXCEPCIÓN |

- **VA=64** es el primer acceso fuera del espacio válido. Aunque solo excede el límite
por 1, ya viola el bounds y se lanza la excepción.
- **VA=100** está muy por fuera del espacio del proceso, y también es rechazado.

Ambos accesos quedarían en territorio de otro proceso o del SO si no existiera
el mecanismo de protección, lo que representaría una violación de aislamiento de memoria.

### ¿Qué haría el SO real ante esta excepción?

En un sistema operativo real con hardware de protección de memoria (MMU), el proceso
de manejo de esta excepción sería el siguiente:

1. La MMU detecta la violación en hardware antes de que el acceso llegue a la RAM.
2. Se genera una interrupción de protección de memoria, conocida como *segmentation fault*
o *protection fault*, según la arquitectura.
3. El hardware transfiere el control al SO, guardando el estado del proceso infractor.
4. El SO identifica la causa: la dirección virtual solicitada está fuera del rango
`[base, base + bounds)` del proceso.
5. El SO envía una señal al proceso infractor: en Linux/Unix envía `SIGSEGV`
(*Segmentation Violation*), que por defecto termina el proceso y puede generar un
volcado de memoria (*core dump*) para análisis posterior.
6. El proceso es terminado de forma forzada, sin afectar a otros procesos ni al SO,
gracias al aislamiento que provee precisamente el mecanismo de base y bounds.

> Este mecanismo es la base del aislamiento de procesos: cada proceso solo puede
> acceder a su propio espacio de direcciones. Cualquier intento de salirse de ese espacio
> es interceptado por el hardware y manejado por el SO, garantizando que un proceso
> defectuoso o malicioso no pueda corromper la memoria de otros procesos.

### Punto 2: Agregar Proceso C (base=0, bounds=32)
 ```c
int main() {
    ...

    Registro proC = {0, 32}; /* base=0, bounds=32 */
    ...

    printf("--- Proceso C (base=%d, bounds=%d) ---\n",
        proC.base, proC.bounds);
    for (int i = 0; i < n; i++) {
        int pa = traducir(proC, vas[i]);
        if (pa != -1)
        printf(" VA=%3d -> PA=%3d\n", vas[i], pa);
    }

    ...
}
```
#### Traduciendo las mismas direcciones:
<img width="453" height="142" alt="image" src="https://github.com/user-attachments/assets/5216a50e-407d-42cc-a739-b8692000041d" />

#### ¿Puede el Proceso A acceder a las direcciones del Proceso C directamente?

No. Aunque las direcciones físicas del Proceso C van de `PA=0` a `PA=31`, el Proceso A
solo puede generar direcciones virtuales en el rango `[0, 63)`, que su MMU traduce
siempre sumando su base: `PA = 32 + VA`. Es imposible que el Proceso A produzca
una dirección física menor a 32, por lo que nunca puede tocar la memoria del Proceso C.

Cada proceso vive en su propio espacio virtual. El mecanismo de base y bounds garantiza
que la traducción VA → PA siempre quede confinada al segmento físico asignado a ese
proceso, haciendo que el acceso directo entre procesos sea arquitecturalmente imposible.

### Punto 3: Limitación princiapal del esquema base & bounds

El esquema base & bounds asigna a cada proceso un único bloque contiguo de memoria
física. Esta restricción genera dos problemas fundamentales:

**1. Fragmentación externa:** a medida que los procesos se crean y terminan, el espacio
libre queda dividido en huecos dispersos. Puede haber suficiente memoria libre en total,
pero ningún bloque contiguo lo suficientemente grande para un proceso nuevo.

**2. Ineficiencia interna:** el bloque debe reservarse para el tamaño máximo que el proceso
podría necesitar. La memoria entre el stack y el heap, que aún no ha sido usada, queda
reservada pero desperdiciada.

```text
Memoria física:
┌──────────┬───────────────┬──────────┬───────────────┐
│ Proceso A│  DESPERDICIO  │ Proceso B│  HUECO LIBRE  │
│ (usado)  │  (reservado)  │ (usado)  │  (inutilizable│
└──────────┴───────────────┴──────────┴───────────────┘
```
La segmentación surge para resolver esto: en lugar de un solo registro base & bounds,
cada proceso tiene múltiples segmentos (código, heap, stack), cada uno con su propio
par base & bounds. Así cada segmento ocupa solo la memoria que realmente necesita,
reduciendo el desperdicio y aprovechando mejor los huecos disponibles.
---
# 4 Paginación 
## 4.1 Traducción manual con tabla de segmentos
### Punto 1: Cálculo paso a paso para cada VA
#### Reglas de traducción

- **Segmento positivo:** válido si `0 <= offset < tamaño`. Luego `PA = base + offset`.
- **Segmento negativo (stack):** válido si `offset >= (offset(max) - tamaño)`. `Offset(max) = 2^(# bits del offset)`
  Luego `PA = base - (offset(max) - offset)`.

#### VA = 0x03A0 — Segmento Code (selector 00)
<img width="975" height="208" alt="image" src="https://github.com/user-attachments/assets/961b0188-7d4c-4f29-aacc-01009153014b" />

#### VA = 0x1800 — Segmento Heap (selector 01)
<img width="925" height="212" alt="image" src="https://github.com/user-attachments/assets/aa6b9698-d1bc-4d7c-9593-66fd3b3faec4" />

#### VA = 0x3C00 — Segmento Stack (selector 11)
<img width="1057" height="720" alt="image" src="https://github.com/user-attachments/assets/99ad487d-1349-42b2-9f1a-39b2197d9f0e" />

#### VA = 0x0C00 — Segmento Code (selector 00)
<img width="850" height="171" alt="image" src="https://github.com/user-attachments/assets/704d814a-c44d-49b4-af52-94fb80f29d1d" />

#### VA = 0x2200 — Selector inválido (selector 10)
<img width="713" height="167" alt="image" src="https://github.com/user-attachments/assets/bf81c684-018c-49d2-ac2e-f85aa21785b8" />

#### Tabla completa resuelta
<img width="677" height="277" alt="image" src="https://github.com/user-attachments/assets/a9d8ab99-11e6-4f51-9eb4-b1067cad5a2a" />

---
| VA (hex) | Selector | Offset | Segmento | PA o Excepción |
|---|---|---|---|---|
| 0x03A0 | 00 | 0x3A0 | Code  | PA = **0x43A0** |
| 0x1800 | 01 | 0x800 | Heap  | PA = **0x6800** |
| 0x3C00 | 11 | 0xC00 | Stack | PA = **0x2400** |
| 0x0C00 | 00 | 0xC00 | Code  | **EXCEPCIÓN** (offset 0xC00 (3k) >= tamaño 0x800 (2k)) |
| 0x2200 | 10 | —     | ???   | **EXCEPCIÓN** (selector 10 no definido) |

### Punto 2: Caracteristicas del Stack

#### ¿Por qué el stack crece en dirección negativa?

Es una convención histórica que viene del diseño original de los procesadores x86. Cuando
un programa llama a una función, el stack necesita guardar datos (parámetros, dirección de
retorno, variables locales). Para no colisionar con el heap, que crece hacia arriba, se
decidió que el stack creciera en dirección contraria, hacia abajo.

```text
Memoria virtual de un proceso:
0x0000  ┌─────────────┐
│    Code     │
├─────────────┤
│    Heap     │  crece hacia ↓
│      ↓      │
│             │  (espacio libre)
│      ↑      │
│    Stack    │  crece hacia ↑ (direcciones decrecientes)
0xFFFF  └─────────────┘
```
Esto permite que heap y stack compartan el espacio libre del medio y crezcan
uno hacia el otro sin necesidad de reservar tamaños fijos para cada uno.

#### Ajuste especial en la fórmula del PA

Para segmentos que crecen positivo la fórmula es directa:  

```text
PA = base + offset
```
Pero el stack crece negativo, por lo que la `base` apunta al tope superior del segmento,
no al inicio. El offset no se puede sumar directamente porque eso llevaría la dirección
hacia arriba, fuera del segmento. Se necesita convertirlo en un desplazamiento negativo:

<img width="720" height="167" alt="Captura de pantalla 2026-05-06 205313" src="https://github.com/user-attachments/assets/a66f6bd4-b10d-48e2-a1a3-f958e488ba0c" />

Donde `Offset(max) = 2^(# bits del offset)`

### Punto 3: Ventaja de la segmentación frente a Base & Bounds

Con base & bounds, cada proceso recibe un único bloque contiguo de memoria física que
debe ser lo suficientemente grande para contener todo: código, heap y stack. El espacio
entre el heap y el stack queda reservado pero vacío, desperdiciando memoria física.

La segmentación elimina esto dividiendo el espacio del proceso en segmentos independientes,
cada uno con su propio par base & bounds

Las ventajas concretas son:

- Cada segmento ocupa solo lo que necesita. No hay memoria reservada entre heap y stack.
- Los huecos entre segmentos quedan libres y pueden ser asignados a otros procesos.
- El heap y el stack pueden crecer de forma independiente sin afectarse mutuamente,
  siempre que haya espacio físico disponible.
- Múltiples procesos comparten mejor la RAM, ya que los segmentos pequeños encajan
  más fácilmente en los huecos disponibles.

> La segmentación no elimina la fragmentación externa (los huecos entre segmentos siguen
> existiendo), pero sí elimina casi por completo la fragmentación interna que era
> inevitable con base & bounds.

### Punto 4: Fragmentación externa

#### ¿Qué es la fragmentación externa?

Es el fenómeno donde hay suficiente memoria libre en total para satisfacer una solicitud,
pero esa memoria está dividida en huecos pequeños y dispersos, ninguno lo suficientemente
grande de forma **contigua**. El espacio libre existe, pero no es utilizable.

#### ¿Por qué surge con segmentación?

Porque la segmentación sigue requiriendo que cada segmento ocupe un bloque contiguo
de memoria física. A medida que los procesos se crean, crecen y terminan, dejan huecos
de distintos tamaños repartidos por la RAM. Con el tiempo, esos huecos se vuelven
demasiado pequeños para alojar nuevos segmentos.

#### Diagrama: evolución de la fragmentación externa

**Estado inicial — tres procesos en memoria:**
```
┌─────────────┐ 0x0000
│   Proceso A │ 20KB
├─────────────┤ 0x5000
│   Proceso B │ 30KB
├─────────────┤ 0xC800
│   Proceso C │ 15KB
├─────────────┤ 0x1000
│    LIBRE    │ 35KB
└─────────────┘ 0x1FFFF
```

**Proceso A y Proceso C terminan — dejan huecos:**
```
┌─────────────┐ 0x0000
│    LIBRE    │ 20KB  ← hueco 1
├─────────────┤ 0x5000
│   Proceso B │ 30KB
├─────────────┤ 0xC800
│    LIBRE    │ 15KB  ← hueco 2
├─────────────┤ 0x10000
│    LIBRE    │ 35KB  ← hueco 3
└─────────────┘ 0x1FFFF
```

**Nuevo proceso D necesita 60KB contiguos — FALLA:**
```
┌─────────────┐
│    LIBRE    │ 20KB  ┐
├─────────────┤       │
│   Proceso B │ 30KB  │  Libre total = 70KB 
├─────────────┤       │  Pero ningún bloque
│    LIBRE    │ 15KB  │  contiguo >= 60KB   
├─────────────┤       │
│    LIBRE    │ 35KB  ┘
└─────────────┘

→ Proceso D no puede cargarse aunque haya memoria suficiente en total.
  Esto es fragmentación externa.
```

#### Solución que adoptaron los SO modernos

La fragmentación externa es el problema que motivó el desarrollo de la paginación:
dividir la memoria en bloques de tamaño fijo (páginas) elimina los huecos de tamaño
variable, ya que cualquier página libre puede usarse para cualquier proceso,
independientemente de dónde esté ubicada físicamente.

---

# 5) Paginación
