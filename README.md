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
## Actividad 5.1: Cálculo de la tabla de páginas
### Punto 1: Bits VPN y Bits offset:

**Datos del sistema:**
- Espacio virtual: 32 bits
- Tamaño de página: 4KB = 2¹² bytes

<img width="1493" height="423" alt="image" src="https://github.com/user-attachments/assets/d10687ec-4a2c-4bd8-b30d-bcab05ec115e" />

**Estructura de la dirección virtual:**

```
┌──────────────────────────┬─────────────────┐
│     VPN (20 bits)        │  Offset (12 bits)│
│   bits [31 ... 12]       │  bits [11 ... 0] │
└──────────────────────────┴─────────────────┘
 ←────── 32 bits en total ──────────────────→
```
### Punto 2. Entradas tabla de pagina

#### ¿Cuántas entradas tiene la tabla de páginas de un proceso?

El número de entradas de la tabla de páginas equivale al número total de páginas
virtuales posibles, que está determinado por el VPN de 20 bits:

```
Número de entradas = 2^(bits de VPN) = 2^20 = 1.048.576 entradas
```

Cada entrada corresponde a una página virtual distinta que el proceso podría tener
mapeada. Con 20 bits de VPN hay exactamente 2²⁰ páginas virtuales posibles.

### Punto 3: Espacio de tabla de pagina

**¿Cuánto ocupa la tabla de páginas completa en memoria?**

Cada entrada (PTE) ocupa 4 bytes según los datos del sistema:

```
Tamaño total = número de entradas × tamaño de PTE
             = 2^20 × 4 bytes
             = 4.194.304 bytes
             = 4 MB
```

Esto significa que solo la tabla de páginas de un proceso ocupa 4MB de memoria

**¿Es razonable?**

No. 4MB por proceso es excesivo por varias razones:

- En un sistema con 100 procesos activos simultáneos, solo las tablas de páginas
  consumirían `100 × 4MB = 400MB` de RAM, sin contar el código ni los datos de
  los procesos.
- La mayoría de los procesos no usan ni remotamente las 2²⁰ páginas virtuales
  disponibles, por lo que la mayor parte de la tabla contiene entradas inválidas
  que desperdician memoria.
- La tabla completa debe residir en memoria física para que la MMU pueda
  consultarla en cada acceso.

Por estas razones los SO modernos utilizan tablas de páginas multinivel, que
solo reservan memoria para las partes de la tabla que realmente están en uso,
reduciendo drásticamente el consumo en la mayoría de los casos.

**Resumen:**

| Parámetro | Valor |
|---|---|
| Bits de VPN | 20 bits |
| Número de entradas | 2²⁰ = 1.048.576 |
| Tamaño por entrada (PTE) | 4 bytes |
| Tamaño total de la tabla | 4 MB |

### Punto 4: Bits PFN

<img width="1476" height="335" alt="image" src="https://github.com/user-attachments/assets/505a8063-ff3c-4263-9046-a2d57e6a6ef4" />

**Estructura de la PTE (4 bytes = 32 bits):**

```
┌──────────────────────────────────────┬────────────────┐
│        Bits de control (24 bits)     │  PFN (8 bits)  │
│              bits [31..8]            │  bits [7..0]   │
└──────────────────────────────────────┴────────────────┘
 ←───────────────── 32 bits (4 bytes) ─────────────────→
```

Con solo 8 bits para el PFN y 32 bits totales en la PTE, quedan **24 bits disponibles**
para bits de control. En la práctica los SO no usan todos; la mayoría quedan reservados
para uso futuro.

---

### Bits de control y su función

| Bit | Nombre | Función |
|---|---|---|
| **V** | Valid / Present | Indica si la página está cargada en RAM. Si es 0, cualquier acceso genera un **page fault** y el SO debe cargar la página desde disco. |
| **R/W** | Read/Write | Define los permisos de acceso. Si es 0 la página es solo lectura; intentar escribir genera una excepción de protección. |
| **U/S** | User/Supervisor | Indica si la página es accesible desde modo usuario o solo desde modo kernel. Protege las páginas del SO frente a los procesos. |
| **D** | Dirty | Se activa cuando la página ha sido **modificada** desde que se cargó. El SO lo usa para saber si debe escribir la página a disco antes de desalojarla. |
| **A** | Accessed | Se activa cuando la página ha sido leída o escrita recientemente. El SO lo usa para los algoritmos de reemplazo de páginas (ej: LRU aproximado). |

> Estos bits de control son la razón por la que el tamaño de la PTE es de 4 bytes
> y no simplemente 1 byte para el PFN. La información de protección y estado que
> almacenan es esencial para que el SO gestione correctamente la memoria virtual.

## Actividad 5.3: Simulador — Analisis
### Punto 1: Compilar y ejecutar
<img width="762" height="306" alt="image" src="https://github.com/user-attachments/assets/84a8eaa8-0e4b-45fa-9858-668463596bfc" />

### Punto 2: ¿Qué ocurre con VA=0x10 y VA=0xA3?
**VA = 0x10 → PAGE FAULT**

```
VA = 0x10 = 0001 0000
VPN   = 1
Offset  = 0

page_table[1] = -1  →  página no presente  →  PAGE FAULT
```

La página virtual 1 no tiene marco físico asignado. No está en RAM.

**VA = 0xA3 → traducción exitosa**

```
VA = 0xA3 = 1010 0011
VPN    = 10
Offset = 3

page_table[10] = 4  →  PFN = 4
PA =  0x43
```

La página virtual 10 sí tiene marco físico asignado (PFN=4), por lo que la traducción
se completa normalmente con PA=0x43.

---

### ¿Qué haría el SO real ante un page fault?

Cuando ocurre un page fault el hardware detecta que el bit **Valid=0** en la PTE y
transfiere el control al SO mediante una interrupción. El SO sigue estos pasos:

**1. Verificar si el acceso es legítimo:**
si la VA no pertenece al espacio válido del proceso, el SO termina el proceso con
una señal `SIGSEGV`. Si sí es válida, continúa.

**2. Encontrar un marco físico libre:**
el SO busca un marco disponible en RAM. Si no hay ninguno libre, aplica un
**algoritmo de reemplazo de páginas** (LRU, Clock, etc.) para desalojar una página
existente y liberar su marco.

**3. Escribir la página desalojada a disco (si es necesario):**
si el bit **Dirty=1** de la página desalojada está activo, el SO escribe su contenido
al área de swap en disco antes de liberar el marco.

**4. Cargar la página faltante desde disco:**
el SO carga la página solicitada desde el archivo de swap o desde el ejecutable
al marco físico recién liberado.

**5. Actualizar la tabla de páginas:**
se actualiza la PTE de la página faltante con el nuevo PFN y se activa el bit
Valid=1.

**6. Reanudar el proceso:**
el SO devuelve el control al proceso, que reintenta la instrucción que causó el
page fault, esta vez con éxito.

```
Proceso accede a VA=0x10
        │
        ▼
  MMU consulta PTE → Valid=0
        │
        ▼
  Interrupción → SO toma control
        │
        ▼
  ¿Acceso válido? ── No ──→ SIGSEGV → proceso terminado
        │
       Sí
        │
        ▼
  Buscar marco libre en RAM
        │
        ▼
  Cargar página desde disco → marco físico
        │
        ▼
  Actualizar PTE (PFN + Valid=1)
        │
        ▼
  Reanudar proceso → reintenta acceso → éxito
```
### Punto 3: ¿Cuántos accesos a memoria física requiere un Load con tabla de páginas de un nivel?

Una instrucción `load` con paginación de un solo nivel requiere 2 accesos a memoria física:

```
Instrucción: LOAD R1, VA

Acceso 1: consultar la tabla de páginas en RAM
          VA → VPN → índice en page_table → obtener PFN

Acceso 2: acceder al dato real en RAM
          PA = (PFN << PAGE_BITS) | offset → leer el dato
```

Sin paginación, el mismo `load` requeriría solo 1 acceso. La tabla de páginas
duplica el costo de cada operación de memoria.

**¿Por qué es costoso?**

En un procesador moderno que ejecuta cientos de millones de instrucciones por segundo,
cada acceso a RAM toma entre 50 y 100 nanosegundos. Duplicar ese costo en cada
instrucción que accede a memoria representa una degradación de rendimiento inaceptable.
El problema se agrava con tablas multinivel:

| Niveles de tabla | Accesos a memoria por Load |
|---|---|
| Sin paginación | 1 |
| 1 nivel | 2 |
| 2 niveles | 3 |
| 3 niveles | 4 |

---

### Solución de hardware: TLB (Translation Lookaside Buffer)

La solución es una caché de traducciones integrada directamente en la MMU llamada
TLB (Translation Lookaside Buffer). Almacena las traducciones VPN → PFN usadas
recientemente para evitar consultar la tabla de páginas en RAM.

**Funcionamiento:**

```
Proceso accede a VA
        │
        ▼
  MMU busca VPN en TLB
        │
   ┌────┴────┐
   │         │
TLB Hit   TLB Miss
   │         │
   ▼         ▼
PFN directo  Consulta RAM    ← 1 acceso extra
desde TLB    (page table)
   │         │
   └────┬────┘
        ▼
  Acceder al dato en RAM    ← 1 acceso
```

- **TLB Hit:** solo 1 acceso a RAM (el dato). La traducción sale de la caché.
- **TLB Miss:** 2 accesos a RAM (tabla de páginas + dato). La traducción nueva
  se guarda en la TLB para futuros accesos.

**¿Por qué funciona bien en la práctica?**

Los programas exhiben localidad de referencia: tienden a acceder repetidamente
a las mismas páginas en períodos cortos de tiempo. Una TLB de apenas 64 a 1024
entradas logra tasas de acierto (*hit rate*) superiores al 99%, haciendo que el
costo promedio de traducción sea casi igual al de un sistema sin paginación.

### Punto 4: ¿Qué ventaja tiene la paginación sobre la segmentación en cuanto a fragmentación?

La ventaja principal es que la paginación elimina la fragmentación externa a costa
de introducir una fragmentación interna mínima y controlada.

**¿Por qué la segmentación sufre fragmentación externa?**

Los segmentos tienen tamaño variable. A medida que los procesos entran y salen de
memoria, quedan huecos de distintos tamaños que no siempre pueden ser aprovechados
por nuevos segmentos.

```
RAM con segmentación (tamaño variable):

┌─────────────┐
│  Segmento A │ 18KB
├─────────────┤
│    LIBRE    │ 5KB   ← demasiado pequeño para un segmento de 8KB
├─────────────┤
│  Segmento B │ 30KB
├─────────────┤
│    LIBRE    │ 6KB   ← demasiado pequeño para un segmento de 8KB
├─────────────┤
│  Segmento C │ 20KB
└─────────────┘
Libre total: 11KB, pero ningún hueco admite un segmento de 8KB 
```

**¿Por qué la paginación elimina la fragmentación externa?**

Todos los marcos físicos tienen el **mismo tamaño fijo**. Cualquier marco libre puede
alojar cualquier página de cualquier proceso, sin importar dónde esté ubicado en RAM.
No existen huecos inutilizables.

```
RAM con paginación (marcos de tamaño fijo):

┌─────────────┐
│  Marco  0   │ 16B  → Proceso A, página 2
├─────────────┤
│  Marco  1   │ 16B  → LIBRE   puede alojar cualquier página
├─────────────┤
│  Marco  2   │ 16B  → Proceso B, página 0
├─────────────┤
│  Marco  3   │ 16B  → LIBRE   puede alojar cualquier página
├─────────────┤
│  Marco  4   │ 16B  → Proceso A, página 0
└─────────────┘
Cualquier marco libre es aprovechable al 100% 
```

**¿Qué es la fragmentación interna que introduce la paginación?**

Si un proceso no usa completamente la última página asignada, el espacio sobrante
dentro de esa página se desperdicia. Sin embargo este desperdicio es acotado:

```
Proceso necesita: 4KB + 1 byte
Páginas asignadas: 2 páginas = 8KB
Desperdicio: 8KB - (4KB + 1 byte) = 4095 bytes por proceso ← peor caso 
```

Es un costo pequeño y predecible, muy inferior al desperdicio impredecible que
genera la fragmentación externa de la segmentación.

---

**Comparación directa:**

| Fenómeno | Segmentación | Paginación |
|---|---|---|
| Fragmentación externa |  Sí, severa e impredecible |  No existe |
| Fragmentación interna |  No existe |  Sí, pero mínima y acotada |
| Aprovechamiento de huecos | Parcial (depende del tamaño) | Total (cualquier marco sirve) |

> La eliminación de la fragmentación externa es la razón principal por la que los
> SO modernos adoptaron la paginación como mecanismo base de gestión de memoria,
> combinándola con segmentación en algunos casos (ej: x86 en modo protegido) para
> aprovechar las ventajas de ambos esquemas.

---

# 6: Gestión de espacio libre
## Actividad 6.1: Simulación de estrategias de asignación
### Punto 1: First Fit

**Regla:** se asigna el primer bloque de la lista libre que sea suficientemente grande.

**Lista libre inicial:**

| Dirección | Tamaño |
|---|---|
| 0x0100 | 100 bytes |
| 0x0200 | 500 bytes |
| 0x0400 | 200 bytes |
| 0x0500 | 300 bytes |
| 0x0700 | 600 bytes |

---

**malloc(212):**
```
0x0100: 100 < 212 NO
0x0200: 500 >= 212 SI → asigna en 0x0200, remainder = 500 - 212 = 288 bytes
```

**malloc(417):**
```
0x0100: 100 < 417 NO
0x0200: 288 < 417 NO
0x0400: 200 < 417 NO
0x0500: 300 < 417 NO
0x0700: 600 >= 417 SI → asigna en 0x0700, remainder = 600 - 417 = 183 bytes
```

**malloc(98):**
```
0x0100: 100 >= 98 SI → asigna en 0x0100, remainder = 100 - 98 = 2 bytes
```

**malloc(426):**
```
0x0100:   2 < 426 NO
0x0200: 288 < 426 NO
0x0400: 200 < 426 NO
0x0500: 300 < 426 NO
0x0700: 183 < 426 NO
→ FALLA: no existe bloque suficientemente grande
```

---

**Lista libre resultante tras las 4 solicitudes:**

| Dirección | Tamaño | Observación |
|---|---|---|
| 0x0100 | 2 bytes | remainder de malloc(98) |
| 0x02D4 | 288 bytes | remainder de malloc(212) |
| 0x0400 | 200 bytes | sin cambios |
| 0x0500 | 300 bytes | sin cambios |
| 0x07B1 | 183 bytes | remainder de malloc(417) |

> **malloc(426) falla** porque ningún bloque libre disponible es suficientemente
> grande, a pesar de que la memoria libre total es 2+288+200+300+183 = **973 bytes**.
> Esto ilustra cómo First Fit puede generar fragmentación externa que impide
> satisfacer solicitudes aunque haya memoria libre suficiente en total.

### Punto 2: Best Fit

**Regla:** se asigna el bloque más pequeño que sea suficientemente grande,
minimizando el desperdicio en cada asignación.

---

**malloc(212):**
```
0x0100: 100 < 212 NO
0x0200: 500 >= 212 SI desperdicio = 288
0x0400: 200 < 212 NO
0x0500: 300 >= 212 SI desperdicio =  88 ← mejor ajuste
0x0700: 600 >= 212 SI desperdicio = 388

→ asigna en 0x0500, remainder = 88 bytes
```

**malloc(417):**
```
0x0100: 100 < 417 NO
0x0200: 500 >= 417 SI desperdicio =  83 ← mejor ajuste
0x0400: 200 < 417 NO
0x0500:  88 < 417 NO
0x0700: 600 >= 417 SI desperdicio = 183

→ asigna en 0x0200, remainder = 83 bytes
```

**malloc(98):**
```
0x0100: 100 >= 98 SI desperdicio =   2 ← mejor ajuste
0x0200:  83 < 98  NO
0x0400: 200 >= 98 SI desperdicio = 102
0x0500:  88 < 98  NO
0x0700: 600 >= 98 SI desperdicio = 502

→ asigna en 0x0100, remainder = 2 bytes
```

**malloc(426):**
```
0x0100:   2 < 426 NO
0x0200:  83 < 426 NO
0x0400: 200 < 426 NO
0x0500:  88 < 426 NO
0x0700: 600 >= 426 SI desperdicio = 174 ← único candidato

→ asigna en 0x0700, remainder = 174 bytes SI
```

---

**Lista libre resultante tras las 4 solicitudes:**

| Dirección | Tamaño | Observación |
|---|---|---|
| 0x0100 | 2 bytes | remainder de malloc(98) |
| 0x02A1 | 83 bytes | remainder de malloc(417) |
| 0x0400 | 200 bytes | sin cambios |
| 0x0512 | 88 bytes | remainder de malloc(212) |
| 0x07B2 | 174 bytes | remainder de malloc(426) |

---

### ¿Cambia el resultado frente a First Fit?

Sí, y de forma significativa:

| Solicitud | First Fit | Best Fit |
|---|---|---|
| malloc(212) | 0x0200 (500B) | 0x0500 (300B) |
| malloc(417) | 0x0700 (600B) | 0x0200 (500B) |
| malloc(98)  | 0x0100 (100B) | 0x0100 (100B) |
| malloc(426) |  FALLA       |  0x0700 (600B) |

Best Fit logra satisfacer malloc(426) donde First Fit fallaba, porque al asignar
malloc(212) en el bloque de 300 bytes (en lugar del de 500), conserva el bloque
de 600 bytes intacto y disponible para la solicitud más grande.

Sin embargo, Best Fit no siempre es superior: al intentar minimizar el desperdicio
por asignación, tiende a generar muchos remanentes muy pequeños (como los 83
y 88 bytes del ejemplo) que son difíciles de reutilizar, contribuyendo a la
fragmentación externa a largo plazo.

### Punto 3: ¿Cuál estrategia genera más fragmentación externa?

Comparando los remanentes que dejó cada estrategia:

| Dirección | First Fit | Best Fit |
|---|---|---|
| 0x0100 | 2 bytes | 2 bytes |
| 0x0200 | 288 bytes | 83 bytes |
| 0x0400 | 200 bytes | 200 bytes |
| 0x0500 | 300 bytes | 88 bytes |
| 0x0700 | 183 bytes | 174 bytes |
| **Total libre** | **973 bytes** | **547 bytes** |
| **Bloques útiles (>= 212B)** | 0x0500: 300B | 0x0400: 200B |
| **malloc(426) satisfecho** |  No |  Sí |

**¿Cuál genera más fragmentación externa?**

**First Fit** genera más fragmentación externa en este caso. Aunque deja más memoria
libre en total (973 bytes vs 547 bytes), esa memoria está distribuida en bloques
que no son suficientemente grandes para satisfacer malloc(426). Tener mucha memoria
libre pero inutilizable es precisamente la definición de fragmentación externa.

**¿Cuál la minimiza?**

**Best Fit** la minimiza en este caso concreto. Al elegir siempre el bloque con
menor desperdicio, preservó el bloque más grande (0x0700: 600B) disponible para
la solicitud más exigente, logrando satisfacer las 4 solicitudes.

Sin embargo, esta conclusión no es universal:

| Estrategia | Ventaja | Desventaja |
|---|---|---|
| **First Fit** | Rápido, preserva bloques grandes al final | Fragmenta el inicio de la lista |
| **Best Fit** | Minimiza desperdicio por asignación | Genera remanentes muy pequeños e inútiles a largo plazo |
| **Worst Fit** | Deja remanentes grandes y reutilizables | Destruye los bloques grandes rápidamente |
| **Next Fit** | Distribuye la fragmentación uniformemente | Similar a First Fit en fragmentación |

> En general, ninguna estrategia es óptima para todos los casos. La elección
> depende del patrón de solicitudes del sistema. En la práctica, **First Fit**
> suele ser preferido por su velocidad y comportamiento aceptable en la mayoría
> de escenarios reales.

### Punto 4: ¿Qué es el Coalescing?

El coalescing (o coalescencia) es el proceso de fusionar bloques libres adyacentes
en memoria en un único bloque más grande cuando se libera memoria. Lo realiza el gestor
del heap automáticamente al ejecutar `free()`, revisando si los bloques vecinos también
están libres para combinarlos.

Sin coalescing, bloques libres contiguos permanecen separados en la lista libre y no
pueden satisfacer solicitudes que cabrían en su espacio combinado.


#### Caso ilustrado: malloc(250) falla sin coalescing

**Situación inicial: tres bloques fueron liberados en posiciones contiguas**

```
Dirección   Tamaño    Estado
┌─────────────────────────────┐
│ 0x0100    100 bytes  LIBRE  │
├─────────────────────────────┤
│ 0x0164    80 bytes   LIBRE  │
├─────────────────────────────┤
│ 0x01B4    120 bytes  LIBRE  │
├─────────────────────────────┤
│ 0x0234    400 bytes  EN USO │
└─────────────────────────────┘
Memoria libre total: 100 + 80 + 120 = 300 bytes
```

**Sin coalescing → malloc(250) FALLA:**

```
Lista libre:
  [0x0100: 100B] → [0x0164: 80B] → [0x01B4: 120B]

malloc(250):
  0x0100: 100 < 250 NO
  0x0164:  80 < 250 NO
  0x01B4: 120 < 250 NO
  → FALLA: ningún bloque individual alcanza 250 bytes
    aunque hay 300 bytes libres en total 
```

**Con coalescing → malloc(250) ÉXITO:**

```
Al liberar los bloques, el gestor detecta vecinos libres y los fusiona:

0x0100 (100B) + 0x0164 (80B) + 0x01B4 (120B)
─────────────────────────────────────────────
        0x0100: 300 bytes LIBRE  

Lista libre:
  [0x0100: 300B]

malloc(250):
  0x0100: 300 >= 250 SI → asigna en 0x0100, remainder = 50 bytes 
```

**Visualmente:**

```
Sin coalescing:                   Con coalescing:

┌─────────────────┐               ┌─────────────────┐
│ 0x0100  100B    │ LIBRE  ┐      │                 │
├─────────────────┤        │      │ 0x0100  300B    │ LIBRE
│ 0x0164   80B    │ LIBRE  ├─────▶│                 │
├─────────────────┤        │      │                 │
│ 0x01B4  120B    │ LIBRE  ┘      ├─────────────────┤
├─────────────────┤               │ 0x0234  400B    │ EN USO
│ 0x0234  400B    │ EN USO        └─────────────────┘
└─────────────────┘
malloc(250)                     malloc(250) 
```

> El coalescing es una técnica fundamental en todo gestor de heap moderno.
> Su ausencia convierte la fragmentación externa en un problema irreversible:
> la memoria se divide en fragmentos cada vez más pequeños que nunca pueden
> volver a combinarse, degradando el rendimiento del sistema con el tiempo.

### Punto 5: ¿Qué es la fragmentación interna?

La fragmentación interna ocurre cuando se asigna a un proceso más memoria de la
que realmente necesita, y el espacio sobrante dentro del bloque asignado queda
desperdiciado e inutilizable por cualquier otro proceso.

A diferencia de la fragmentación externa (huecos entre bloques), la fragmentación
interna es desperdicio dentro de un bloque ya asignado:

```
Bloque asignado: 256 bytes
Dato almacenado: 200 bytes
                 ┌──────────────────────────────────────┐
                 │▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓░░░░░░░░░░░░░░░░░░░│
                 │◄─── 200B usado ──►◄─── 56B perdido ──►
                 └──────────────────────────────────────┘
                 El proceso "dueño" del bloque no usa los 56B,
                 pero ningún otro proceso puede usarlos tampoco.
```

---

#### ¿Qué es un Slab Allocator?

El slab allocator es un gestor de memoria usado principalmente en kernels de SO
(Linux lo usa desde 1994). En lugar de asignar memoria de tamaño arbitrario, pre-divide
la memoria en slabs: colecciones de bloques de tamaño fijo diseñados para objetos
específicos del kernel (inodos, descriptores de proceso, etc.).

```
Slab de inodos (cada objeto = 256 bytes):
┌────────┬────────┬────────┬────────┬────────┐
│ inodo  │ inodo  │ inodo  │  FREE  │  FREE  │
│ 256B   │ 256B   │ 256B   │ 256B   │ 256B   │
└────────┴────────┴────────┴────────┴────────┘

Slab de PCBs (cada objeto = 512 bytes):
┌────────┬────────┬────────┬────────┐
│  PCB   │  PCB   │  FREE  │  FREE  │
│ 512B   │ 512B   │ 512B   │ 512B   │
└────────┴────────┴────────┴────────┘
```

---

#### ¿Cuándo aparece fragmentación interna en un Slab Allocator?

El slab allocator casi elimina la fragmentación interna para los objetos que gestiona,
pero aparece en dos situaciones típicas:

**1. El objeto no llena completamente su slot:**

Si el slab fue diseñado para objetos de 256 bytes pero el objeto real ocupa 200 bytes,
los 56 bytes restantes de cada slot se desperdician:

```
Slot del slab: 256 bytes fijos
               ┌─────────────────────┬───────────┐
               │   objeto: 200B      │  56B lost │
               └─────────────────────┴───────────┘
                                      ↑
                              fragmentación interna
Con 1000 objetos: 56 × 1000 = 56.000 bytes desperdiciados
```

**2. Alineación de memoria:**

El slab allocator alinea los objetos a fronteras de memoria (4, 8 o 16 bytes) para
que la CPU pueda accederlos eficientemente. Si un objeto tiene un tamaño que no es
múltiplo de la alineación requerida, se añaden bytes de padding:

```
Objeto real:    52 bytes
Alineación:      8 bytes
Slot asignado:  56 bytes  (próximo múltiplo de 8)
Padding:         4 bytes  ← fragmentación interna por alineación

┌──────────────────────────┬────────┐
│      objeto: 52B         │ pad 4B │
└──────────────────────────┴────────┘
```

---

#### Comparación: fragmentación interna vs externa

| Característica | Fragmentación Interna | Fragmentación Externa |
|---|---|---|
| Ubicación | Dentro del bloque asignado | Entre bloques libres |
| Causa | Tamaño fijo mayor al necesario | Bloques libres dispersos |
| Afecta a | El proceso asignado | Nuevas solicitudes |
| Solución | Tamaños de slot más ajustados | Coalescing, compactación |
| Presente en | Paginación, slab allocator | Segmentación, first/best fit |

> El slab allocator acepta una pequeña fragmentación interna por alineación como
> un compromiso razonable a cambio de eliminar casi por completo la fragmentación
> externa y acelerar drásticamente la asignación de objetos frecuentes del kernel.

## Actividad 6.2: Fragmentación
<img width="1113" height="392" alt="image" src="https://github.com/user-attachments/assets/bd6de000-7085-44c4-a8b7-718126802c1f" />

## Actividad 6.3: Fragmentacióon en glibc — Análisis
### Punto 1: ¿Son consecutivas las direcciones? ¿Qué patrón de separación se observa?

**Direcciones asignadas:**

| Índice | Tamaño | Dirección | Separación con el siguiente |
|---|---|---|---|
| 0 | 16B   | 0x5577476812a0 | 0x430 (1072B) |
| 1 | 32B   | 0x5577476816d0 | 0x030 (48B)   |
| 2 | 64B   | 0x557747681700 | 0x050 (80B)   |
| 3 | 128B  | 0x557747681750 | 0x090 (144B)  |
| 4 | 256B  | 0x5577476817e0 | 0x110 (272B)  |
| 5 | 512B  | 0x5577476818f0 | 0x210 (528B)  |
| 6 | 1024B | 0x557747681b00 | 0x410 (1040B) |
| 7 | 512B  | 0x557747681f10 | 0x210 (528B)  |
| 8 | 256B  | 0x557747682120 | 0x110 (272B)  |
| 9 | 128B  | 0x557747682230 | —             |

**¿Son consecutivas?**

No exactamente. Los bloques están ordenados secuencialmente en memoria (cada dirección
es mayor que la anterior), pero no son estrictamente consecutivas: entre cada bloque
hay una separación mayor al tamaño solicitado.

**Patrón observado:**

La separación entre bloques es siempre tamaño solicitado + 16 bytes:

```
Bloque de  32B → separación =  32 + 16 =  48B (0x030) 
Bloque de  64B → separación =  64 + 16 =  80B (0x050) 
Bloque de 128B → separación = 128 + 16 = 144B (0x090) 
Bloque de 256B → separación = 256 + 16 = 272B (0x110) 
Bloque de 512B → separación = 512 + 16 = 528B (0x210) 
```

Esos 16 bytes extra corresponden al header de gestión que `malloc` antepone
a cada bloque para almacenar metadatos internos del heap (tamaño del bloque, flags
de estado, punteros de la lista libre). El usuario nunca los ve, pero siempre están:

```
Memoria física real por cada malloc(N):

┌──────────────────┬──────────────────────────┐
│  Header: 16B     │  Datos del usuario: N B  │
│  (metadata)      │  ← dirección retornada   │
└──────────────────┴──────────────────────────┘
 ←──────────── N + 16 bytes en total ─────────►
```

> El patrón confirma que el heap de Linux (glibc) usa un overhead fijo de 16 bytes
> por bloque para su gestión interna, independientemente del tamaño solicitado.
> Esto es un ejemplo de fragmentación interna introducida por el propio gestor de
> memoria, no por el programa del usuario.

### Punto 2: ¿Tiene éxito la asignación de 1500 bytes?

**Sí, tiene éxito:**
```
malloc(1500) -> 0x5577476822c0 [exito]
```

#### ¿Por qué tuvo éxito si se liberaron bloques alternos creando huecos?

Al liberar los índices pares se liberaron estos bloques:

| Índice | Tamaño liberado |
|---|---|
| 0 | 16B   |
| 2 | 64B   |
| 4 | 256B  |
| 6 | 1024B |
| 8 | 256B  |
| **Total** | **1616B** |

En teoría, con 1616 bytes liberados repartidos en 5 huecos separados por bloques
ocupados, una solicitud de 1500 bytes debería fallar por fragmentación externa.
Sin embargo tuvo éxito por dos razones:

**Razón 1: El heap puede crecer**

Cuando `malloc` no encuentra un hueco suficientemente grande en los bloques
existentes, no falla inmediatamente. En su lugar solicita más memoria al SO
mediante `sbrk()` o `mmap()`, expandiendo el heap hacia direcciones más altas.
La dirección retornada `0x5577476822c0` es más alta que todas las anteriores,
lo que confirma que `malloc` obtuvo memoria nueva del SO en lugar de reutilizar
los huecos:

```
Última dirección asignada:  0x557747682230  (índice 9, 128B)
Dirección de malloc(1500):  0x5577476822c0  ← justo después, heap expandido
```

**Razón 2: El coalescing del heap de glibc**

El gestor de memoria de glibc aplica coalescing automático al hacer `free()`.
Si alguno de los bloques liberados era adyacente a otro bloque libre, los fusiona.
En este caso los huecos no eran adyacentes entre sí (están separados por bloques
ocupados de índices impares), por lo que el coalescing no pudo formar un bloque
de 1500B a partir de los huecos existentes.

```
Estado del heap tras liberar índices pares:

┌──────────┬──────────┬──────────┬──────────┬──────────┐
│ LIBRE    │ idx 1    │ LIBRE    │ idx 3    │ LIBRE    │ ...
│ 16B  [0] │ 32B  [1] │ 64B  [2] │ 128B [3] │ 256B [4] │
└──────────┴──────────┴──────────┴──────────┴──────────┘
     ↑           ↑          ↑
  huecos separados por bloques ocupados → no se pueden fusionar
  ningún hueco individual >= 1500B → heap se expande
```

---

#### Conclusión en términos de fragmentación

| Situación | Resultado |
|---|---|
| Memoria libre total tras liberar pares | 1616B |
| Bloque contiguo libre más grande | 1024B (índice 6) |
| Solicitud de 1500B satisfecha con huecos |  Imposible |
| Solicitud satisfecha expandiendo el heap |  Éxito |

Este resultado ilustra perfectamente la fragmentación externa: había 1616 bytes
libres en total, más que suficientes para 1500 bytes, pero dispersos en huecos
separados por bloques ocupados. El sistema tuvo que consumir memoria nueva del SO
en lugar de reutilizar la memoria ya liberada, aumentando innecesariamente el
consumo de RAM del proceso.

### Punto 3: Diferencia entre el allocator de usuario y el del kernel

#### Los dos niveles de gestión de memoria

```
┌─────────────────────────────────────────────────────┐
│                  ESPACIO DE USUARIO                  │
│                                                      │
│   Programa C                                         │
│   malloc(256) ──► glibc allocator                   │
│                   (first fit / best fit / bins)      │
│                        │                            │
│                        │ sbrk() / mmap()            │
│                        ▼                            │
├─────────────────────────────────────────────────────┤
│                   ESPACIO DE KERNEL                  │
│                                                      │
│            Buddy System  ◄──── páginas físicas       │
│                 │                                    │
│                 ▼                                    │
│            Slab Allocator ◄─── objetos del kernel    │
└─────────────────────────────────────────────────────┘
```

---

#### Allocator de usuario: malloc / glibc

Gestiona memoria **dentro del heap del proceso**. Cuando el proceso necesita más
heap, pide páginas al kernel mediante `sbrk()` o `mmap()`, y luego las subdivide
internamente para satisfacer solicitudes de tamaño arbitrario.

| Característica | Detalle |
|---|---|
| Ubicación | Espacio de usuario |
| Granularidad | Bytes arbitrarios (1B, 17B, 1500B...) |
| Algoritmos | First fit, best fit, bins por tamaño (glibc usa tcmalloc-style bins) |
| Overhead | 16 bytes de header por bloque |
| Interacción con SO | Solo al crecer/reducir el heap (sbrk/mmap) |
| Velocidad | Muy rápido (no hay cambio de modo) |
| Fragmentación | Externa e interna posibles |

---

#### Allocator de kernel: Buddy System + Slab

El kernel también necesita memoria dinámica para sus propias estructuras internas
(inodos, PCBs, descriptores de archivo, etc.), pero no puede usar `malloc` porque
ese vive en espacio de usuario.

**Buddy System:** gestiona páginas físicas completas

Divide la memoria en bloques de potencias de 2 (1, 2, 4, 8... páginas). Cuando
se libera un bloque, busca su "buddy" (bloque adyacente del mismo tamaño) y los
fusiona automáticamente:

```
Memoria física: 16 páginas

Solicitud de 3 páginas → asigna bloque de 4 (potencia de 2):
┌────┬────┬────┬────┬────────┬────────────────┐
│ En │ En │ En │    │        │                │
│ uso│ uso│ uso│free│  free  │      free      │
│ 1P │ 1P │ 1P │ 1P │   2P   │      8P        │
└────┴────┴────┴────┴────────┴────────────────┘
                 ↑
         fragmentación interna (1 página desperdiciada)
```

**Slab Allocator:** gestiona objetos pequeños y frecuentes del kernel

Toma páginas del buddy system y las subdivide en slots del tamaño exacto de
objetos específicos, eliminando la fragmentación externa para esos objetos:

```
Slab de inodos (256B cada uno):
┌─────────┬─────────┬─────────┬─────────┬─────────┐
│ inodo   │ inodo   │  FREE   │ inodo   │  FREE   │
│ 256B    │ 256B    │ 256B    │ 256B    │ 256B    │
└─────────┴─────────┴─────────┴─────────┴─────────┘
  en uso    en uso              en uso
```

| Característica | Buddy System | Slab Allocator |
|---|---|---|
| Gestiona | Páginas físicas | Objetos del kernel |
| Granularidad | Potencias de 2 en páginas | Tamaño fijo por tipo de objeto |
| Fragmentación | Interna (redondeo a potencia de 2) | Mínima |
| Coalescing | Automático con buddy adyacente | No necesario (slots fijos) |
| Velocidad | Rápido | Muy rápido (slots preasignados) |

---

### ¿Por qué existen dos niveles?

Porque el kernel y los procesos de usuario tienen necesidades radicalmente distintas:

**1. Protección y aislamiento:**
el kernel no puede confiar en el allocator del usuario. Si un proceso corrompe
su heap, el kernel debe seguir funcionando. Tener su propio allocator garantiza
que la memoria del kernel nunca es afectada por bugs en espacio de usuario.

**2. Granularidad diferente:**
el kernel trabaja con páginas físicas (4KB mínimo). Dárselas directamente a
`malloc` sería un desperdicio enorme para objetos pequeños como un descriptor
de archivo (unos pocos bytes). El slab allocator resuelve esto subdividiendo
las páginas en objetos del tamaño exacto necesario.

**3. Rendimiento:**
una llamada al kernel (syscall) es costosa: implica cambio de modo usuario→kernel,
guardado de contexto, validaciones de seguridad. Si `malloc` tuviera que hacer
una syscall por cada asignación, el rendimiento sería catastrófico. Con dos
niveles, `malloc` solo llama al kernel cuando necesita más páginas; el resto
del tiempo opera completamente en espacio de usuario.

**4. Especialización:**
el slab allocator puede optimizar para patrones de uso conocidos del kernel
(muchas asignaciones y liberaciones del mismo tipo de objeto), mientras que
`malloc` debe ser de propósito general para cualquier programa de usuario.

```
Sin dos niveles:                  Con dos niveles:

malloc(8) ──► syscall ──► kernel  malloc(8) ──► glibc (user space) 
malloc(8) ──► syscall ──► kernel  malloc(8) ──► glibc (user space) 
malloc(8) ──► syscall ──► kernel  malloc(8) ──► glibc (user space) 
                                  glibc necesita más heap ──► syscall ──► kernel
N syscalls para N mallocs         1 syscall para miles de mallocs
```

> Los dos niveles de gestión de memoria son un ejemplo del principio de separación
> de responsabilidades: el kernel gestiona recursos físicos de forma segura y
> eficiente, mientras que el allocator de usuario optimiza el uso de esos recursos
> para los patrones de acceso de los programas.

---

# 7) TLBs — Translation Lookaside Buffer
#### Tuve que agregarle una linea adicional al codigo debido a que me salia este error:
<img width="666" height="125" alt="Captura de pantalla 2026-05-09 171748" src="https://github.com/user-attachments/assets/97c80216-5e21-47a0-bf8f-243ed48ba4e4" />

#### Ese error aparece porque CLOCK_MONOTONIC y clock_gettime() son funciones POSIX y en algunos compiladores/configuraciones no se habilitan automáticamente.

Añadí esta linea al principio:
```c
#define _POSIX_C_SOURCE 199309L
```
## Actividad 7.1: Localidad y TLB — Análisis
### Punto 1: Comparación de acceso secuencial vs aleatorio
<img width="1071" height="296" alt="image" src="https://github.com/user-attachments/assets/d4b17d63-4582-430d-9378-d0d4b2ff35e4" />

**Resultados de las 3 ejecuciones:**

| Ejecución | Secuencial (ms) | Aleatorio (ms) | Factor |
|---|---|---|---|
| 1 | 12.72 | 51.34 | 4.04x |
| 2 | 12.27 | 52.09 | 4.25x |
| 3 | 12.22 | 52.84 | 4.33x |
| **Promedio** | **12.40** | **52.09** | **4.20x** |

```
Promedio secuencial = (12.72 + 12.27 + 12.22) / 3 = 12.40 ms
Promedio aleatorio  = (51.34 + 52.09 + 52.84) / 3 = 52.09 ms
Factor              = 52.09 / 12.40 = 4.20x más lento
```

El acceso aleatorio es aproximadamente **4.2 veces más lento** que el secuencial
sobre el mismo arreglo de 16MB con los mismos datos.

**¿Por qué existe esa diferencia?**

Ambos accesos suman exactamente los mismos 4M enteros (confirmado por
`sum=8796090925056` idéntico en todos los casos), por lo que la diferencia
no es de cómputo sino puramente de **costo de acceso a memoria**:

- **Secuencial:** cada página cargada en TLB sirve para los siguientes 1024
  accesos consecutivos (página de 4KB / 4 bytes por entero). La TLB tiene
  una tasa de acierto cercana al 100%.

- **Aleatorio:** cada acceso salta a una página distinta e impredecible.
  La TLB se llena rápidamente con entradas que no se volverán a usar,
  generando **TLB misses** continuos que obligan a consultar la tabla de
  páginas en RAM en cada acceso.

```
Acceso secuencial:          Acceso aleatorio:

arr[0]  → TLB miss  →  carga página 0    arr[idx[0]] → TLB miss → carga página X
arr[1]  → TLB hit                        arr[idx[1]] → TLB miss → carga página Y
arr[2]  → TLB hit                        arr[idx[2]] → TLB miss → carga página Z
arr[3]  → TLB hit                        arr[idx[3]] → TLB miss → carga página W
...     → TLB hit    (×1022 más)       ...           → TLB miss → (casi siempre)

1 miss cada ~1024 accesos              ~1 miss por cada acceso
```
### Punto 2. Explicación con el modelo TLB

### ¿Qué es el TLB y cómo funciona?

El TLB (Translation Lookaside Buffer) es una caché de traducciones de direcciones
integrada en la MMU. Guarda las últimas traducciones VPN → PFN para evitar consultar
la tabla de páginas en RAM en cada acceso a memoria.

```
CPU solicita dirección virtual VA
            │
            ▼
      MMU busca VPN en TLB
            │
     ┌──────┴──────┐
     │             │
  TLB Hit       TLB Miss
     │             │
     ▼             ▼
  PFN directo   Consulta tabla    ← acceso extra a RAM (costoso)
  desde TLB     de páginas en RAM
     │             │
     └──────┬──────┘
            ▼
      Accede al dato en RAM
```

---

### Caso 1: Acceso secuencial — TLB hit rate alto

El arreglo ocupa 16MB. Con páginas de 4KB y enteros de 4 bytes, cada página
contiene **1024 enteros consecutivos**. Al recorrer el arreglo en orden:

```
Acceso a arr[0]    → TLB miss → carga traducción de página 0
Acceso a arr[1]    → TLB hit   (misma página)
Acceso a arr[2]    → TLB hit   (misma página)
...
Acceso a arr[1023] → TLB hit   (misma página)
Acceso a arr[1024] → TLB miss → carga traducción de página 1
Acceso a arr[1025] → TLB hit   (misma página)
...
```

```
Total páginas del arreglo = 16MB / 4KB = 4096 páginas
Total accesos             = 4.194.304
TLB misses                ≈ 4.096  (1 por página)
TLB hits                  ≈ 4.190.208

Hit rate ≈ 4.190.208 / 4.194.304 ≈ 99.9% 
```

---

### Caso 2: Acceso aleatorio — TLB hit rate bajo

El índice `idx[]` fue mezclado con Fisher-Yates, por lo que cada acceso
`arr[idx[i]]` salta a una página completamente distinta e impredecible.
Con 4096 páginas y una TLB típica de 64 entradas, la probabilidad de que
la página necesaria ya esté en TLB es mínima:

```
Acceso a arr[idx[0]] → página 3821 → TLB miss → carga traducción
Acceso a arr[idx[1]] → página 102  → TLB miss → carga traducción
Acceso a arr[idx[2]] → página 2957 → TLB miss → carga traducción
Acceso a arr[idx[3]] → página 44   → TLB miss → carga traducción
...
```

```
Total páginas del arreglo = 4096 páginas
Tamaño típico de TLB      = 64 entradas
Probabilidad de TLB hit   = 64 / 4096 ≈ 1.5%

Hit rate ≈ 1.5%    (casi cada acceso es un TLB miss)
TLB misses ≈ 4.128.301  (de 4.194.304 accesos totales)
```

---

### Comparación directa

| Métrica | Secuencial | Aleatorio |
|---|---|---|
| Patrón de acceso | Predecible, contiguo | Impredecible, disperso |
| TLB hit rate | ~99.9% | ~1.5% |
| TLB misses | ~4.096 | ~4.128.301 |
| Accesos extra a RAM | ~4.096 | ~4.128.301 |
| Tiempo promedio | 12.40 ms | 52.09 ms |
| Factor de lentitud | 1x | **4.2x** |

Cada TLB miss implica un acceso adicional a RAM para consultar la tabla de páginas.
Con ~4 millones de misses extra en el caso aleatorio, ese costo acumulado explica
directamente los 40ms de diferencia observados en las mediciones.

> Este experimento demuestra que la localidad de referencia no es solo un
> concepto teórico: tiene un impacto medible y significativo en el rendimiento
> real de los programas. Escribir código que acceda a memoria de forma secuencial
> y predecible es una de las optimizaciones más efectivas disponibles, sin cambiar
> el algoritmo ni el hardware.

### Punto 3. ¿Qué pasaría con páginas de 64KB en accesos aleatorios?

### Impacto en el TLB

Con páginas más grandes, cada entrada del TLB cubre un rango mayor de memoria,
por lo que se necesitan menos entradas para cubrir el mismo arreglo:

```
Arreglo de 16MB con páginas de 4KB:
  Total páginas = 16MB / 4KB  = 4.096 páginas
  TLB de 64 entradas cubre   = 64 / 4.096  = 1.5% del arreglo

Arreglo de 16MB con páginas de 64KB:
  Total páginas = 16MB / 64KB = 256 páginas
  TLB de 64 entradas cubre   = 64 / 256    = 25% del arreglo
```

Con páginas de 64KB la TLB puede cubrir el 25% del arreglo simultáneamente
en lugar del 1.5%. Esto significa que en el acceso aleatorio, 1 de cada 4 accesos
encontraría su traducción ya en la TLB:

```
Páginas de 4KB:                    Páginas de 64KB:

arr[idx[0]] → página 3821 → miss   arr[idx[0]] → página 238 → miss
arr[idx[1]] → página 102  → miss   arr[idx[1]] → página 14  → miss
arr[idx[2]] → página 2957 → miss   arr[idx[2]] → página 238 → HIT 
arr[idx[3]] → página 44   → miss   arr[idx[3]] → página 71  → miss
arr[idx[4]] → página 1203 → miss   arr[idx[4]] → página 14  → HIT 
...                                ...

Hit rate ≈ 1.5%                    Hit rate ≈ 25%
```

**Desde el punto de vista del TLB: mejora.**

---

### Impacto en el uso de memoria

Sin embargo, páginas más grandes introducen más fragmentación interna:

```
Páginas de 4KB:
  Desperdicio máximo por proceso = 4KB - 1 = 4.095 bytes ≈ 4KB

Páginas de 64KB:
  Desperdicio máximo por proceso = 64KB - 1 = 65.535 bytes ≈ 64KB
```

Un proceso que necesita apenas 1 byte más que un múltiplo de 64KB
desperdicia hasta 64KB en su última página. Con muchos procesos activos
este desperdicio se acumula rápidamente:

```
100 procesos × hasta 64KB desperdiciados = hasta 6.4MB desperdiciados
solo en fragmentación interna de la última página de cada proceso
```

Además, cada TLB miss con páginas de 64KB implica cargar 64KB desde disco
si la página no está en RAM, lo que hace que los page faults sean mucho
más costosos:

```
Page fault con página de 4KB  → leer  4KB desde disco
Page fault con página de 64KB → leer 64KB desde disco  (16x más lento)
```

**Desde el punto de vista del uso de memoria: empeora.**

---

### Resumen

| Métrica | Páginas 4KB | Páginas 64KB |
|---|---|---|
| Páginas para cubrir 16MB | 4.096 | 256 |
| TLB hit rate (acceso aleatorio) | ~1.5% | ~25% |
| TLB misses | ~4.1 millones | ~3.1 millones |
| Fragmentación interna máxima | ~4KB | ~64KB |
| Costo de page fault | bajo | 16x mayor |
| Entradas de tabla de páginas | 4.096 | 256 |

> El tamaño de página es un compromiso clásico en diseño de SO: páginas grandes
> mejoran el hit rate del TLB y reducen el tamaño de la tabla de páginas, pero
> aumentan la fragmentación interna y el costo de cada page fault. Por eso los
> SO modernos usan huge pages (2MB o 1GB en x86-64) de forma selectiva,
> solo para regiones de memoria grandes y de acceso frecuente, manteniendo
> páginas de 4KB como tamaño base para el resto.

## Actividad 7.2: Comportamiento de los TLB
### Punto 1: ¿Cuánta memoria puede cubrir un TLB de 64 entradas con páginas de 4KB?
 
**Cálculo:**

```
Memoria cubierta = entradas TLB × tamaño de página
                 = 64 × 4KB
                 = 256KB
```

Con 64 entradas el TLB puede mantener simultáneamente las traducciones de
**64 páginas distintas**, cubriendo un total de **256KB de memoria** sin
generar ningún miss.

---

#### ¿Es suficiente para un proceso moderno típico?

**No.** 256KB es insuficiente para la mayoría de procesos modernos:

```
Uso de memoria típico de procesos modernos:

Navegador web       →  500MB – 2GB  por pestaña
JVM (Java)          →  256MB – 1GB  mínimo
Servidor de base de datos → 1GB – 64GB
Editor de código    →  200MB – 800MB
Proceso simple en C →   5MB  – 50MB  ← el más cercano a 256KB
```

Incluso un proceso simple en C que usa 5MB de heap ya necesita:

```
Páginas requeridas = 5MB / 4KB = 1.280 páginas
TLB solo cubre     =              64 páginas  (5% del total)
```

---

#### ¿Cómo lo compensan los procesadores reales?

Los procesadores modernos usan varias estrategias para mitigar esta limitación:

**1. TLB multinivel:**
igual que la memoria caché, existe un TLB L1 (pequeño y rápido) y un TLB L2
(más grande y algo más lento):

```
Intel Core i7 (típico):
  TLB L1 datos:      64 entradas  → cubre  256KB
  TLB L2 unificado: 1536 entradas → cubre    6MB
```

**2. Huge Pages:**
usar páginas de 2MB en lugar de 4KB multiplica la cobertura por 512:

```
64 entradas × 2MB = 128MB cubiertos sin miss
```

**3. Prefetching y localidad:**
el hardware predice qué páginas se usarán próximamente y carga sus
traducciones en el TLB antes de que se necesiten.

---

#### Resumen

| Parámetro | Valor |
|---|---|
| Entradas TLB | 64 |
| Tamaño de página | 4KB |
| Memoria cubierta sin miss | **256KB** |
| Memoria típica de un proceso | **100MB – 2GB** |
| ¿Es suficiente? | **No** |
| Solución principal | TLB L2 + Huge Pages |

> 256KB puede parecer poco, pero gracias a la localidad de referencia la
> mayoría de los programas bien escritos trabajan intensamente sobre un conjunto
> de páginas pequeño en cada momento (working set), por lo que un TLB de 64
> entradas logra hit rates del 99%+ en código secuencial, como se demostró
> en el experimento anterior.

### Punto 2: ¿Qué es un TLB Shootdown?

Un TLB shootdown es el proceso por el cual un procesador obliga a todos los
demás procesadores del sistema a invalidar entradas específicas de sus TLBs locales
cuando una traducción de dirección virtual cambia o es eliminada.

Ocurre porque en un sistema multiprocesador cada CPU tiene su propio TLB,
y esos TLBs pueden tener copias de la misma traducción. Si una traducción cambia
en uno de ellos, los demás quedan con información desactualizada (*stale entries*).

---

#### ¿Cuándo ocurre?

El TLB shootdown ocurre cada vez que el SO modifica la tabla de páginas de un
proceso que puede estar ejecutándose en múltiples CPUs simultáneamente:

```
Situaciones típicas:

1. munmap()      → el proceso libera un rango de memoria virtual
2. mprotect()    → cambian los permisos de una página (R/W → solo lectura)
3. fork()        → se crea un nuevo proceso (Copy-On-Write)
4. swapping      → el SO desaloja una página a disco y invalida su PTE
5. mremap()      → se remapea un rango de direcciones virtuales
```

**Ejemplo concreto:**

```
CPU 0 ejecuta proceso P          CPU 1 ejecuta proceso P
TLB[VPN=42] → PFN=100           TLB[VPN=42] → PFN=100
                                              ↑ misma entrada

El SO en CPU 0 ejecuta munmap() sobre la página VPN=42:
  → invalida PTE en tabla de páginas
  → invalida TLB[VPN=42] en CPU 0
  → ¿y CPU 1?  ← todavía tiene la traducción stale ¡MAL!

Si CPU 1 accede a VPN=42 con la entrada stale:
  → traduciría a PFN=100 (que ya no le pertenece al proceso)
  → acceso a memoria de otro proceso  ← violación de seguridad ¡MAL!
```

Para evitar esto, el SO dispara un TLB shootdown hacia CPU 1.

---

#### ¿Cómo funciona el mecanismo?

```
CPU 0 (inicia el shootdown)              Otras CPUs

1. Modifica la PTE en la tabla
   de páginas compartida

2. Envía IPI (Inter-Processor        →  3. Reciben la interrupción
   Interrupt) a todas las CPUs           y pausan su ejecución
   afectadas

                                         4. Invalidan la entrada
                                            específica en su TLB
                                            (INVLPG en x86)

                                         5. Envían ACK a CPU 0

6. CPU 0 recibe todos los ACKs
   y continúa su ejecución
```

---

#### ¿Por qué es una operación costosa?

El TLB shootdown es costoso por varias razones que se acumulan:

**1. Interrupciones entre CPUs (IPI):**
enviar una interrupción a otra CPU no es instantáneo. El bus de interconexión
entre procesadores introduce latencia, y esta latencia escala con el número
de CPUs del sistema:

```
Sistema de 4 CPUs:   3 IPIs  → latencia moderada
Sistema de 64 CPUs: 63 IPIs  → latencia severa
```

**2. Pausa forzada en todas las CPUs receptoras:**
cada CPU que recibe el IPI debe **interrumpir lo que está haciendo**, guardar
su estado, ejecutar la invalidación del TLB y enviar el ACK. Todo el trabajo
útil que esas CPUs estaban realizando se detiene:

```
CPU 1 ejecutando trabajo útil:
────────────────────┬──────────────┬────────────────────
  trabajo normal    │  TLB flush   │  trabajo normal
                    │  (pausa)     │
                    └──────────────┘
                      tiempo perdido
```

**3. CPU iniciadora debe esperar todos los ACKs:**
CPU 0 no puede continuar hasta confirmar que todas las CPUs han invalidado
su TLB. Si una CPU tarda, todas las demás ya terminaron pero CPU 0 sigue
bloqueada esperando.

**4. TLB warming tras el shootdown:**
después de invalidar entradas, cada CPU debe recargar las traducciones desde
la tabla de páginas cuando vuelva a necesitarlas, generando una ráfaga de
TLB misses que degrada el rendimiento temporalmente.

```
Costo total de un TLB shootdown:

  Latencia IPI:          ~200-500 ns por CPU
  Pausa en CPUs:         ~100-300 ns por CPU
  TLB warming posterior: ~1-10 μs dependiendo del working set

En un servidor de 64 CPUs con shootdowns frecuentes:
  → puede consumir hasta un 10-20% del tiempo total de CPU
```

---

### Resumen

| Aspecto | Detalle |
|---|---|
| ¿Qué es? | Invalidación forzada de TLBs en todas las CPUs del sistema |
| ¿Cuándo ocurre? | Al modificar PTEs: munmap, mprotect, fork, swap |
| ¿Por qué es necesario? | Para mantener coherencia entre TLBs locales de cada CPU |
| ¿Por qué es costoso? | IPIs, pausas forzadas, espera de ACKs y TLB warming |
| ¿Escala bien? | No: el costo crece con el número de CPUs del sistema |

> El TLB shootdown es uno de los costos ocultos más significativos en sistemas
> multiprocesador de alta escala. Bases de datos, hipervisores y kernels de SO
> modernos dedican esfuerzo considerable a reducir la frecuencia de shootdowns
> agrupando modificaciones de PTEs, usando huge pages (menos entradas que
> invalidar) y diseñando estructuras de datos que minimicen el remapeo de memoria.

### Punto 3: TLB gestionado por hardware vs software

#### TLB por hardware (CISC / x86)

El hardware maneja automáticamente los TLB misses. Cuando ocurre un miss,
la MMU recorre la tabla de páginas en RAM (*page walk*) sin intervención
del SO, carga la traducción en el TLB y reintenta el acceso.

```
TLB miss en x86:
  CPU → miss → MMU hace page walk automático → carga PTE → reintenta
  (el SO nunca se entera si la página está presente)
```

El SO solo interviene si la página no está en RAM (page fault).
La tabla de páginas debe tener un formato fijo que el hardware entienda
(en x86: estructura de 4 niveles con formato específico).

#### TLB por software (RISC / MIPS)

El hardware simplemente lanza una excepción en cada TLB miss. Es el SO
quien decide cómo buscar la traducción, en qué estructura, y cómo cargarla
en el TLB mediante instrucciones privilegiadas.

```
TLB miss en MIPS:
  CPU → miss → excepción → SO busca la traducción → carga en TLB → reintenta
  (el SO controla todo el proceso)
```

#### Comparación

| Aspecto | Hardware (x86) | Software (MIPS) |
|---|---|---|
| ¿Quién maneja el miss? | La MMU automáticamente | El SO mediante excepción |
| Formato de tabla de páginas | Fijo (impuesto por hardware) | Libre (decide el SO) |
| Velocidad en miss | Mayor (sin excepción) | Menor (overhead de excepción) |
| Flexibilidad para el SO | Baja | Alta |
| Complejidad del hardware | Alta | Baja |

#### ¿Cuál ofrece mayor flexibilidad?

El **TLB por software (RISC/MIPS)**, porque el SO puede usar cualquier
estructura para su tabla de páginas: tabla invertida, tabla hash, árbol,
o cualquier formato optimizado para su caso de uso. No está atado a un
formato impuesto por el hardware.

Esto permite, por ejemplo, implementar tablas de páginas invertidas que
escalan con la memoria física en lugar de con el espacio virtual, algo
imposible en x86 sin extensiones especiales.

> La contrapartida es el rendimiento: cada TLB miss en MIPS genera una
> excepción que el SO debe manejar, lo que introduce más overhead que el
> page walk automático del hardware en x86. Es el compromiso clásico entre
> flexibilidad y velocidad.
