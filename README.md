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
