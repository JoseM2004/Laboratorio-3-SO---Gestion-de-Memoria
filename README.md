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
55f554dc8000-55f554dc9000    r-xp    00001000    08:20    58513    /home/equipo/proyectosC/LAB SO/LAB03/mem_map

| Campo | Valor |
|-------|-------|
| Rango | `55f554dc8000` – `55f554dc9000` |
| Permisos | `r-xp` |

**Permisos:** lectura (`r`) y ejecución (`x`), **sin escritura**.

**¿Por qué?** Esta región contiene el código máquina del programa (instrucciones). No necesita ser escrita en tiempo de ejecución. Prohibir la escritura es una medida de seguridad que evita que código malicioso modifique las instrucciones en memoria (*code injection*).

---

####  Región HEAP
55f5726ea000-55f57270b000   rw-p   00000000   00:00   0   [heap]


| Campo | Valor |
|-------|-------|
| Rango | `55f5726ea000` – `55f57270b000` |
| Permisos | `rw-p` |

**Permisos:** lectura (`r`) y escritura (`w`), **sin ejecución**.

**¿Por qué?** El heap almacena datos dinámicos creados con `malloc`. Deben poder leerse y modificarse. Sin embargo, no debe tener permiso de ejecución, ya que permitir ejecutar código desde el heap facilitaría ataques como buffer overflows o inyección de shellcode; esto se evita mediante la protección **NX/DEP** — *No eXecute / Data Execution Prevention*.

---

####  Región STACK

7fffb3845000-7fffb3866000   rw-p   00000000   00:00   0   [stack]


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
