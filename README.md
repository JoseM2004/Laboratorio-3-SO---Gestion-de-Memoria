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

Ya que el main esta alojado en la direccion `0x55f554dc8209` que esta dentro del rango `55f554dc8000 - 55f554dc9000`

| Campo | Valor |
|-------|-------|
| Rango | `55f554dc8000` – `55f554dc9000` |
| Permisos | `r-xp` |

**Permisos:** lectura (`r`) y ejecución (`x`), **sin escritura**.

**¿Por qué?** Esta región contiene el código máquina del programa (instrucciones). No necesita ser escrita en tiempo de ejecución. Prohibir la escritura es una medida de seguridad que evita que código malicioso modifique las instrucciones en memoria (*code injection*).

---

####  Región HEAP



