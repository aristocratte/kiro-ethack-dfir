---
name: docker-evidence-analysis
description: Análisis forense en SOLO LECTURA del .tar exportado de un contenedor Docker comprometido. Parte de docker diff (A/C/D) filtrando el ruido del runtime, descubre dónde loguea Apache (y maneja access.log → /dev/stdout), revisa access.log/error.log buscando XSS, SQLi, inyección de comandos, webshell y escáneres, examina .bash_history, /etc/passwd, cron, /tmp y archivos, y detecta borrado de huellas CRUZANDO docker logs con el access.log del .tar (recupera líneas eliminadas), más logs truncados e historial vacío. Explica el límite de los mtime en exports. Cada hallazgo lleva su evidencia y su técnica MITRE ATT&CK. Cubre la etapa Analyze.
---

# docker-evidence-analysis — Analizar el `.tar` en solo lectura

Cubre **Analyze** del Flujo_Investigacion. Trabaja **únicamente** sobre el
`05_docker_export.tar` recolectado por `docker-evidence-collection`, extraído y
montado en **solo lectura**. No se vuelve a tocar el contenedor.

## Regla de oro del análisis

- **Solo lectura.** Se extrae la copia, se le quita permiso de escritura y se analiza
  así. Nunca se monta el contenedor vivo ni se usa `docker exec`.
- **Integridad antes y después.** `sha256sum -c SHA256SUMS` debe dar **OK antes** de
  empezar y **OK al terminar** (`hash_pre == hash_post`); si no, el análisis no es
  válido. Anota ambas verificaciones en la Cadena_Custodia.

## Paso 0 — Verificar y extraer en solo lectura

```bash
export ENGAGEMENT_ID="dvwa-lab-ulsa"      # el MISMO engagement de la recolección
export ENG_DIR="agent_ethack_dfir/engagements/${ENGAGEMENT_ID}"   # camino COMPLETO (scope.yaml real)
export EVID_DIR="${ENG_DIR}/evidence"
export WORK="${ENG_DIR}/analysis"         # gitignored: el rootfs extraído no se commitea

# 1) Integridad ANTES (hash_pre)
( cd "${EVID_DIR}" && sha256sum -c SHA256SUMS )

# 2) Extraer la copia y dejarla en SOLO LECTURA
mkdir -p "${WORK}/rootfs"
tar -xf "${EVID_DIR}/05_docker_export.tar" -C "${WORK}/rootfs"
chmod -R a-w "${WORK}/rootfs"
export ROOT="${WORK}/rootfs"
```

Al terminar todo el análisis, repetir `sha256sum -c SHA256SUMS` (hash_post) y
comprobar que coincide con el inicial.

## Paso 1 — Partir de lo que señaló `docker diff` (A / C / D)

`docker diff` marca cada ruta cambiada respecto a la imagen base. Es el mapa de por
dónde empezar:

- **`A`** (*Added*) — archivos **nuevos**: candidatos a webshell, herramientas
  subidas, binarios, payloads en `/tmp`, claves `authorized_keys`.
- **`C`** (*Changed*) — archivos **modificados**: `/etc/passwd`, `/etc/crontab`,
  configuraciones, `.bashrc`, logs manipulados.
- **`D`** (*Deleted*) — archivos **borrados**: posible borrado de huellas.

```bash
grep '^A ' "${EVID_DIR}/03_docker_diff.txt"   # añadidos
grep '^C ' "${EVID_DIR}/03_docker_diff.txt"   # modificados
grep '^D ' "${EVID_DIR}/03_docker_diff.txt"   # borrados  (ojo: anti-forense)
```

**Filtra el ruido del runtime.** Un `docker diff` real trae decenas de rutas que
cambian por el funcionamiento normal (sesiones PHP, PIDs, sockets, datos de la base
de datos) o que inyecta el entorno de ejecución (p. ej. certificados de
OrbStack/Docker Desktop), no el atacante. Descártalas para no ahogarte:

```bash
D="${EVID_DIR}/03_docker_diff.txt"
NOISE='/(run|proc|sys|tmp)(/|$)|/var/lib/mysql(/|$)|/var/lib/php(/|$)|/var/log/(mysql|apache2/other)|/\.cache/|orbstack|/usr/local/share/ca-certificates'
ZONAS='/var/www/|/hackable/|/tmp/|/var/tmp/|/dev/shm/|/etc/(passwd|shadow|crontab|cron|sudoers|ssh)|/var/spool/cron|\.bashrc|\.profile|authorized_keys|/var/log/'

# Añadidos y Borrados = alta señal; se muestran todos menos el ruido del runtime
grep -E '^[AD] ' "$D" | grep -Ev "$NOISE"
# Modificados (C): suelen ser muchos; quédate solo con los de las zonas que importan
grep '^C ' "$D" | grep -E "$ZONAS" | grep -Ev "$NOISE"
```

**Dónde mirar de verdad** (prioriza estas rutas sobre el resto del `diff`):

| Zona | Por qué importa | ATT&CK típico |
|---|---|---|
| **docroot** (`/var/www/html`, `/hackable/uploads`) | webshells, páginas alteradas | T1505.003 |
| **`/tmp`, `/var/tmp`, `/dev/shm`** | *staging* y herramientas subidas | T1074 |
| **cron** (`/etc/crontab`, `/etc/cron.*`, `/var/spool/cron`) | persistencia | T1053.003 |
| **`/etc`** (`passwd`, `shadow`, `sudoers`, `ssh/`) | cuentas, claves, privilegios | T1136 · T1098 |
| **home** (`.bashrc`, `.profile`, `.ssh/authorized_keys`) | persistencia de usuario | T1546.004 |
| **`/var/log`** | logs truncados o borrados (anti-forense) | T1070.002 |

Cada ruta interesante de `diff` se corrobora en `${ROOT}` (o se marca como borrada).

## Paso 2 — Logs de Apache: `access.log` y `error.log`

**No supongas la ruta: descúbrela primero.** Según la imagen, Apache puede loguear a
`/var/log/apache2/`, a otra ruta (mira `CustomLog`/`ErrorLog` en su configuración) o
directamente a `/dev/stdout`:

```bash
# 1) ¿dónde loguea Apache, según su configuración?
grep -RInE "CustomLog|ErrorLog" "${ROOT}/etc/apache2/" 2>/dev/null

# 2) localiza los access/error.log reales dentro de la copia
find "${ROOT}/var/log" -maxdepth 3 -type f \( -name "access*log*" -o -name "error*log*" \) 2>/dev/null

ACC="${ROOT}/var/log/apache2/access.log"      # ajústalo a lo que encontraste
ERR="${ROOT}/var/log/apache2/error.log"
ls -la "${ROOT}/var/log/apache2/"
```

> **Caso `/dev/stdout`.** Si `access.log` es un **symlink a `/dev/stdout`** (o a
> `/proc/self/fd/...`), dentro del `.tar` será un enlace colgante y **no contiene las
> peticiones**: Apache las mandó al stdout del contenedor. En ese caso el análisis de
> logs se apoya en **`docker logs` (`04_docker_logs.txt`)**, no en el archivo:
> ```bash
> readlink -f "$ACC" 2>/dev/null        # si apunta a /dev/stdout o /proc/.../fd → usa docker logs
> [ -s "$ACC" ] || echo "access.log vacío/colgante → analiza ${EVID_DIR}/04_docker_logs.txt"
> ```

Buscar las familias de ataque sobre DVWA (si el archivo está vacío o es un symlink
colgante, corre los mismos `grep` sobre `${EVID_DIR}/04_docker_logs.txt`):

```bash
# SQL injection (T1190)
grep -Ei "union[[:space:]%+]+select|information_schema|' ?or ?'?1'?='?1|sleep\(|benchmark\(|concat\(" "$ACC"

# XSS reflejado/almacenado (T1059.007)
grep -Ei "<script|%3cscript|onerror=|onload=|javascript:|alert\(|document\.cookie" "$ACC"

# Inyección de comandos (DVWA "Command Injection") (T1190 + T1059)
grep -Ei "(;|%3b|\||%7c|&&|%26%26|\\\$\(|%60)[[:space:]]*(id|whoami|uname|cat|ls|nc|bash|sh|wget|curl|python)" "$ACC"

# Subida de webshell en DVWA (T1505.003)
grep -Ei "POST .*/vulnerabilities/upload" "$ACC"
grep -Ei "/hackable/uploads/.*\.(php|phtml|php5|phar)" "$ACC"

# Webshell por correlación con docker diff: NO solo /hackable/uploads. Todo .php que
# docker diff marcó AÑADIDO (A) —en cualquier ruta— buscado en los logs (T1505.003)
for p in $(grep -E '^A ' "${EVID_DIR}/03_docker_diff.txt" | awk '{print $2}' | grep -Ei '\.(php|phtml|php[0-9]?|phar)$'); do
  base="$(basename "$p")"
  echo "[.php añadido en diff: ${base}]"; grep -E "/${base}([?/ ]|$)" "$ACC"
done

# Peticiones con parámetros típicos de ejecución de comandos (webshell genérico) — T1059
grep -Ei '[?&](cmd|exec|command|shell|c|run|exe|arg|op|do)=' "$ACC"

# Escáneres / herramientas automáticas (T1595 / T1046) por User-Agent y patrón
grep -Ei "nikto|sqlmap|nmap|masscan|dirb|gobuster|wfuzz|feroxbuster|hydra" "$ACC"

# error.log: errores de PHP/SQL que delatan explotación en curso
grep -Ei "error|warning|sql syntax|undefined|allowed memory|system\(|exec\(" "$ERR"
```

Para cada coincidencia anota: **IP de origen, fecha/hora, método+URL, User-Agent y
código de respuesta**. Un `200`/`302` tras un payload sugiere éxito; un `403`/`404`
sugiere intento fallido.

## Paso 3 — Artefactos del sistema de archivos

```bash
# Historial de shell (comandos del atacante) — T1059
cat "${ROOT}/root/.bash_history" 2>/dev/null
for h in "${ROOT}"/home/*/.bash_history; do echo "== $h =="; cat "$h" 2>/dev/null; done

# Usuarios y cuentas (altas, UID 0 extra, shells sospechosas) — T1136 / T1078
cat "${ROOT}/etc/passwd"; echo "---"; cat "${ROOT}/etc/shadow" 2>/dev/null
awk -F: '($3==0){print "UID 0 -> "$1}' "${ROOT}/etc/passwd"

# Persistencia por cron — T1053.003
cat "${ROOT}/etc/crontab" 2>/dev/null
ls -la "${ROOT}/etc/cron.d/" "${ROOT}/etc/cron.daily/" 2>/dev/null
cat "${ROOT}"/var/spool/cron/crontabs/* 2>/dev/null

# Persistencia por perfiles de shell — T1546.004
grep -RInE "curl|wget|nc |bash -i|/dev/tcp|base64 -d" \
  "${ROOT}/root/.bashrc" "${ROOT}/root/.profile" "${ROOT}/etc/profile" 2>/dev/null

# Staging en /tmp y directorios world-writable — T1074 / herramientas subidas
ls -la "${ROOT}/tmp/" "${ROOT}/dev/shm/" "${ROOT}/var/tmp/" 2>/dev/null
find "${ROOT}" -type f \( -name "*.php" -o -name "*.sh" -o -name "*.py" \) \
     -path "*upload*" 2>/dev/null

# Archivos modificados recientemente — OJO: docker export NO preserva bien los mtime
# (ver el límite en el Paso 4). Úsalo como pista para la cronología, no como prueba.
find "${ROOT}" -xdev -type f -printf '%TY-%Tm-%Td %TH:%TM %p\n' 2>/dev/null \
  | sort | tail -n 40
```

Correlaciona estos artefactos con las IP y horas de los logs de Apache para armar la
cronología.

## Paso 4 — ¿La Red Team borró sus huellas? (anti-forense)

Busca señales de que el atacante limpió la escena; cada una es, en sí misma, un
hallazgo.

### 4.1 Cruce clave: `docker logs` (#4) ↔ `access.log` del `.tar` (#5)

**Esta es la comprobación más importante del skill, y la razón por la que se
recolecta `docker logs` ANTES del `export`.** En contenedores, Apache suele enviar el
log también al stdout del contenedor (por un `tail -f access.log` del entrypoint, o
un `CustomLog /dev/stdout`). Ese stream lo captura Docker **en el host**, fuera del
alcance del atacante dentro del contenedor: si borra o edita el `access.log` del
filesystem, **la línea sobrevive en `docker logs`**. Comparar ambas fuentes delata el
borrado e incluso **recupera la línea eliminada**:

```bash
ACC="${ROOT}/var/log/apache2/access.log"      # ajusta a la ruta descubierta en el Paso 2

# normaliza las peticiones de cada fuente (quita el prefijo de tiempo que añade docker logs)
grep -E '"(GET|POST|HEAD|PUT)' "${EVID_DIR}/04_docker_logs.txt" | sed -E 's/^[0-9T:.Z+-]+ //' | sort > /tmp/_fromlogs.txt
sort "$ACC" 2>/dev/null > /tmp/_fromfile.txt

echo "accesos en docker logs: $(wc -l < /tmp/_fromlogs.txt)   en el archivo: $(wc -l < /tmp/_fromfile.txt)"
echo "--- líneas presentes en docker logs pero AUSENTES del archivo (= borradas) ---"
comm -23 /tmp/_fromlogs.txt /tmp/_fromfile.txt        # T1070.002
rm -f /tmp/_fromlogs.txt /tmp/_fromfile.txt
```

Si `comm -23` devuelve líneas, el `access.log` fue **manipulado**: documenta cada
línea recuperada como hallazgo (T1070.002) con su cita literal y úsala en la
cronología. (Si el archivo es un symlink a `/dev/stdout`, `docker logs` es
directamente la única fuente de accesos; ver Paso 2.)

### 4.2 Otras señales de limpieza

```bash
# Logs truncados o vacíos (tamaño 0 pese a haber tráfico) — T1070.002.
# Se EXCLUYEN los que están vacíos por diseño (no son hallazgo): btmp, wtmp, lastlog,
# faillog, tallylog y other_vhosts_access.log (vhost no usado en DVWA).
ls -la "${ROOT}/var/log/apache2/"
find "${ROOT}/var/log" -type f -empty 2>/dev/null \
  | grep -Ev '/(btmp|wtmp|lastlog|faillog|tallylog|other_vhosts_access\.log)$'

# Rotaciones/huecos: saltos grandes de tiempo o reinicio del contador de líneas
head -n1 "$ACC"; tail -n1 "$ACC"      # ¿el rango temporal cubre la ventana del ataque?

# Historial de shell vaciado o redirigido a /dev/null — T1070.003
ls -la "${ROOT}/root/.bash_history" 2>/dev/null   # tamaño 0 = vaciado
readlink "${ROOT}/root/.bash_history" 2>/dev/null # ¿apunta a /dev/null?

# Rutas marcadas 'D' en docker diff = borrados respecto a la imagen — T1070.004
grep '^D ' "${EVID_DIR}/03_docker_diff.txt"
```

> **Límite de `docker export` con los mtime (timestomping, T1070.006).** `docker
> export` aplana el filesystem y **no conserva de forma fiable las marcas de tiempo**
> ni la historia de capas, así que un `find -newermt` sobre la copia **no prueba**
> alteración de fechas: trátalo como indicio débil, no como evidencia. Para
> timestomping apóyate en fuentes más fiables —las marcas de `docker logs`, el
> `Created`/`StartedAt` de `docker inspect` y la correlación entre fuentes (4.1)—, no
> en el mtime del `.tar`.

Un `access.log` cuyo rango temporal **no** cubre el ataque que sí aparece en otras
evidencias, **una línea presente en `docker logs` y ausente del archivo**, un
`.bash_history` en tamaño 0 o enlazado a `/dev/null`, o un `diff` con borrados de
logs, son indicios de **Covering Tracks**.

## Cada hallazgo: evidencia + técnica ATT&CK

Documenta cada hallazgo con esta ficha (alimenta el reporte del skill
`docker-forensics-report`):

```
- Hallazgo:     <qué pasó, en una frase>
- Evidencia:    <archivo:línea o ruta en ${ROOT}; cita literal del log/diff>
- Fuente:       <access.log | error.log | docker diff | .bash_history | passwd | cron | /tmp>
- Cuándo (UTC): <fecha/hora del log>
- Origen:       <IP atacante / usuario>
- ATT&CK:       <Txxxx[.sub] — Nombre de la técnica>
- Confianza:    <alta | media | baja> + por qué
```

Mapeo ATT&CK de referencia para este escenario DVWA:

| Observación | Técnica MITRE ATT&CK |
|---|---|
| SQLi contra la app pública | T1190 Exploit Public-Facing Application |
| Inyección de comandos | T1190 + T1059 Command and Scripting Interpreter |
| XSS | T1059.007 JavaScript |
| Webshell en `/hackable/uploads/` | T1505.003 Server Software Component: Web Shell |
| Escaneo con nikto/sqlmap/nmap | T1595 Active Scanning · T1046 Network Service Scanning |
| Alta de usuario / UID 0 | T1136 Create Account · T1078 Valid Accounts |
| Persistencia por cron | T1053.003 Scheduled Task/Job: Cron |
| Persistencia por `.bashrc`/perfil | T1546.004 Unix Shell Configuration Modification |
| Lectura de `/etc/passwd`,`/etc/shadow` | T1003.008 OS Credential Dumping: /etc/passwd and /etc/shadow |
| Borrado/truncado de logs | T1070.002 Clear Linux or Mac System Logs |
| Vaciado de historial | T1070.003 Clear Command History |
| Borrado de archivos | T1070.004 File Deletion |
| Alteración de mtimes | T1070.006 Timestomp |

## Por modo de ejecución

- **script-kiddie:** entrega los `grep`/`find` listos y resume los hallazgos con su
  técnica ATT&CK.
- **green-hat:** explica cada patrón (qué delata una SQLi vs un escaneo) y pide
  interpretar las coincidencias antes de concluir.
- **pro:** no da los patrones hechos; guía al analista a construir sus expresiones y
  su cronología, y a justificar cada mapeo ATT&CK y nivel de confianza.
