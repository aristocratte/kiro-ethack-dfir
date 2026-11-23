# Realimentación del resultado — `docker-forensics` (Req 15.4)

> Artefacto_Documentacion obligatorio. Registra la realimentación del resultado del
> Power al probarlo contra el Entorno_Laboratorio: qué salió bien, qué se corrigió y
> qué queda pendiente.

## Sesión de prueba (self-test, modo green-hat)

Se probó de punta a punta sobre un contenedor desechable propio (`test-dvwa`, imagen
`vulnerables/web-dvwa`, publicado solo en `127.0.0.1`), simulando un ataque:
webshell `/var/www/html/shell.php` + borrado de una línea del `access.log`. No se
tocó el DVWA del laboratorio (`scope.yaml`) ni el host; las evidencias fueron a un
directorio efímero.

### Qué funcionó

- Recolección en Orden_Volatilidad (`docker top → inspect → diff → logs → export`)
  sin `docker exec` ni escritura en el contenedor víctima.
- Cadena_Custodia encadenada (10 eslabones); la prueba de manipulación de una línea
  rompió el enlace como se espera.
- Integridad `hash_pre == hash_post` del export; análisis del `.tar` en solo lectura.
- `docker diff` marcó el webshell como `A /var/www/html/shell.php`; los `grep`
  identificaron `sqlmap` y `Nikto`.
- El borrado de huella se detectó y la línea eliminada se **recuperó** cruzando
  `docker logs` con el `access.log` del `.tar`.

## Qué se corrigió tras la realimentación (7 huecos detectados en la prueba)

1. **Cruce `docker logs` ↔ `access.log` (lo más importante).** El Power recolectaba
   ambas fuentes pero no decía compararlas. Añadido el Paso **4.1** en
   `docker-evidence-analysis` (`comm -23` para recuperar líneas borradas); explica que
   por eso se recolecta `docker logs` **antes** del `export`.
2. **Aislamiento.** `docker network disconnect` borra el estado de red que
   `docker inspect` debe capturar. Ahora se recomienda **`docker pause` por defecto**
   (con el porqué) y `disconnect` **solo si lo pide el Incident Manager** y tras
   capturar `inspect`. Corregido en `docker-evidence-collection` y en el README.
3. **Pre-flight.** Añadida una comprobación inicial en `docker-evidence-collection`:
   demonio Docker activo, `sha256sum`/`tar` presentes y `jq` opcional, con una
   **variante de `coc_append` sin `jq`**.
4. **Rutas de log.** Antes se asumía `var/log/apache2/`. Ahora el Paso 2 **descubre**
   dónde loguea Apache (`CustomLog`/`ErrorLog`, `find`) y maneja el caso
   **`access.log → /dev/stdout`** (apoyarse en `docker logs`).
5. **Ruido de `docker diff`.** Añadido un filtro del ruido del runtime (sesiones PHP,
   `/run`, `/var/lib/mysql`, certificados de OrbStack/Docker Desktop) y una tabla de
   **dónde mirar de verdad** (docroot, `/tmp`, cron, `/etc`, home, `/var/log`).
6. **Límite de `docker export` con los mtime.** Documentado que el export no conserva
   bien las marcas de tiempo, así que `find -newermt` **no prueba** timestomping
   (T1070.006); es indicio débil. Se apoya en `docker logs`/`docker inspect`.
7. **Invariante del encadenado.** Documentado que `prev_sha256` se calcula sobre la
   línea anterior **incluido su salto `\n`**, con el comando de verificación exacto
   (`tail -n 1 | sha256sum` al encadenar, `printf '%s\n' | sha256sum` al verificar)
   para que otra implementación no vea "cadena rota" en falso.

## Segunda ronda — scope, rutas y pulidos (tras el 2º self-test)

El 2º self-test confirmó que los 7 huecos anteriores se sostienen corriendo el Power
al pie de la letra. Quedaba un problema de fondo —el Power asumía el engagement real y
había que fijar variables a mano y saltarse el scope— ya corregido **sin contornear el
alcance**:

8. **Variables derivadas de `ENGAGEMENT_ID`, nada en duro.** `ENG_DIR`, `SCOPE`,
   `EVID_DIR` y `COC` se derivan; el `CONTAINER` se **lee del `scope.yaml`** (por
   `ASSET_ID`) con `python3`, no se teclea. (`docker-evidence-collection` Paso 3 y
   `docker-evidence-analysis` Paso 0.)
9. **Validación de alcance como comando que detiene.** El Paso 4 comprueba contra
   `scope.yaml` que el asset existe y que `host_is_target: false`; si no, aborta
   (`exit 1`). Ya no es "a ojo" ni se salta.
10. **Engagement de prueba local (sin commit).** Documentado cómo crear el
    `scope.yaml` de prueba en su **camino completo**
    `agent_ethack_dfir/engagements/<algo>-selftest/` (donde vive el scope.yaml real),
    para que la validación de alcance pase con normalidad.
11. **Evidencia pesada fuera del repo.** `.gitignore` con prefijo **`**/`** (casa a
    cualquier profundidad: raíz y `agent_ethack_dfir/engagements/`) excluye
    `**/engagements/*/evidence/*` (incluido el `.tar` y `SHA256SUMS`),
    `**/engagements/*/analysis/` y `**/engagements/*-selftest/`; **solo**
    `chain_of_custody.jsonl` queda versionado. Un patrón anclado a la raíz
    (`engagements/...`) **no** cubría `agent_ethack_dfir/engagements/`; corregido y
    verificado con `git check-ignore --no-index`.
12. **`return 1` del pre-flight.** Envuelto en una función `preflight()` (ahí `return`
    es válido) y llamado con `preflight || exit 1`.
13. **Webshell en los logs no solo en `/hackable/uploads`.** El Paso 2 ahora busca
    también cada `.php` que `docker diff` marcó **añadido (A)** y las peticiones con
    parámetros de ejecución (`cmd=|exec=|command=|shell=|c=|run=…`).
14. **`find -empty` con exclusiones.** Se descartan los vacíos por diseño: `btmp`,
    `wtmp`, `lastlog`, `faillog`, `tallylog`, `other_vhosts_access.log`.

## Pendientes / mejoras futuras

- Validar las rutas de log sobre el `.tar` real del DVWA del laboratorio.
- Confirmar `docker pause` como aislamiento por defecto con el Incident Manager en un
  simulacro.
- Mínimo de ≥2 Powers con Herramienta_Real por alumno (Req 9.6): **no aplica aquí**.
  El profesor confirmó **un solo Power para todo el equipo Digital Forensics**, así
  que el estado "pendiente (<2)" que reporta `make validate` para el responsable es
  **esperado y correcto**, no un fallo a cerrar.
- Power ya cableado al agente de rol `digital-forensics` (lista `powers:` del SOP y
  fila `digital-forensics` de `gen_kiro_agents.py`), con
  `.kiro/agents/ethack-digital-forensics.json` regenerado.
