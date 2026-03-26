# Informe de Deuda Técnica — Seguridad y Plataforma (lisco)

Fecha: 2026-03-05  
Perspectiva aplicada: **metaframework** (prioriza extensibilidad, documentación y hardening progresivo por perfil/configuración)

## 1) Enfoque de análisis

Este análisis se reorienta asumiendo que `lisco` es una base reusable para múltiples productos y contextos.  
En ese escenario, una parte de la deuda **no se resuelve restringiendo por defecto**, sino con:

- contratos claros,
- perfiles de seguridad (`baseline`, `strict`) por configuración,
- telemetría de adopción para migrar sin romper ecosistema.

Se evaluaron dos ejes:

1. **Deuda de seguridad** (riesgos explotables o de exposición).
2. **Deuda técnica general** (consistencia de API, mantenibilidad, DX, gobernanza y claridad documental).

---

## 2) Resumen ejecutivo

### Seguridad (prioridad alta)

1. **Alto** — SQL dinámica con identificadores no validados en filtros/ordenación (`whereRaw`/`orderByRaw`).
2. **Medio** — Exposición de mensajes internos en errores `500`.
3. **Medio** — Logging de `request.body` completo.
4. **Medio** — CORS default muy permisivo para escenarios con credenciales.
5. **Medio** — `express-fileupload` sin límites explícitos por defecto.
6. **Bajo/Medio** — REPL remota potente sin controles integrados (si se habilita fuera de red confiable).

### Deuda técnica general (prioridad media)

1. **Media** — Inconsistencias de contrato/semántica HTTP en controladores base.
2. **Media** — Inconsistencias de naming/configuración (`ioroutes` vs `ioevents`, `PORT_SSL` en docs vs `SSL_PORT` en runtime).
3. **Media** — Acoplamiento global por override de `console.*`.
4. **Baja/Media** — Límites por defecto altos/no uniformes en capa de datos.
5. **Baja** — Calidad documental/mensajes (typos y detalles confusos) que afectan adopción segura.

---

## 3) Hallazgos de seguridad (visión metaframework)

## S-01 — SQL dinámica con identificadores no validados

**Severidad:** Alta  
**Evidencia:**

- `src/db/knex/filters/KnexFilterParser.js:100`
- `src/db/knex/filters/KnexFilterParser.js:157`
- `src/db/knex/filters/KnexFilterParser.js:228`

Uso de `whereRaw`/`orderByRaw` con interpolación de identificadores (`prop`, `sort.field`) sin whitelist local obligatoria.

**Riesgo:** potencial SQL Injection por manipulación de campos/expresiones.

**Mitigación metaframework (no breaking):**

- Incorporar `allowedColumns` opcional por tabla/módulo.
- Definir `security.filterPolicy = "compat" | "warn" | "strict"`:
	- `compat`: comportamiento actual,
	- `warn`: ignora campo no permitido + warning,
	- `strict`: responde `400`.

**Potencial breaking (solo en hardening estricto):** `strict` por defecto y retirada de operadores `*raw` expuestos.

---

## S-02 — Exposición de errores internos

**Severidad:** Media  
**Evidencia:**

- `src/server/Server.js:199`

Se retorna `err.message` al cliente en `500`.

**Mitigación metaframework (no breaking):**

- Perfil `errorExposure: "legacy" | "safe"` (default `legacy` inicialmente).
- En `safe`: mensaje genérico + `errorId` correlacionable en logs.

---

## S-03 — Logging de body completo

**Severidad:** Media  
**Evidencia:**

- `src/server/Server.js:111`

Con `traceRequests=true` se loguea el `request.body` sin redacción.

**Mitigación metaframework (no breaking):**

- `traceRequests: { enabled, redactKeys, maxBodyLength, includeBody }`.
- Mantener `includeBody=true` para compatibilidad, pero documentar y recomendar `false` en producción.

---

## S-04 — CORS y file upload con defaults poco defensivos

**Severidad:** Media  
**Evidencia:**

- `src/server/Server.js:29`
- `src/server/Server.js:91`

`cors: { origin: true, credentials: true }` y `fileUpload()` sin límites explícitos.

**Mitigación metaframework (no breaking):**

- Mantener defaults actuales, pero añadir validadores de configuración con warnings de arranque.
- Exponer perfiles recomendados en docs (`dev`, `staging`, `prod`) en vez de forzar bloqueo inmediato.

---

## S-05 — REPL remota: capacidad operativa de alto impacto

**Severidad:** Baja/Media  
**Evidencia:**

- `src/App.js` (uso de `net.createServer` y `repl.start` cuando `REPL_ENABLED=true`)

No es un fallo por defecto (viene deshabilitada), pero su activación sin guía endurecida es riesgo operativo alto.

**Mitigación metaframework (no breaking):**

- Añadir “operational guardrails” documentales: bind local, túnel seguro, entorno controlado, checklist de producción.

---

## 4) Deuda técnica general (no solo seguridad)

## T-01 — Inconsistencias de contrato HTTP en `BaseController`

**Severidad:** Media  
**Evidencia:**

- `src/base/BaseController.js` (respuesta `204` con body JSON en `deleteEntidad`)
- `src/base/BaseController.js` (`Location: /entity/{id}` fijo, no ligado a `entity` real)

**Impacto:** integraciones y clientes SDK pueden asumir semánticas REST distintas; genera ambigüedad y bugs de cliente.

**Recomendación metaframework:**

- Documentar contrato actual como `legacy`.
- Definir modo `restStrict` opcional para comportamiento canónico (`204` sin body, `Location` consistente por recurso).

**Potencial breaking:** activar `restStrict` por defecto.

---

## T-02 — Inconsistencia de naming/configuración

**Severidad:** Media  
**Evidencia:**

- `src/server/Server.js` (constructor guarda `ioroutes`, `initialize()` invoca `configureIoEvents(this.ioevents)`)
- `readme.md:167` (`PORT_SSL`) vs `src/server/ClusterServer.js` (usa `SSL_PORT`)

**Impacto:** fricción de adopción, configuración errónea y comportamientos inesperados.

**Recomendación metaframework:**

- Mantener compatibilidad con alias de config y deprecación gradual.
- Corregir documentación primero, luego telemetría de uso y retiro controlado.

---

## T-03 — Acoplamiento global del logger

**Severidad:** Media  
**Evidencia:**

- `src/logger/Logger.js` (override global de `console.log/error/info/debug`)

**Impacto:** efectos laterales en librerías consumidoras, tests y tooling; difícil composición en ecosistema heterogéneo.

**Recomendación metaframework:**

- Mantener modo actual como `logger.mode = "patch-console"`.
- Añadir `logger.mode = "inject-only"` sin override global para nuevos proyectos.

---

## T-04 — Defaults y límites no uniformes en datos

**Severidad:** Baja/Media  
**Evidencia:**

- `src/base/BaseService.js` (`limit` por defecto de listados)
- `src/db/knex/dao/BaseKnexDao.js:18` (`limit || 10000`)

**Impacto:** variabilidad de rendimiento y riesgo de sobrecarga según ruta/DAO.

**Recomendación metaframework:**

- Centralizar política de paginación (`pagination.defaultLimit`, `pagination.maxLimit`) documentada y configurable.

---

## T-05 — Calidad documental y consistencia DX

**Severidad:** Baja  
**Evidencia:**

- `src/base/BaseController.js` (`Expected uiid` typo)
- `src/common/Runtime.js` (`process.exit(1)` en salidas exitosas de utilidades CLI)

**Impacto:** mensajes confusos y señales de error ambiguas en automatizaciones.

**Recomendación metaframework:**

- Corregir copy/typos y códigos de salida de CLI (`0` en éxito), documentando transición si hay scripts dependientes.

---

## 5) Estrategia recomendada para metaframework (sin ruptura)

### Fase A — Documentar y observar (rápida)

1. Publicar “Security & Platform Profiles” (`compat`, `recommended`, `strict`).
2. Añadir warnings de configuración insegura en arranque (sin bloquear).
3. Corregir incoherencias de documentación/env vars y checklist operacional (REPL, CORS, uploads).

### Fase B — Endurecer por opt-in

1. Activar validación opcional de columnas/filtros.
2. Añadir modos opcionales para contratos REST y logger sin override global.
3. Exponer límites uniformes de paginación y uploads por configuración central.

### Fase C — Migrar a defaults más seguros (con comunicación)

1. Medir impacto real (warnings/telemetría).
2. Publicar deprecaciones y ventana de migración.
3. Cambiar defaults en major release si el impacto está acotado.

---

## 6) Matriz rápida: documentar vs restringir

- **Documentar primero:** REPL, CORS en entornos, perfiles de logging, convenciones REST.
- **Restringir opcional (opt-in):** validación de filtros/sort, límites upload/paginación.
- **Restringir por defecto (major):** solo tras telemetría y guía de migración.

---

## 7) Conclusión

Desde una perspectiva de metaframework, la deuda principal no es solo técnica sino de **gobernanza de contratos**.  
La ruta con menor riesgo es: **compatibilidad por defecto + perfiles recomendados + endurecimiento progresivo con observabilidad**, evitando breaking changes inmediatos y habilitando a cada producto consumidor a subir su nivel de seguridad de forma controlada.
