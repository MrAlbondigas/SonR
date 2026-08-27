# Proyecto Cyber — Escáner de vulnerabilidades de red

[![Tests](https://github.com/MrAlbondigas/-proyecto-cyber/actions/workflows/tests.yml/badge.svg)](https://github.com/MrAlbondigas/-proyecto-cyber/actions/workflows/tests.yml)

Plataforma de gestión de vulnerabilidades para la red local: descubre equipos, identifica software y versiones en ejecución, cruza contra vulnerabilidades conocidas y expone los resultados en un dashboard web.

## Arquitectura

- **db** — PostgreSQL, almacena inventario de equipos, software detectado y vulnerabilidades.
- **api** — FastAPI, expone endpoints de consulta, autenticación con roles (admin/analista/visor) y recibe los resultados del escáner.
- **scanner** — Python + nmap, descubre equipos en la red local (`network_mode: host`) y envía los resultados a la API.
- **enricher** — cruza cada software detectado con la API de NVD (CVEs) y el catálogo CISA KEV (exploits activamente explotados).
- **credcheck** — prueba credenciales por defecto muy conocidas y documentadas contra SSH/FTP/Telnet/HTTP Basic Auth expuestos, priorizando las específicas del fabricante detectado (por MAC) antes que la lista genérica.
- **reporter** — genera un reporte PDF semanal (top prioridades, rutas de ataque, credenciales encontradas, timeline) descargable desde el dashboard.
- **dashboard** — servido por la propia API (plantillas Jinja2), muestra inventario, prioridades, rutas de ataque y timeline en tiempo real.

## Uso

```bash
cp .env.example .env   # editar con valores propios
docker compose up -d --build
```

Dashboard disponible en `http://<ip-vm>:8000`.

## Tests

```bash
cd api
DATABASE_URL=sqlite:///./test.db JWT_SECRET=test SCANNER_API_KEY=test ADMIN_USERNAME=admin ADMIN_PASSWORD=test \
  pytest app/tests -v
```

Se ejecutan automáticamente en cada push/PR a `main` vía GitHub Actions (ver badge arriba). Corren contra una
base de datos SQLite aislada — nunca tocan los datos reales de Postgres.

## Roadmap

- [x] Fase 1: core (BBDD, API, escáner básico, dashboard, login)
- [x] Fase 2: cruce con CVEs (NVD), verificación de exploits públicos (CISA KEV), timeline de cambios, priorización top-5
- [x] Fase 3: credenciales por defecto (SSH/FTP/HTTP Basic), fingerprinting de fabricante por MAC, rutas de ataque
- [x] Fase 4: reportes PDF programados (semanal). Asistente de chat pendiente — necesita una API key de Anthropic propia del proyecto (no incluida por decisión del alumno)
- [x] Fase 5: cruce exacto por CPE contra NVD, escaneo autenticado por SSH, lista de credenciales por defecto ampliada, verificación no destructiva de PoC en equipos de prácticas, plazos de remediación (SLA) por severidad, alertas por email además de webhook, cifrado en reposo de credenciales guardadas
- [x] Fase 6: etiquetado de equipos y riesgo agregado por grupo (unidad de negocio, entorno, ubicación)
- [x] Fase 7: claves API de solo lectura para integraciones externas, resumen periódico automático por email/webhook
- [x] Fase 8: rol "analista" (RBAC de tres niveles) y gestión de usuarios desde el dashboard
- [x] Fase 9: enrutado de alertas por etiqueta (webhook/email propio por unidad de negocio, entorno o ubicación)

## Precisión del cruce con NVD

Cuando nmap identifica un CPE de servicio con versión concreta (`-sV` suele incluirlo en su XML), el enricher
convierte ese CPE 2.2 al formato 2.3 y consulta la API de NVD con `cpeName` + `isVulnerable=true` — esto compara
contra las condiciones de aplicabilidad reales de cada CVE, no contra texto libre. Cuando nmap no logra determinar
un CPE fiable (banner genérico, versión ambigua o desconocida), se recurre a búsqueda por palabra clave
(nombre + versión) como respaldo, menos precisa. Cada CVE mostrado en el dashboard indica cuál de los dos
métodos se usó (`CPE exacto` / `aprox.`), para que la confianza del hallazgo sea transparente en vez de implícita.

## Escaneo autenticado

Para equipos donde un administrador ha guardado credenciales SSH (las mismas que usa el parcheo automático), el
escáner ya no se conforma con el banner de red: se conecta por SSH y consulta con `dpkg-query` la versión EXACTA
instalada del paquete (operación de solo lectura, sin privilegios). Esa versión verificada sustituye a la que
adivinó nmap, y se usa también para corregir el componente de versión del CPE — conservando el vendor/producto
que nmap ya suele identificar bien — lo que a su vez mejora la precisión del cruce con NVD descrito arriba. Cada
hallazgo indica si su versión viene de "red" (fingerprinting) o está "verificado" (confirmado por SSH en el
propio equipo). Solo se intenta en equipos con credenciales guardadas explícitamente; nunca por defecto.

## Credenciales por defecto

La lista genérica (~23 pares muy documentados en el sector) se complementa con credenciales específicas por
fabricante — Ubiquiti, Hikvision, Dahua, D-Link, Netgear, TP-Link, Cisco, MikroTik, etc. — que se prueban
primero cuando el fingerprinting por MAC ya identificó el fabricante del equipo, igual que haría un atacante
real que reconoce el dispositivo antes de improvisar. Sigue sin ser un diccionario de fuerza bruta: es una
lista curada y acotada, pensada para ser rápida y respetuosa con los dispositivos de la red. También se
añadió Telnet (puerto 23) — el vector clásico de credenciales por defecto en routers/cámaras/DVRs baratos
(el mismo que explotó la botnet Mirai) — aunque, a diferencia de SSH/FTP, Telnet no tiene una señal formal de
éxito/fallo en el protocolo, así que esa comprobación es heurística (reconoce patrones de prompt típicos) y
por tanto algo menos fiable por naturaleza del propio protocolo, no por una limitación de la implementación.

## Verificación de exploits (PoC)

Para equipos marcados explícitamente por un administrador como "de prácticas" (nunca por defecto), el dashboard
permite reverificar en vivo un hallazgo ya existente: reintentar un login con credenciales por defecto ya
encontradas, o releer la cabecera de un servicio HTTP para confirmar si sigue anunciando la versión vulnerable.
Ambas comprobaciones son reales (conexión de red genuina, no simulada) pero deliberadamente no destructivas —
no se explota ninguna vulnerabilidad de ejecución de código, solo se confirma o descarta lo ya detectado. Cada
intento queda registrado (qué, cuándo, quién, resultado) en un log de auditoría, igual que el parcheo automático.

## Plazos de remediación (SLA)

Cada vulnerabilidad detectada recibe automáticamente una fecha límite de remediación según su severidad
(configurable por un administrador; por defecto 7/30/90/180 días para crítica/alta/media/baja, en línea con
prácticas habituales de PCI-DSS / ISO 27001). El plazo se fija en el momento de la detección (o reapertura) y
no se mueve retroactivamente si la política cambia después. El dashboard muestra qué está fuera de plazo y qué
vence en los próximos días — la vista que un responsable de cumplimiento revisaría antes de una auditoría.

## Alertas por email

Además del webhook saliente (Discord/Slack), las mismas alertas (vulnerabilidad crítica con exploit conocido,
credenciales por defecto encontradas, parche aplicado, cuenta bloqueada) pueden enviarse por email vía SMTP.
Ambos canales son independientes y opcionales; cada intento de envío queda registrado en el historial de
alertas con su canal y resultado, se haya entregado o no.

## Resumen periódico

Cada vez que el servicio `reporter` genera el reporte PDF (por defecto, semanal), dispara además un resumen
corto por los mismos canales (webhook/email): equipos monitorizados, vulnerabilidades nuevas y resueltas en
los últimos 7 días, cuántas están fuera de plazo (SLA) ahora mismo, y credenciales por defecto encontradas.
Es el recordatorio que te llega al buzón sin tener que entrar al dashboard — también se puede disparar a mano
desde la vista de Alertas para probarlo.

## Roles de equipo

Tres roles, pensados para que la herramienta la use un equipo y no solo una persona: **administrador** (todo,
incluida la configuración — políticas, credenciales, claves API, usuarios), **analista** (el día a día —
reconocer y parchear vulnerabilidades, verificar PoC — sin poder tocar configuración ni gestionar el equipo) y
**visor** (solo lectura). Un administrador crea y elimina usuarios desde la vista "Usuarios"; las contraseñas
se guardan con el mismo hash bcrypt que ya usaba la cuenta inicial, nunca en texto plano.

## Grupos y etiquetas

Un administrador puede etiquetar cada equipo (por ejemplo "producción", "finanzas", "sede-madrid" — un equipo
puede tener varias) desde el Inventario. La vista de Grupos agrega el riesgo (puntuación total y media,
vulnerabilidades abiertas, credenciales encontradas) por etiqueta, para poder responder preguntas como "¿cuál
es el riesgo de los equipos de producción?" sin tener que revisar equipo por equipo — el tipo de vista que
esperaría un responsable de una unidad de negocio, no solo el equipo técnico.

Cada etiqueta puede tener además su propio webhook y/o email de destino (vista Grupos → "Alertas por
etiqueta"). No sustituye a los canales globales — los complementa: el admin sigue viendo todas las alertas,
y quien reciba el canal de "producción" recibe solo las suyas, sin ruido del resto de la red.

## Limitaciones conocidas

- Las "rutas de ataque" asumen red plana (sin VLANs/segmentación) ya que no se detecta topología de red más allá de la subred local.
- El escaneo autenticado verifica la versión de servicios que nmap ya detectó en la red (vía `dpkg-query`); no hace un inventario completo de todos los paquetes instalados en el sistema, solo de los que corresponden a servicios expuestos.
- La verificación de PoC es intencionadamente no destructiva y solo opera sobre equipos marcados como "de prácticas": el sistema no explota vulnerabilidades de ejecución de código ni intenta ganar acceso más allá de credenciales ya encontradas. El resto de hallazgos se reportan por coincidencia contra bases de datos públicas (NVD, CISA KEV), sin confirmación de explotabilidad real.
