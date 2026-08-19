# Proyecto Cyber — Escáner de vulnerabilidades de red

[![Tests](https://github.com/MrAlbondigas/-proyecto-cyber/actions/workflows/tests.yml/badge.svg)](https://github.com/MrAlbondigas/-proyecto-cyber/actions/workflows/tests.yml)

Plataforma de gestión de vulnerabilidades para la red local: descubre equipos, identifica software y versiones en ejecución, cruza contra vulnerabilidades conocidas y expone los resultados en un dashboard web.

## Arquitectura

- **db** — PostgreSQL, almacena inventario de equipos, software detectado y vulnerabilidades.
- **api** — FastAPI, expone endpoints de consulta, autenticación con roles (admin/viewer) y recibe los resultados del escáner.
- **scanner** — Python + nmap, descubre equipos en la red local (`network_mode: host`) y envía los resultados a la API.
- **enricher** — cruza cada software detectado con la API de NVD (CVEs) y el catálogo CISA KEV (exploits activamente explotados).
- **credcheck** — prueba una lista corta de credenciales por defecto muy conocidas contra SSH/FTP/HTTP Basic Auth expuestos.
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

## Precisión del cruce con NVD

Cuando nmap identifica un CPE de servicio con versión concreta (`-sV` suele incluirlo en su XML), el enricher
convierte ese CPE 2.2 al formato 2.3 y consulta la API de NVD con `cpeName` + `isVulnerable=true` — esto compara
contra las condiciones de aplicabilidad reales de cada CVE, no contra texto libre. Cuando nmap no logra determinar
un CPE fiable (banner genérico, versión ambigua o desconocida), se recurre a búsqueda por palabra clave
(nombre + versión) como respaldo, menos precisa. Cada CVE mostrado en el dashboard indica cuál de los dos
métodos se usó (`CPE exacto` / `aprox.`), para que la confianza del hallazgo sea transparente en vez de implícita.

## Limitaciones conocidas

- La detección de credenciales por defecto usa una lista corta (~10 pares) de credenciales muy conocidas, no un diccionario de fuerza bruta — pensado para ser rápido y respetuoso con los dispositivos de la red, no exhaustivo.
- Las "rutas de ataque" asumen red plana (sin VLANs/segmentación) ya que no se detecta topología de red más allá de la subred local.
- No hay escaneo autenticado (login remoto para comprobar versiones exactas de paquetes instalados) más allá del parcheo por SSH ya implementado — el descubrimiento de software sigue siendo por fingerprinting de red (banners, puertos), no por inventario de paquetes.
- Ningún hallazgo de vulnerabilidad se verifica activamente explotándolo — el sistema reporta coincidencias contra bases de datos públicas (NVD, CISA KEV), no confirmación de explotabilidad real.
