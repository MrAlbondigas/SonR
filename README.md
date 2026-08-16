# Proyecto Cyber — Escáner de vulnerabilidades de red

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

## Roadmap

- [x] Fase 1: core (BBDD, API, escáner básico, dashboard, login)
- [x] Fase 2: cruce con CVEs (NVD), verificación de exploits públicos (CISA KEV), timeline de cambios, priorización top-5
- [x] Fase 3: credenciales por defecto (SSH/FTP/HTTP Basic), fingerprinting de fabricante por MAC, rutas de ataque
- [x] Fase 4: reportes PDF programados (semanal). Asistente de chat pendiente — necesita una API key de Anthropic propia del proyecto (no incluida por decisión del alumno)

## Limitaciones conocidas

- El cruce con NVD usa búsqueda por palabra clave (nombre + versión), no CPE exacto — es rápido de implementar pero menos preciso que un matching formal. Trabajo futuro: migrar a matching CPE.
- La detección de credenciales por defecto usa una lista corta (~10 pares) de credenciales muy conocidas, no un diccionario de fuerza bruta — pensado para ser rápido y respetuoso con los dispositivos de la red, no exhaustivo.
- Las "rutas de ataque" asumen red plana (sin VLANs/segmentación) ya que no se detecta topología de red más allá de la subred local.
