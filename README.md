# Proyecto Cyber — Escáner de vulnerabilidades de red

Plataforma de gestión de vulnerabilidades para la red local: descubre equipos, identifica software y versiones en ejecución, cruza contra vulnerabilidades conocidas y expone los resultados en un dashboard web.

## Arquitectura

- **db** — PostgreSQL, almacena inventario de equipos, software detectado y vulnerabilidades.
- **api** — FastAPI, expone endpoints de consulta, autenticación con roles (admin/viewer) y recibe los resultados del escáner.
- **scanner** — Python + nmap, descubre equipos en la red local (`network_mode: host`) y envía los resultados a la API.
- **dashboard** — servido por la propia API (plantillas Jinja2), muestra el inventario en tiempo real.

## Uso

```bash
cp .env.example .env   # editar con valores propios
docker compose up -d --build
```

Dashboard disponible en `http://<ip-vm>:8000`.

## Roadmap

- [x] Fase 1: core (BBDD, API, escáner básico, dashboard, login)
- [ ] Fase 2: cruce con CVEs (NVD), verificación de exploits públicos, timeline de cambios, priorización
- [ ] Fase 3: credenciales por defecto, fingerprinting de IoT, rutas de ataque
- [ ] Fase 4: asistente de chat, reportes programados
