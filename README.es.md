# Scalp! — Analizador de Ataques en Logs de Apache

[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](#-licencia) [![Python](https://img.shields.io/badge/python-3-green.svg)](https://www.python.org) [![Upstream](https://img.shields.io/badge/upstream-nanopony%2Fapache--scalp-orange.svg)](https://github.com/nanopony/apache-scalp) [![Author](https://img.shields.io/badge/autor%20original-Romain%20Gaucher-orange.svg)](http://rgaucher.info) [![Maintainer](https://img.shields.io/badge/mantenido%20por-DragonJAR%20SAS-blue.svg)](https://www.DragonJAR.org) [![English](https://img.shields.io/badge/read%20in-English-blue.svg)](README.md)

> Scalp! es un analizador de logs para servidores web Apache que busca en logs de acceso de gran tamaño patrones de ataque enviados vía HTTP GET/POST, usando las expresiones regulares de alta calidad del [proyecto PHPIDS](https://github.com/PHPIDS/PHPIDS).

Este repositorio es una **modernización del fork de [Nanopony](https://github.com/nanopony/apache-scalp)** de la herramienta original Scalp! de Romain Gaucher. Nosotros solo la mantenemos viva: compatibilidad con Python 3, archivo de filtros actualizado y correcciones de mantenimiento. Todo el crédito de la herramienta y su evolución es de los autores originales.

## 🎯 Qué Hace

- Escanea logs de acceso de Apache y Nginx línea por línea contra las reglas `default_filter.xml` de PHPIDS y firmas modernas en JSON.
- Soporta logs en **texto plano y comprimidos con gzip (`.gz`)** de forma totalmente transparente.
- Inspecciona **múltiples vectores HTTP**: URL de la petición, cabecera `User-Agent` y cabecera `Referer`, registrando la procedencia del vector.
- Soporta tráfico **HTTP/1.0, HTTP/1.1, HTTP/2 y HTTP/3**, IPv4, IPv6 (incluyendo `[::1]`), nombres de host y puertos.
- Detecta y clasifica el espectro completo de ataques web de forma predeterminada (clásicos y modernos):
  - **Ataques Web Clásicos**: XSS, inyección SQL, CSRF, DoS, directory traversal, spam, divulgación de información, ejecución de archivos remotos (`rfe`/`ref`) y local file inclusion (`lfi`).
  - **NoSQL Injection**: Operadores BSON de MongoDB/CouchDB (`$ne`, `$gt`, `$where`, `$regex`).
  - **Prototype Pollution**: Manipulación de prototipos en JavaScript/Node.js (`__proto__`, `constructor.prototype`).
  - **CRLF Injection**: Envenenamiento y división de cabeceras HTTP (`%0d%0aSet-Cookie:`, `Location:`).
  - **Inyección de Comandos OS y Shellshock**: Sintaxis de shell (`() { :; };`, `$(...)`, encadenamiento `;`, `|`, `&`).
  - **SSRF**: Metadatos cloud (AWS, GCP, Azure, Alibaba, Oracle) con evasiones de IP decimal, hexadecimal y octal.
  - **Log4Shell/JNDI**: Inyección y variantes ofuscadas (`${jndi:...}`).
  - **SSTI y Spring4Shell**: Explotación de motores de plantillas y ClassLoader.
  - **Sondeos y Reconocimiento**: `.env`, `.git`, endpoints Actuator y Swagger UI / GraphQL.
- Decodificador anti-evasión multicapa: desescape URL recursivo, entidades HTML, normalización Unicode NFKC (conversión de caracteres fullwidth), eliminación de bytes de control y extracción/decodificación de payloads Base64.
- Priorización por severidad de impacto (10 a 0) para destacar exploits críticos.
- Correlación con códigos de respuesta HTTP (resaltando ejecuciones potenciales `200/500` vs bloqueos `404/403`).
- Incluye el módulo heurístico integrado **Anathema** (`--anathema`) para scoring de ataques por comportamiento y seguimiento de IPs maliciosas.
- Genera resultados en TEXT, XML, HTML5 moderno responsivo o JSON (para SIEM y pipelines de CI/CD).

## 📦 Instalación

```bash
git clone https://github.com/DragonJAR/apache-scalp
cd apache-scalp
pip install -r requirements.txt
```

## ⚙️ Requisitos

| Herramienta | Propósito |
|------|---------|
| Python 3.10+ | Runtime |
| `regex` (ver `requirements.txt`) | Motor de expresiones regulares avanzado |
| Log de acceso de Apache / Nginx (`.log`, `.txt` o `.gz`) | Datos de entrada |
| `default_filter.xml` (incluido) | Firmas de ataque integradas |
| `scalp/rules/modern_rules.json` (incluido) | Firmas de ataque modernas |

El archivo de filtros viene incluido en este repositorio. Si falta, Scalp! lo descarga automáticamente desde el [proyecto PHPIDS](https://github.com/PHPIDS/PHPIDS/blob/master/lib/IDS/default_filter.xml).

## 🚀 Uso

Ejecución directa desde el directorio raíz:

```bash
python3 scalp.py -l /var/log/apache2/access.log -f default_filter.xml -o ./scalp-output --html --anathema
```

O probar inmediatamente con el log de ejemplo multi-aplicación incluido:

```bash
python3 scalp.py -l examples/example.log -f default_filter.xml -o ./scalp-output --html --json --anathema
```

O analizando logs rotados y comprimidos con gzip:

```bash
python3 scalp.py -l /var/log/nginx/access.log.1.gz -o ./scalp-output --json
```

```text
usage: scalp [--help] [-V] [-l LOG] [-f FILTERS] [-o OUTPUT] [-h] [-x] [-t]
             [--json] [-a ATTACK] [-p PERIOD] [-s SAMPLE] [-i IGNORE_IP]
             [-n IGNORE_SUBNET] [-e] [-u] [-c] [--anathema]

Scalp! Apache/Nginx attack analyzer based on PHPIDS and modern signatures.

options:
  --help                Muestra este mensaje de ayuda y sale.
  -V, --version         Muestra la versión instalada.
  -l, --log LOG         Ruta al archivo de log de Apache/Nginx (soporta archivos .gz)
  -f, --filters FILTERS Ruta al archivo de filtros (XML o JSON)
  -o, --output OUTPUT   Directorio donde escribir los reportes (por defecto: directorio actual)
  -h, --html            Genera un reporte en HTML5 responsivo
  -x, --xml             Genera un reporte en formato XML
  -t, --text            Genera un reporte en texto plano
  --json                Genera un reporte estructurado en JSON
  -a, --attack ATTACK   Lista de tipos de ataque a buscar (ej: xss,sqli,lfi,ssrf,log4j,nosql,rce)
  -p, --period PERIOD   Rango de fechas a analizar (ej: '04/Apr/2024:15:45;10/May/2024:23:59')
  -s, --sample SAMPLE   Porcentaje de muestra de líneas a analizar (0.0 a 100.0, por defecto: 100.0)
  -i, --ignore-ip IGNORE_IP
                        Lista de direcciones IP a excluir (separadas por coma)
  -n, --ignore-subnet IGNORE_SUBNET
                        Lista de subredes/CIDR a excluir (ej: 192.168.1.0/24)
  -e, --exhaustive      Reporta todas las coincidencias por línea en vez de parar en la primera
  -u, --tough           Habilita decodificación profunda anti-evasión (habilitado por defecto)
  -c, --except          Guarda líneas no parseadas en scalp_except.txt
  --anathema            Habilita el módulo de análisis heurístico y comportamiento Anathema
```

### Clases de Ataques

| Flag | Clase de ataque | Descripción |
|------|-----------------|-------------|
| `xss` | Cross-site scripting | Inyección de scripts ejecutables en navegador y etiquetas HTML |
| `sqli` | Inyección SQL | Manipulación sintáctica SQL, inyección de comentarios, blind booleano |
| `nosql` | Inyección NoSQL | Operadores BSON de MongoDB/CouchDB (`$ne`, `$where`, `$regex`, `$gt`) |
| `pollution` | Prototype pollution | Inyección de propiedades y prototipos en JavaScript (`__proto__`) |
| `crlf` | Inyección CRLF | División de respuestas HTTP e inyección de cabeceras (`%0d%0a`) |
| `rce` / `cmd` | Ejecución de comandos | Sintaxis de shell (`() { :; };`, `$(...)`, encadenamiento `;`, `|`, `&`) |
| `csrf` | Cross-site request forgery | Acciones no autorizadas en nombre de usuarios autenticados |
| `dos` | Denegación de servicio | Patrones pesados de agotamiento de recursos del servidor |
| `dt` | Directory traversal | Secuencias de escape de directorios (`../` y equivalentes URL-encoded) |
| `spam` | Spam | Bots de spam en formularios, libros de visitas y comentarios |
| `id` | Divulgación de información | Fugas de código fuente, tokens de servidor, endpoints de debug |
| `rfe` / `ref` | Ejecución de archivos remotos | Inyección de código, inclusiones remotas y lookups JNDI/Log4j |
| `lfi` | Local file inclusion | Lectura de archivos locales del servidor (passwd, shadow, config) |
| `ssrf` | Server-side request forgery | Acceso a metadatos cloud (AWS, GCP, Azure, Alibaba, Oracle) |
| `log4j` | Log4Shell | Lookups JNDI (`${jndi:ldap://...}`) y variantes ofuscadas |
| `ssti` | Inyección de plantillas | Ataques a motores Jinja2, Twig, Spring EL y Freemarker |
| `spring` | Spring4Shell | Explotación de ClassLoader y vectores de deserialización |
| `probe` | Sondeos y reconocimiento | Sondeos a `.env`, `.git`, endpoints Actuator y Swagger UI |

## 🧪 Pruebas Automatizadas

Ejecutá la suite completa con pytest (73 pruebas unitarias y de integración que validan el parser, normalizador, motor de reglas, heurística y reporteros):

```bash
pytest
```

## 🧠 Módulo Heurístico Anathema

El paquete `anathema/` y la opción `--anathema` activan la capa heurística basada en comportamiento (creada por Nanopony y modernizada por DragonJAR) que analiza el tráfico detectando patrones de escáneres web, sondas sospechosas y rastreo de IPs reincidentes.

## ⚠️ Limitaciones

1. **Apache no registra los cuerpos POST por defecto** — la detección se basa principalmente en la línea de petición y la query string, a menos que el formato de log capture el body.
2. **Detección basada en regex** — payloads altamente personalizados pueden evadir firmas fijas; el normalizador anti-evasión se ejecuta automáticamente para mitigar ofuscaciones.
3. **Formatos de log soportados** — soporta de forma nativa los formatos estándar CLF, Combined, VHost Combined y Nginx.

## 🏛️ Historia y Créditos

Esta herramienta se apoya en el trabajo de otros:

- **[Romain Gaucher](http://rgaucher.info)** — autor original de Scalp! (2008), hospedado en el proyecto original de Google Code.
- **[Nanopony](https://github.com/nanopony/apache-scalp)** — mantuvo y modernizó el proyecto: port a Python 3, el módulo heurístico Anathema y el desarrollo continuo tras el cierre de Google Code.
- **[Equipo PHPIDS](https://github.com/PHPIDS/PHPIDS)** — las expresiones regulares de `default_filter.xml` que alimentan el motor de detección.
- **[DragonJAR SAS](https://www.DragonJAR.org)** — mantenimiento actual: dependencias y archivo de filtros actualizados, documentación y que la herramienta siga siendo usable.

## 📄 Licencia

Apache License 2.0 — heredada del proyecto original.

## 👨‍💻 Mantenedor

**DragonJAR SAS** — [https://www.DragonJAR.org](https://www.DragonJAR.org)

[Expertos en servicios de seguridad informática, validación proactiva y seguridad ofensiva.](https://www.dragonjar.org/servicios-de-seguridad-informatica)
