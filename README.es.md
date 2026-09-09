# Scalp! — Analizador de Ataques en Logs de Apache

[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](#-licencia) [![Python](https://img.shields.io/badge/python-3-green.svg)](https://www.python.org) [![Upstream](https://img.shields.io/badge/upstream-nanopony%2Fapache--scalp-orange.svg)](https://github.com/nanopony/apache-scalp) [![Author](https://img.shields.io/badge/autor%20original-Romain%20Gaucher-orange.svg)](http://rgaucher.info) [![Maintainer](https://img.shields.io/badge/mantenido%20por-DragonJAR%20SAS-blue.svg)](https://www.DragonJAR.org) [![English](https://img.shields.io/badge/read%20in-English-blue.svg)](README.md)

> Scalp! es un analizador de logs para servidores web Apache que busca en logs de acceso de gran tamaño patrones de ataque enviados vía HTTP GET/POST, usando las expresiones regulares de alta calidad del [proyecto PHPIDS](https://github.com/PHPIDS/PHPIDS).

Este repositorio es una **modernización del fork de [Nanopony](https://github.com/nanopony/apache-scalp)** de la herramienta original Scalp! de Romain Gaucher. Nosotros solo la mantenemos viva: compatibilidad con Python 3, archivo de filtros actualizado y correcciones de mantenimiento. Todo el crédito de la herramienta y su evolución es de los autores originales.

## 🎯 Qué Hace

- Escanea los logs de acceso de Apache línea por línea y los compara contra el set de expresiones regulares `default_filter.xml` de PHPIDS.
- Detecta y clasifica ataques: XSS, inyección SQL, CSRF, DoS, directory traversal, spam, divulgación de información, referencia a archivos remotos y local file inclusion.
- Reporta cada coincidencia con su regla, puntaje de impacto, descripción y tags.
- Incluye el módulo heurístico **Anathema** (de Nanopony) para scoring de ataques por comportamiento.
- Genera resultados en TEXT, XML o HTML.

## 📦 Instalación

```bash
git clone https://github.com/DragonJAR/apache-scalp
cd apache-scalp
pip install -r requirements.txt
```

## ⚙️ Requisitos

| Herramienta | Propósito |
|------|---------|
| Python 3 | Runtime |
| `regex` (ver `requirements.txt`) | Motor de expresiones regulares avanzado |
| Log de acceso de Apache | Datos de entrada |
| `default_filter.xml` (incluido) | Firmas de ataque de PHPIDS |

El archivo de filtros viene incluido en este repositorio. Si falta, Scalp! lo descarga automáticamente desde el [proyecto PHPIDS](https://github.com/PHPIDS/PHPIDS/blob/master/lib/IDS/default_filter.xml).

## 🚀 Uso

```bash
python3 scalp/scalp.py -l /var/log/apache2/access.log -f default_filter.xml -o ./scalp-output --html
```

```text
Scalp the apache log! by Romain Gaucher
usage:  ./scalp.py [--log|-l log_file] [--filters|-f filter_file] [--period time-frame] [OPTIONS] [--attack a1,a2,..,an]
                   [--sample|-s 4.2]
   --log       |-l:  el archivo de log de Apache './access_log' por defecto
   --filters   |-f:  el archivo de filtros './default_filter.xml' por defecto
   --exhaustive|-e:  reporta todos los tipos de ataques detectados sin detenerse en el primero
   --tough     |-u:  intenta decodificar los vectores de ataque potenciales (puede aumentar el tiempo de análisis)
   --period    |-p:  el período se especifica en el mismo formato de los logs de Apache usando * como wild-card
                     ej: 04/Apr/2008:15:45;*/Mai/2008
   --html      |-h:  genera una salida HTML
   --xml       |-x:  genera una salida XML
   --text      |-t:  genera una salida de texto simple (por defecto)
   --except    |-c:  genera un archivo con los logs no examinados (logs mal formados, etc.)
   --attack    |-a:  especifica la lista de ataques a buscar
                     lista: xss, sqli, csrf, dos, dt, spam, id, ref, lfi
                     ej: xss,sqli,lfi,ref
   --ignore-ip|-i:  lista de direcciones IP a excluir (separadas por coma)
   --ignore-subnet|-n:  lista de subredes a excluir (separadas por coma)
   --output    |-o:  directorio de salida; por defecto, scalp intenta escribir en el mismo
                     directorio del archivo de log
   --sample    |-s:  usa una muestra aleatoria de líneas; el número (float en [0,100]) es el
                     porcentaje, ej: --sample 0.1 para 1/1000
```

### Clases de Ataques

| Flag | Clase de ataque |
|------|--------------|
| `xss` | Cross-site scripting |
| `sqli` | Inyección SQL |
| `csrf` | Cross-site request forgery |
| `dos` | Denegación de servicio |
| `dt` | Directory traversal |
| `spam` | Spam |
| `id` | Divulgación de información |
| `ref` | Referencia a archivos remotos |
| `lfi` | Local file inclusion |

## 🧠 Módulo Heurístico Anathema

El paquete `anathema/` agrega una capa heurística (de Nanopony) que puntúa las peticiones más allá del matching por regex, analizando patrones de IP, método, URL y user-agent contra una base de firmas en JSON.

## ⚠️ Limitaciones

1. **Apache no registra los cuerpos POST por defecto** — la detección de ataques se basa principalmente en GET, salvo que tu formato de log capture los cuerpos de las peticiones.
2. **Detección basada en regex** — payloads sofisticados u ofuscados pueden evadir el matching; usa `--tough` para decodificar vectores codificados.
3. **Código heredado** — la herramienta nació en 2008 (era Python 2); este fork parchea la compatibilidad con Python 3, pero el motor sigue siendo simple por diseño.
4. **Suposiciones sobre el formato del log** — formatos de log de Apache no estándar pueden no parsear correctamente.

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
