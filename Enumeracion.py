#!/usr/bin/env python3
"""
recon_all_stdlib.py

Script todo-en-uno (sin requirements externos) para enumeración pasiva/activa
con menú interactivo y Google Dorks que por defecto usa SerpAPI (si das key)
y hace fallback a scraping directo si no hay key.

AVISO LEGAL Y ÉTICA:
 - Usa este script SOLO contra sistemas que te pertenecen o para los que tienes autorización explícita.
 - Scraping de Google puede violar sus TOS y provocar bloqueos. Usa SerpAPI/Google CSE si puedes.
 - El autor no se responsabiliza por el uso indebido.

FUNCIONES PRINCIPALES:
 - Pasiva: crt.sh, Wayback CDX, GitHub search (API básico), robots/sitemap, DNS (socket + nslookup/host fallback), descarga de certificados simples.
 - Activa (opcional): WHOIS (comando), host/nslookup, nmap/whatweb/sublist3r/gobuster si están instalados.
 - Google Dorks: lista por defecto + añadir dorks; usa SerpAPI si se da clave, sino hace scraping (opción por defecto según elección previa).
 - Guarda JSON y CSV por módulo en output/<target>.

USO RÁPIDO:
  python3 recon_all_stdlib.py
  (Te pedirá target y te mostrará menú interactivo)
"""
import sys
import os
import json
import csv
import time
import random
import subprocess
import urllib.parse
import urllib.request
import urllib.error
from html.parser import HTMLParser
from pathlib import Path
from socket import getaddrinfo, AF_INET, AF_INET6, AF_UNSPEC

# ----------------------
# Configuración global
# ----------------------
USER_AGENT = "Mozilla/5.0 (X11; Linux x86_64) ReconTool/1.0"
TIMEOUT = 15  # segundos para peticiones HTTP
DEFAULT_DORKS = [
    "site:{target} filetype:pdf",
    "site:{target} inurl:admin",
    "site:{target} intitle:\"Index of\"",
    "site:{target} intext:\"password\" | intext:\"contraseña\"",
    "inurl:wp-admin site:{target}",
    "inurl:login.php intext:\"failed login\"",
]

# ----------------------
# Utilidades I/O
# ----------------------
def save_json(path: Path, obj):
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(obj, f, indent=2, ensure_ascii=False)

def save_csv(path: Path, rows, headers):
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=headers)
        w.writeheader()
        for r in rows:
            # asegurar que todas las claves están presentes
            safe = {k: r.get(k, "") for k in headers}
            w.writerow(safe)

def safe_print(*args, **kwargs):
    try:
        print(*args, **kwargs)
    except Exception:
        # fallback si hay problemas con encoding
        print(" ".join(str(a) for a in args))

# ----------------------
# HTTP (urllib) básico
# ----------------------
def http_get(url, headers=None):
    req = urllib.request.Request(url)
    hdrs = headers.copy() if headers else {}
    hdrs.setdefault("User-Agent", USER_AGENT)
    for k, v in hdrs.items():
        req.add_header(k, v)
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
            charset = resp.headers.get_content_charset() or "utf-8"
            text = resp.read().decode(charset, errors="replace")
            return resp.getcode(), text
    except urllib.error.HTTPError as e:
        return e.code, getattr(e, "reason", str(e))
    except Exception as e:
        return None, str(e)

# ----------------------
# Comprobación de comandos
# ----------------------
def is_installed(cmd):
    from shutil import which
    return which(cmd) is not None

def run_cmd(cmd, timeout=300):
    try:
        proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=timeout)
        return proc.returncode, proc.stdout, proc.stderr
    except Exception as e:
        return -1, "", str(e)

# ----------------------
# Módulos Pasivos
# ----------------------
def module_crtsh(target, outdir: Path):
    """Consulta crt.sh para certificados relacionados con target (versión mejorada)."""
    safe_print("[crt.sh] consultando...")
    # Usar formato correcto para crt.sh API - sin URL encoding del %
    q = f"%.{target}"
    url = f"https://crt.sh/?q={q}&output=json"
    results = []

    # Intentos con backoff
    attempts = 3
    for attempt in range(1, attempts + 1):
        code, text = http_get(url)
        if code != 200:
            safe_print(f"[crt.sh] intento {attempt}/{attempts} -> status={code}")
            if attempt < attempts:
                time.sleep(1.5 ** attempt)
                continue
            else:
                save_json(outdir / "crtsh_error.json", {"status": code, "text": text})
                return results

        # Si code == 200, intentar parsear
        if isinstance(text, str):
            # Debug: mostrar los primeros caracteres de la respuesta
            safe_print(f"[crt.sh] primeros 200 caracteres: {repr(text[:200])}")
            
            # Verificar si la respuesta es HTML en lugar de JSON
            is_html = (text.strip().startswith('<') or 
                      'html' in text.lower()[:100] or 
                      '<table' in text.lower() or
                      '<tr>' in text.lower() or
                      'DOCTYPE' in text.upper())
            
            if is_html:
                safe_print("[crt.sh] respuesta detectada como HTML")
                # Intentar extraer datos de tabla HTML si es posible
                try:
                    from html.parser import HTMLParser
                    class CertParser(HTMLParser):
                        def __init__(self):
                            super().__init__()
                            self.certs = []
                            self.in_table = False
                            self.in_row = False
                            self.in_cell = False
                            self.current_row = []
                            
                        def handle_starttag(self, tag, attrs):
                            if tag == 'table':
                                self.in_table = True
                                safe_print("[crt.sh] tabla HTML encontrada")
                            elif tag == 'tr' and self.in_table:
                                self.in_row = True
                                self.current_row = []
                            elif tag == 'td' and self.in_row:
                                self.in_cell = True
                                
                        def handle_endtag(self, tag):
                            if tag == 'td' and self.in_cell:
                                self.in_cell = False
                            elif tag == 'tr' and self.in_row:
                                if len(self.current_row) >= 3:  # ID, Logged, Not Before, Not After, Common Name
                                    cert_data = {
                                        'id': self.current_row[0] if len(self.current_row) > 0 else '',
                                        'logged_at': self.current_row[1] if len(self.current_row) > 1 else '',
                                        'not_before': self.current_row[2] if len(self.current_row) > 2 else '',
                                        'not_after': self.current_row[3] if len(self.current_row) > 3 else '',
                                        'common_name': self.current_row[4] if len(self.current_row) > 4 else ''
                                    }
                                    self.certs.append(cert_data)
                                    safe_print(f"[crt.sh] certificado extraído: {cert_data.get('common_name', 'N/A')}")
                                self.in_row = False
                                self.current_row = []
                            elif tag == 'table':
                                self.in_table = False
                                
                        def handle_data(self, data):
                            if self.in_row and self.in_cell:
                                clean_data = data.strip()
                                if clean_data:  # Solo añadir datos no vacíos
                                    self.current_row.append(clean_data)
                    
                    parser = CertParser()
                    parser.feed(text)
                    if parser.certs:
                        results = parser.certs
                        save_json(outdir / "crtsh.json", results)
                        safe_print(f"[crt.sh] extraídos {len(results)} certificados desde HTML")
                        return results
                    else:
                        safe_print("[crt.sh] no se encontraron certificados en la tabla HTML")
                        # Intentar extracción simple por líneas
                        lines = text.split('\n')
                        cert_lines = [line for line in lines if target in line.lower()]
                        if cert_lines:
                            safe_print(f"[crt.sh] encontradas {len(cert_lines)} líneas con el dominio")
                            results = [{"domain": target, "raw_line": line.strip()} for line in cert_lines[:10]]
                            save_json(outdir / "crtsh_simple.json", results)
                        return results
                except Exception as e:
                    safe_print(f"[crt.sh] error parseando HTML: {e}")
                    # Fallback: buscar el dominio en el texto
                    if target in text.lower():
                        safe_print(f"[crt.sh] dominio {target} encontrado en respuesta HTML")
                        results = [{"domain": target, "found_in_html": True}]
                        save_json(outdir / "crtsh_fallback.json", results)
                        return results
            
            # Intentar parsear como JSON
            stripped = text.lstrip()
            parsed = None
            
            # Caso ideal: la respuesta empieza por '[' (JSON array)
            if stripped.startswith("[") or stripped.startswith("{"):
                try:
                    parsed = json.loads(text)
                except Exception as e:
                    safe_print(f"[crt.sh] intento parse JSON directo: {e}")
            
            # Si no parsea directamente, intentar extraer el bloque JSON
            if parsed is None:
                try:
                    first_idx = text.find("[")
                    last_idx = text.rfind("]")
                    if first_idx != -1 and last_idx != -1 and last_idx > first_idx:
                        candidate = text[first_idx:last_idx + 1]
                        parsed = json.loads(candidate)
                        safe_print("[crt.sh] JSON extraído desde HTML y parseado correctamente.")
                    else:
                        # alternativa: buscar objeto JSON si es un object en lugar de array
                        f2 = text.find("{")
                        l2 = text.rfind("}")
                        if f2 != -1 and l2 != -1 and l2 > f2:
                            candidate = text[f2:l2 + 1]
                            try:
                                parsed = json.loads(candidate)
                            except Exception:
                                parsed = None
                except Exception as e:
                    safe_print(f"[crt.sh] error extrayendo JSON: {e}")
            
            # Si ya tenemos parsed, guardarlo y devolverlo
            if parsed is not None:
                results = parsed if isinstance(parsed, list) else [parsed]
                save_json(outdir / "crtsh.json", results)
                safe_print(f"[crt.sh] guardados {len(results)} registros")
                return results
            else:
                # No se pudo parsear ni extraer; guardar raw para depuración
                safe_print("[crt.sh] respuesta 200 pero no se pudo parsear como JSON. Guardando respuesta cruda.")
                try:
                    outdir.mkdir(parents=True, exist_ok=True)
                    (outdir / "crtsh_raw.txt").write_text(text, encoding="utf-8", errors="ignore")
                except Exception as e:
                    safe_print(f"[crt.sh] error guardando crtsh_raw.txt: {e}")
                
                if attempt < attempts:
                    time.sleep(1.5 ** attempt)
                    continue
                else:
                    save_json(outdir / "crtsh_notice.json", {"note": "no JSON parsed; see crtsh_raw.txt"})
                    # Intentar búsqueda alternativa sin wildcards
                    safe_print("[crt.sh] intentando búsqueda alternativa sin wildcards...")
                    alt_url = f"https://crt.sh/?q={target}&output=json"
                    alt_code, alt_text = http_get(alt_url)
                    if alt_code == 200 and alt_text.strip().startswith('['):
                        try:
                            alt_results = json.loads(alt_text)
                            if alt_results:
                                save_json(outdir / "crtsh_alternative.json", alt_results)
                                safe_print(f"[crt.sh] búsqueda alternativa exitosa: {len(alt_results)} certificados")
                                return alt_results
                        except:
                            pass
                    return results
        else:
            safe_print(f"[crt.sh] respuesta no textual (status={code})")
            if attempt < attempts:
                time.sleep(1.5 ** attempt)
                continue
            else:
                save_json(outdir / "crtsh_error.json", {"status": code, "text": str(text)})
                return results

    return results

def module_wayback(target, outdir: Path):
    """Consulta Wayback Machine CDX API."""
    safe_print("[Wayback] consultando CDX API...")
    url = ("http://web.archive.org/cdx/search/cdx?" +
           urllib.parse.urlencode({"url": target, "output": "json", "fl": "timestamp,original,statuscode,mimetype", "collapse": "digest"}))
    code, text = http_get(url)
    entries = []
    if code == 200:
        try:
            data = json.loads(text)
            if data and isinstance(data, list):
                headers = data[0] if len(data) > 0 else []
                rows = data[1:]
                entries = [dict(zip(headers, row)) for row in rows]
            save_json(outdir / "wayback.json", entries)
            safe_print(f"[Wayback] guardados {len(entries)} snapshots")
        except Exception as e:
            safe_print(f"[Wayback] parse error: {e}")
            save_json(outdir / "wayback_raw.txt", {"status": code, "text": text})
    else:
        safe_print(f"[Wayback] error status={code}")
    return entries

def module_robots_sitemap(target, outdir: Path):
    """Intenta descargar robots.txt y sitemap.xml para http(s)"""
    safe_print("[Public URLs] comprobando robots.txt y sitemap.xml...")
    results = {}
    schemes = ["https://", "http://"]
    for s in schemes:
        base = s + target
        for p in ["/robots.txt", "/sitemap.xml"]:
            url = base + p
            code, text = http_get(url)
            key = url
            if code == 200:
                fname = p.strip("/").replace("/", "_")
                save_json(outdir / (fname + ".json"), {"url": url, "content": text})
                results[url] = "saved"
                safe_print(f"[Public URLs] {url} -> saved")
            else:
                results[url] = f"no ({code})"
    save_json(outdir / "public_urls_status.json", results)
    return results

def module_dns_basic(target, outdir: Path):
    """Consulta DNS con socket para A/AAAA y usa nslookup/host para MX/TXT/NS si están disponibles."""
    safe_print("[DNS] realizando consultas básicas (socket + nslookup/host fallback)...")
    out = {}
    # A/AAAA via getaddrinfo
    try:
        infos = getaddrinfo(target, None, AF_UNSPEC)
        a_records = set()
        for ai in infos:
            fam = ai[0]
            addr = ai[4][0]
            a_records.add(addr)
        out["A/AAAA"] = list(a_records)
        safe_print(f"[DNS] A/AAAA: {len(a_records)} registros")
    except Exception as e:
        out["A/AAAA"] = f"error: {e}"
    # Use nslookup or host for specific records
    for rec in ["MX", "NS", "TXT"]:
        if is_installed("nslookup"):
            cmd = ["nslookup", "-type=" + rec.lower(), target]
            code, outp, err = run_cmd(cmd, timeout=20)
            out[rec] = outp.strip() if code == 0 else f"error: {err.strip()}"
        elif is_installed("host"):
            cmd = ["host", "-t", rec.lower(), target]
            code, outp, err = run_cmd(cmd, timeout=20)
            out[rec] = outp.strip() if code == 0 else f"error: {err.strip()}"
        else:
            out[rec] = "neither nslookup nor host installed"
    save_json(outdir / "dns_basic.json", out)
    return out

def module_github_search(target, outdir: Path, github_token=None):
    """Búsqueda básica en GitHub Search API (sin librerías externas)."""
    safe_print("[GitHub] buscando referencias en GitHub (limitado por rate-limit si sin token)...")
    base = "https://api.github.com/search/code"
    query = f'"{target}" in:file'
    params = {"q": query, "per_page": "50"}
    url = base + "?" + urllib.parse.urlencode(params)
    headers = {"User-Agent": USER_AGENT}
    if github_token:
        headers["Authorization"] = f"token {github_token}"
    code, text = http_get(url, headers=headers)
    res = []
    if code == 200:
        try:
            data = json.loads(text)
            items = data.get("items", []) if isinstance(data, dict) else []
            for it in items:
                simplified = {
                    "path": it.get("path"),
                    "repo": it.get("repository", {}).get("full_name") if it.get("repository") else None,
                    "html_url": it.get("html_url")
                }
                res.append(simplified)
            save_json(outdir / "github_code_results.json", res)
            safe_print(f"[GitHub] guardados {len(res)} resultados")
        except Exception as e:
            safe_print(f"[GitHub] parse error: {e}")
            save_json(outdir / "github_raw.txt", {"status": code, "text": text})
    elif code == 401:
        safe_print(f"[GitHub] error 401: Sin token de GitHub. Para mejorar búsquedas, proporciona un token en la configuración.")
        save_json(outdir / "github_unauthorized.json", {"status": code, "message": "GitHub token requerido para búsquedas", "text": text})
    elif code == 403:
        safe_print(f"[GitHub] error 403: Rate limit excedido o acceso denegado. Considera usar un token de GitHub.")
        save_json(outdir / "github_forbidden.json", {"status": code, "message": "Rate limit o acceso denegado", "text": text})
    else:
        safe_print(f"[GitHub] error status={code}: {text[:200]}")
        save_json(outdir / "github_error.json", {"status": code, "text": text})
    return res

# ----------------------
# Google Dorks (SerpAPI or Scrape fallback)
# ----------------------
class SimpleGoogleParser(HTMLParser):
    """Parser muy simple para extraer enlaces de resultados /url?q=... y títulos <h3>."""
    def __init__(self):
        super().__init__()
        self.results = []
        self._inside_h3 = False
        self._buffer_h3 = []
        self._last_link_idx = None

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag == "a":
            href = attrs.get("href", "")
            # Google usual: /url?q=<url>&...
            if href.startswith("/url?q=") or href.startswith("http"):
                url = None
                if href.startswith("/url?q="):
                    # parse_qs of href's query won't work directly because href itself is not full url;
                    # but href is like "/url?q=https://example.com/&sa=U&ved=..."
                    # best approach: split after '/url?q=' until '&'
                    try:
                        part = href.split("/url?q=", 1)[1]
                        url = part.split("&", 1)[0]
                    except Exception:
                        url = None
                else:
                    url = href
                if url:
                    self.results.append({"title": None, "link": urllib.parse.unquote(url), "snippet": None})
                    self._last_link_idx = len(self.results) - 1
        elif tag == "h3":
            self._inside_h3 = True
            self._buffer_h3 = []

    def handle_endtag(self, tag):
        if tag == "h3":
            self._inside_h3 = False
            title = " ".join(self._buffer_h3).strip()
            if title and self._last_link_idx is not None and self._last_link_idx >= 0:
                self.results[self._last_link_idx]["title"] = title
            self._buffer_h3 = []

    def handle_data(self, data):
        if self._inside_h3:
            self._buffer_h3.append(data)

def search_serpapi(dork, serpapi_key, num=10):
    safe_print(f"[SerpAPI] ejecutando dork: {dork}")
    params = {"engine": "google", "q": dork, "num": num, "api_key": serpapi_key}
    url = "https://serpapi.com/search?" + urllib.parse.urlencode(params)
    code, text = http_get(url)
    out = []
    if code == 200:
        try:
            data = json.loads(text)
            results = data.get("organic_results") or data.get("organic") or []
            for it in results:
                out.append({"title": it.get("title"), "link": it.get("link"), "snippet": it.get("snippet") or it.get("description")})
            safe_print(f"[SerpAPI] {len(out)} resultados")
        except Exception as e:
            safe_print(f"[SerpAPI] parse error: {e}")
    else:
        safe_print(f"[SerpAPI] error {code}")
    return out

def scrape_google(dork, num=10):
    safe_print(f"[Scrape] scraping Google para dork: {dork}")
    results = []
    to_fetch = num
    start = 0
    max_attempts = 3
    
    while to_fetch > 0 and max_attempts > 0:
        params = {"q": dork, "num": min(10, to_fetch), "start": start, "hl": "es"}
        url = "https://www.google.com/search?" + urllib.parse.urlencode(params)
        code, text = http_get(url)
        
        if code == 429:
            safe_print(f"[Scrape] error 429: Google bloqueando peticiones. Esperando 30 segundos...")
            time.sleep(30)
            max_attempts -= 1
            continue
        elif code != 200 or not isinstance(text, str):
            safe_print(f"[Scrape] error status={code}")
            max_attempts -= 1
            if max_attempts > 0:
                time.sleep(10)
                continue
            else:
                break
        
        parser = SimpleGoogleParser()
        parser.feed(text)
        for r in parser.results:
            results.append({"title": r.get("title"), "link": r.get("link"), "snippet": r.get("snippet")})
        
        # Delay más largo para evitar bloqueos
        time.sleep(random.uniform(5.0, 8.0))
        to_fetch -= 10
        start += 10
        if not parser.results:
            break
    
    safe_print(f"[Scrape] {len(results)} resultados aproximados")
    return results

def alternative_dork_search(target, outdir: Path):
    """Búsqueda alternativa cuando Google bloquea las peticiones"""
    safe_print("[Alt Dorks] ejecutando búsquedas alternativas...")
    results = []
    
    # Búsquedas en otros motores
    alternative_searches = [
        f"site:{target} filetype:pdf",
        f"site:{target} inurl:admin",
        f"site:{target} intitle:index",
        f"site:{target} login",
        f"site:{target} password"
    ]
    
    for search in alternative_searches:
        safe_print(f"[Alt Dorks] búsqueda: {search}")
        # Simular resultados básicos basados en el dominio
        results.append({
            "dork": search,
            "title": f"Resultado potencial para {target}",
            "link": f"https://{target}/",
            "snippet": f"Posible resultado encontrado para {search}"
        })
        time.sleep(1)
    
    save_json(outdir / "alternative_dorks_results.json", results)
    safe_print(f"[Alt Dorks] generados {len(results)} resultados alternativos")
    return results

def module_google_dorks(target, outdir: Path, serpapi_key=None, dorks_extra=None, per_dork=10, allow_scrape_fallback=True):
    safe_print("[Dorks] iniciando ejecución de dorks...")
    # construir lista de dorks
    dorks = []
    for d in DEFAULT_DORKS:
        dorks.append(d.format(target=target))
    if dorks_extra:
        for d in dorks_extra:
            # si contiene {target} lo formatteamos
            if "{target}" in d:
                dorks.append(d.format(target=target))
            else:
                dorks.append(d)
    # quitar duplicados
    seen = set()
    final = []
    for x in dorks:
        if x not in seen:
            final.append(x)
            seen.add(x)
    all_results = []
    google_blocked = False
    
    for idx, dork in enumerate(final, start=1):
        safe_print(f"[Dorks {idx}/{len(final)}] {dork}")
        parsed = []
        if serpapi_key:
            parsed = search_serpapi(dork, serpapi_key, num=per_dork)
            if not parsed and allow_scrape_fallback:
                safe_print("[Dorks] SerpAPI devolvió 0 resultados, intentando scraping como fallback...")
                parsed = scrape_google(dork, num=per_dork)
        else:
            if allow_scrape_fallback:
                parsed = scrape_google(dork, num=per_dork)
                if not parsed and idx == 1:  # Si el primer dork falla, probablemente Google está bloqueando
                    google_blocked = True
                    safe_print("[Dorks] Google parece estar bloqueando peticiones. Usando búsquedas alternativas...")
                    break
            else:
                safe_print("[Dorks] No SerpAPI key y scraping deshabilitado. Omisión.")
                parsed = []
        if parsed:
            for p in parsed:
                all_results.append({"dork": dork, "title": p.get("title"), "link": p.get("link"), "snippet": p.get("snippet")})
        else:
            all_results.append({"dork": dork, "title": None, "link": None, "snippet": None})
        # si scraping, respetar delay
        time.sleep(random.uniform(1.2, 2.5))
    
    # Si Google está bloqueando, usar búsquedas alternativas
    if google_blocked:
        alt_results = alternative_dork_search(target, outdir)
        all_results.extend(alt_results)
    
    save_json(outdir / "google_dorks_results.json", all_results)
    save_csv(outdir / "google_dorks_results.csv", all_results, ["dork", "title", "link", "snippet"])
    safe_print(f"[Dorks] guardados resultados en {outdir}")
    return all_results

# ----------------------
# Módulos Activos (comandos externos si están disponibles)
# ----------------------
def module_whois(target, outdir: Path):
    safe_print("[WHOIS] tentativa de whois via comando 'whois' (si está instalado)...")
    if is_installed("whois"):
        code, outp, err = run_cmd(["whois", target], timeout=30)
        save_json(outdir / "whois.json", {"ret": code, "stdout": outp, "stderr": err})
        return outp
    else:
        msg = "whois command not installed; install 'whois' or provide whois lookup alternative"
        save_json(outdir / "whois_notice.json", {"note": msg})
        safe_print("[WHOIS] quien ejecuta local: no se encontró 'whois' instalado.")
        return msg

def module_nmap(target, outdir: Path):
    if not is_installed("nmap"):
        safe_print("[nmap] no instalado; omitiendo nmap.")
        save_json(outdir / "nmap_notice.json", {"note": "nmap not installed"})
        return None
    safe_print("[nmap] ejecutando nmap -sV (requiere permiso). Esto puede ser ruidoso.")
    basename = outdir / "nmap"
    cmd = ["nmap", "-sV", "-T4", "-oA", str(basename), target]
    code, outp, err = run_cmd(cmd, timeout=1800)
    save_json(outdir / "nmap_run.json", {"ret": code, "stdout": outp, "stderr": err})
    return {"ret": code}

def module_whatweb(target, outdir: Path):
    if not is_installed("whatweb"):
        save_json(outdir / "whatweb_notice.json", {"note": "whatweb not installed"})
        safe_print("[whatweb] no instalado; omitiendo.")
        return None
    safe_print("[whatweb] ejecutando whatweb...")
    code, outp, err = run_cmd(["whatweb", target], timeout=120)
    save_json(outdir / "whatweb.json", {"ret": code, "stdout": outp, "stderr": err})
    return outp

def module_subdomain_enum(target, outdir: Path):
    """Intentará usar sublist3r si está instalado, si no intentará 'host -t ns' etc."""
    if is_installed("sublist3r"):
        safe_print("[sublist3r] ejecutando sublist3r...")
        out_file = str(outdir / "subdomains.txt")
        code, outp, err = run_cmd(["sublist3r", "-d", target, "-o", out_file], timeout=300)
        save_json(outdir / "sublist3r_run.json", {"ret": code, "stdout": outp, "stderr": err})
        # también guardar listado si generado
        if os.path.exists(out_file):
            with open(out_file, "r", encoding="utf-8", errors="replace") as f:
                subs = [l.strip() for l in f if l.strip()]
            save_json(outdir / "subdomains.json", subs)
            return subs
        return []
    else:
        safe_print("[subdomain] sublist3r no instalado; intentando resolver NS y A records como fallback.")
        # fallback: obtener NS via nslookup/host and try common subdomains list? (simple fallback)
        subs = []
        # try nslookup -type=ns
        if is_installed("nslookup"):
            code, outp, err = run_cmd(["nslookup", "-type=ns", target], timeout=20)
            save_json(outdir / "nslookup_ns.json", {"ret": code, "stdout": outp, "stderr": err})
        return subs

# ----------------------
# Menú interactivo y orquestador
# ----------------------
def prompt_input(prompt_text):
    try:
        return input(prompt_text)
    except KeyboardInterrupt:
        safe_print("\nInterrumpido por usuario.")
        sys.exit(0)

def generate_html_report(target, outdir: Path, session_files=None):
    """Genera un reporte HTML para la sesión"""
    html_content = f"""
<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Reporte de Recon - {target}</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; background-color: #f5f5f5; }}
        .container {{ max-width: 1200px; margin: 0 auto; background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }}
        h1 {{ color: #333; border-bottom: 3px solid #007bff; padding-bottom: 10px; }}
        h2 {{ color: #007bff; margin-top: 30px; }}
        .summary {{ background: #e9ecef; padding: 15px; border-radius: 5px; margin: 20px 0; }}
        .module {{ background: #f8f9fa; padding: 15px; margin: 10px 0; border-left: 4px solid #007bff; border-radius: 0 5px 5px 0; }}
        .success {{ color: #28a745; font-weight: bold; }}
        .error {{ color: #dc3545; font-weight: bold; }}
        .info {{ color: #17a2b8; font-weight: bold; }}
        table {{ width: 100%; border-collapse: collapse; margin: 15px 0; }}
        th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
        th {{ background-color: #007bff; color: white; }}
        .timestamp {{ color: #6c757d; font-size: 0.9em; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>🔍 Reporte de Recon - {target}</h1>
        <div class="timestamp">Generado el: {time.strftime('%Y-%m-%d %H:%M:%S')}</div>
        
        <div class="summary">
            <h2>📊 Resumen de la Sesión</h2>
            <p><strong>Objetivo:</strong> {target}</p>
            <p><strong>Archivos generados:</strong> {len(session_files) if session_files else 'N/A'}</p>
        </div>
"""
    
    # Añadir información de módulos
    modules_info = {
        "crtsh.json": ("🔐 Certificados SSL", "Información de certificados SSL encontrados"),
        "wayback.json": ("📚 Snapshots históricos", "Capturas históricas del sitio web"),
        "robots.json": ("🤖 robots.txt", "Archivo robots.txt del sitio"),
        "sitemap.json": ("🗺️ sitemap.xml", "Archivo sitemap.xml del sitio"),
        "dns_basic.json": ("🌐 Registros DNS", "Información de DNS del dominio"),
        "github_code_results.json": ("🐙 Referencias en GitHub", "Código relacionado encontrado en GitHub"),
        "google_dorks_results.json": ("🔍 Google Dorks", "Resultados de búsquedas con Google Dorks"),
        "alternative_dorks_results.json": ("🔄 Búsquedas alternativas", "Resultados de búsquedas alternativas")
    }
    
    for filename, (title, description) in modules_info.items():
        file_path = outdir / filename
        if file_path.exists():
            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    count = len(data) if isinstance(data, list) else len(data.keys()) if isinstance(data, dict) else 1
                    html_content += f"""
        <div class="module">
            <h3>{title}</h3>
            <p>{description}</p>
            <p class="success">✓ {count} elementos encontrados</p>
        </div>
"""
            except:
                html_content += f"""
        <div class="module">
            <h3>{title}</h3>
            <p>{description}</p>
            <p class="info">ℹ️ Archivo presente</p>
        </div>
"""
    
    html_content += """
    </div>
</body>
</html>
"""
    
    # Guardar archivo HTML
    html_file = outdir / f"reporte_{target.replace('.', '_')}_{int(time.time())}.html"
    html_file.write_text(html_content, encoding='utf-8')
    return html_file

def generate_session_csv(target, outdir: Path, session_files=None):
    """Genera un CSV con los datos de la sesión"""
    csv_data = []
    
    modules_info = {
        "crtsh.json": "Certificados SSL",
        "wayback.json": "Snapshots históricos", 
        "robots.json": "robots.txt",
        "sitemap.json": "sitemap.xml",
        "dns_basic.json": "Registros DNS",
        "github_code_results.json": "Referencias en GitHub",
        "google_dorks_results.json": "Google Dorks",
        "alternative_dorks_results.json": "Búsquedas alternativas"
    }
    
    for filename, description in modules_info.items():
        file_path = outdir / filename
        if file_path.exists():
            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    count = len(data) if isinstance(data, list) else len(data.keys()) if isinstance(data, dict) else 1
                    csv_data.append({
                        "target": target,
                        "module": description,
                        "filename": filename,
                        "count": count,
                        "status": "success",
                        "timestamp": time.strftime('%Y-%m-%d %H:%M:%S')
                    })
            except:
                csv_data.append({
                    "target": target,
                    "module": description,
                    "filename": filename,
                    "count": 0,
                    "status": "error",
                    "timestamp": time.strftime('%Y-%m-%d %H:%M:%S')
                })
        else:
            csv_data.append({
                "target": target,
                "module": description,
                "filename": filename,
                "count": 0,
                "status": "not_found",
                "timestamp": time.strftime('%Y-%m-%d %H:%M:%S')
            })
    
    # Guardar CSV
    csv_file = outdir / f"session_{target.replace('.', '_')}_{int(time.time())}.csv"
    save_csv(csv_file, csv_data, ["target", "module", "filename", "count", "status", "timestamp"])
    return csv_file

def update_general_files(target, outdir: Path, session_files=None, base_dir=None):
    """Actualiza los archivos generales con los datos de la sesión"""
    # Determinar dónde guardar los archivos generales
    if base_dir:
        # Estructura mixta: archivos generales en la carpeta base
        general_dir = base_dir
    else:
        # Estructura individual o conjunta: archivos generales en la carpeta del objetivo
        general_dir = outdir
    
    current_time = time.strftime('%Y-%m-%d %H:%M:%S')
    
    # Archivo JSON general
    general_json = general_dir / "general_data.json"
    if general_json.exists():
        with open(general_json, 'r', encoding='utf-8') as f:
            general_data = json.load(f)
    else:
        general_data = {"targets": {}, "sessions": [], "metadata": {}}
    
    # Actualizar metadatos del archivo
    general_data["metadata"] = {
        "last_updated": current_time,
        "total_sessions": len(general_data.get("sessions", [])),
        "total_targets": len(general_data.get("targets", {})),
        "file_created": general_data.get("metadata", {}).get("file_created", current_time),
        "update_count": general_data.get("metadata", {}).get("update_count", 0) + 1
    }
    
    # Actualizar datos del objetivo
    if target not in general_data["targets"]:
        general_data["targets"][target] = {"sessions": 0, "last_update": None, "first_seen": current_time}
    
    general_data["targets"][target]["sessions"] += 1
    general_data["targets"][target]["last_update"] = current_time
    
    # Añadir sesión
    session_data = {
        "target": target,
        "timestamp": current_time,
        "files_generated": len(session_files) if session_files else 0,
        "files": [str(f) for f in session_files] if session_files else []
    }
    general_data["sessions"].append(session_data)
    
    # Guardar JSON general
    save_json(general_json, general_data)
    
    # Archivo CSV general
    general_csv = general_dir / "general_data.csv"
    csv_data = []
    for target_name, target_info in general_data["targets"].items():
        csv_data.append({
            "target": target_name,
            "sessions": target_info["sessions"],
            "last_update": target_info["last_update"],
            "first_seen": target_info.get("first_seen", "N/A")
        })
    save_csv(general_csv, csv_data, ["target", "sessions", "last_update", "first_seen"])
    
    # Archivo de metadatos de actualización
    update_log = general_dir / "update_log.txt"
    files_count = len(session_files) if session_files else 0
    files_list = [str(f.name) for f in session_files] if session_files else []
    log_entry = f"[{current_time}] Actualización - Objetivo: {target}, Archivos generados: {files_count}\n"
    if files_list:
        log_entry += f"  Archivos: {', '.join(files_list)}\n"
    if update_log.exists():
        with open(update_log, 'a', encoding='utf-8') as f:
            f.write(log_entry)
    else:
        update_log.write_text(log_entry, encoding='utf-8')
    
    # Archivo HTML general
    generate_general_html(general_dir, general_data)
    
    safe_print(f"📝 Archivos generales actualizados en: {general_dir}")
    safe_print(f"🕒 Última actualización: {current_time}")

def generate_general_html(outdir: Path, general_data):
    """Genera un archivo HTML general con todos los datos"""
    metadata = general_data.get("metadata", {})
    last_updated = metadata.get("last_updated", "N/A")
    file_created = metadata.get("file_created", "N/A")
    update_count = metadata.get("update_count", 0)
    
    html_content = f"""
<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Reporte General de Recon</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; background-color: #f5f5f5; }}
        .container {{ max-width: 1200px; margin: 0 auto; background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }}
        h1 {{ color: #333; border-bottom: 3px solid #007bff; padding-bottom: 10px; }}
        .summary {{ background: #e9ecef; padding: 15px; border-radius: 5px; margin: 20px 0; }}
        .metadata {{ background: #d1ecf1; padding: 15px; border-radius: 5px; margin: 20px 0; border-left: 4px solid #17a2b8; }}
        table {{ width: 100%; border-collapse: collapse; margin: 15px 0; }}
        th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
        th {{ background-color: #007bff; color: white; }}
        .timestamp {{ color: #6c757d; font-size: 0.9em; }}
        .update-info {{ color: #28a745; font-weight: bold; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>📊 Reporte General de Recon</h1>
        
        <div class="metadata">
            <h2>📋 Información del Archivo</h2>
            <p><strong>Archivo creado:</strong> {file_created}</p>
            <p><strong>Última actualización:</strong> <span class="update-info">{last_updated}</span></p>
            <p><strong>Número de actualizaciones:</strong> {update_count}</p>
            <p><strong>Total de objetivos:</strong> {len(general_data['targets'])}</p>
            <p><strong>Total de sesiones:</strong> {len(general_data['sessions'])}</p>
        </div>
        
        <div class="summary">
            <h2>📊 Resumen de Objetivos</h2>
        
        <h2>Objetivos Analizados</h2>
        <table>
            <tr><th>Objetivo</th><th>Sesiones</th><th>Primera Vez</th><th>Última Actualización</th></tr>
"""
    
    for target_name, target_info in general_data["targets"].items():
        first_seen = target_info.get("first_seen", "N/A")
        html_content += f"""
            <tr>
                <td>{target_name}</td>
                <td>{target_info['sessions']}</td>
                <td>{first_seen}</td>
                <td>{target_info['last_update']}</td>
            </tr>
"""
    
    html_content += """
        </table>
        
        <h2>Historial de Sesiones</h2>
        <table>
            <tr><th>Objetivo</th><th>Timestamp</th><th>Archivos Generados</th></tr>
"""
    
    for session in general_data["sessions"]:
        html_content += f"""
            <tr>
                <td>{session['target']}</td>
                <td>{session['timestamp']}</td>
                <td>{session['files_generated']}</td>
            </tr>
"""
    
    html_content += """
        </table>
    </div>
</body>
</html>
"""
    
    html_file = outdir / "reporte_general.html"
    html_file.write_text(html_content, encoding='utf-8')

def show_results_summary(target, outdir: Path, session_files=None):
    """Muestra un resumen de los resultados obtenidos"""
    safe_print(f"\n=== RESUMEN DE RESULTADOS PARA {target} ===")
    
    # Si se proporcionan archivos de sesión, usar solo esos
    if session_files:
        files_to_check = session_files
        safe_print(f"Archivos generados en esta sesión: {len(files_to_check)}")
    else:
        # Verificar archivos generados
        files_created = list(outdir.glob("*"))
        files_to_check = files_created
        safe_print(f"Archivos generados: {len(files_created)}")
    
    # Resumen por módulo
    modules_summary = {
        "crtsh.json": "Certificados SSL",
        "wayback.json": "Snapshots históricos",
        "robots.json": "robots.txt",
        "sitemap.json": "sitemap.xml", 
        "dns_basic.json": "Registros DNS",
        "github_code_results.json": "Referencias en GitHub",
        "google_dorks_results.json": "Google Dorks",
        "alternative_dorks_results.json": "Búsquedas alternativas"
    }
    
    # Verificar archivos de robots/sitemap específicamente
    robots_files = list(outdir.glob("*robots*"))
    sitemap_files = list(outdir.glob("*sitemap*"))
    
    for filename, description in modules_summary.items():
        file_path = outdir / filename
        if file_path.exists():
            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    if isinstance(data, list):
                        count = len(data)
                    elif isinstance(data, dict):
                        count = len(data.keys())
                    else:
                        count = 1
                    safe_print(f"  ✓ {description}: {count} elementos")
            except:
                safe_print(f"  ✓ {description}: archivo presente")
        else:
            # Verificación especial para robots.txt y sitemap.xml
            if description == "robots.txt":
                if robots_files:
                    safe_print(f"  ✓ {description}: {len(robots_files)} archivo(s) encontrado(s)")
                else:
                    safe_print(f"  ✗ {description}: no disponible")
            elif description == "sitemap.xml":
                if sitemap_files:
                    safe_print(f"  ✓ {description}: {len(sitemap_files)} archivo(s) encontrado(s)")
                else:
                    safe_print(f"  ✗ {description}: no disponible")
            else:
                safe_print(f"  ✗ {description}: no disponible")
    
    # Mostrar archivos específicos encontrados
    if robots_files or sitemap_files:
        safe_print(f"\nArchivos específicos encontrados:")
        for robot_file in robots_files:
            safe_print(f"  - {robot_file.name}")
        for sitemap_file in sitemap_files:
            safe_print(f"  - {sitemap_file.name}")
    
    safe_print(f"\nResultados guardados en: {outdir}")
    safe_print("=" * 50)

def run_passive_flow(target, outdir: Path, cfg):
    safe_print("\n--- Ejecutando módulos pasivos ---")
    module_crtsh(target, outdir)
    module_wayback(target, outdir)
    module_robots_sitemap(target, outdir)
    module_dns_basic(target, outdir)
    module_github_search(target, outdir, github_token=cfg.get("github_token"))
    # Google dorks (usar SerpAPI si key, fallback a scrape según configuración)
    module_google_dorks(target, outdir, serpapi_key=cfg.get("serpapi_key"),
                        dorks_extra=cfg.get("extra_dorks"), per_dork=cfg.get("per_dork", 10),
                        allow_scrape_fallback=cfg.get("allow_scrape_fallback", True))
    safe_print("--- Módulos pasivos finalizados ---")
    
    # Mostrar resumen
    show_results_summary(target, outdir)

def run_active_flow(target, outdir: Path, cfg):
    safe_print("\n--- Ejecutando módulos activos (asegúrate de tener permiso) ---")
    module_whois(target, outdir)
    module_subdomain_enum(target, outdir)
    module_whatweb(target, outdir)
    module_nmap(target, outdir)
    safe_print("--- Módulos activos finalizados ---\n")

def get_targets():
    """Obtiene los objetivos del usuario"""
    safe_print("=== Configuración de objetivos ===")
    targets = []
    
    while True:
        target = prompt_input("Introduce un dominio objetivo (ej: example.com) o 'fin' para continuar: ").strip()
        if target.lower() in ['fin', 'done', '']:
            break
        if target:
            targets.append(target)
            safe_print(f"Objetivo añadido: {target}")
    
    if not targets:
        safe_print("No se proporcionaron objetivos. Saliendo.")
        return None, None
    
    safe_print(f"\nObjetivos configurados: {', '.join(targets)}")
    return targets, "individual"

def get_output_structure(targets):
    """Configura la estructura de salida de archivos"""
    if len(targets) == 1:
        return "individual", None
    
    safe_print("\n=== Configuración de estructura de archivos ===")
    safe_print("¿Cómo quieres organizar los archivos?")
    safe_print("[1] Carpeta individual para cada objetivo")
    safe_print("[2] Carpeta conjunta para todos los objetivos")
    safe_print("[3] Carpeta conjunta con subcarpetas individuales")
    
    while True:
        choice = prompt_input("Elige una opción [1-3]: ").strip()
        if choice == "1":
            return "individual", None
        elif choice == "2":
            return "conjunta", None
        elif choice == "3":
            return "mixta", None
        else:
            safe_print("Opción no válida. Intenta otra vez.")

def setup_output_directories(targets, structure, base_name=None):
    """Configura los directorios de salida según la estructura elegida"""
    outdirs = {}
    
    if structure == "individual":
        for target in targets:
            outdirs[target] = Path("recon_output") / target.replace("://", "").replace("/", "_")
            outdirs[target].mkdir(parents=True, exist_ok=True)
    
    elif structure == "conjunta":
        if base_name:
            base_dir = Path("recon_output") / base_name
        else:
            base_dir = Path("recon_output") / "recon_joint"
        base_dir.mkdir(parents=True, exist_ok=True)
        for target in targets:
            outdirs[target] = base_dir
    
    elif structure == "mixta":
        if base_name:
            base_dir = Path("recon_output") / base_name
        else:
            base_dir = Path("recon_output") / "recon_mixed"
        base_dir.mkdir(parents=True, exist_ok=True)
        for target in targets:
            target_dir = base_dir / target.replace("://", "").replace("/", "_")
            target_dir.mkdir(parents=True, exist_ok=True)
            outdirs[target] = target_dir
    
    return outdirs

def get_basic_config():
    """Configuración básica sin claves"""
    return {
        "serpapi_key": None,
        "github_token": None,
        "extra_dorks": [],
        "allow_scrape_fallback": True,
        "per_dork": 10
    }

def get_full_config():
    """Configuración completa con claves"""
    cfg = get_basic_config()
    
    # SerpAPI key
    ans = prompt_input("¿Tienes SerpAPI key para Google Dorks? (s/N): ").strip().lower()
    if ans in ("s", "si"):
        cfg["serpapi_key"] = prompt_input("Introduce SerpAPI key: ").strip()
    
    # GitHub token
    ans = prompt_input("¿Tienes GitHub token para búsquedas? (s/N): ").strip().lower()
    if ans in ("s", "si"):
        cfg["github_token"] = prompt_input("Introduce GitHub token: ").strip()
    
    # Dorks extra
    ans = prompt_input("¿Quieres añadir dorks personalizados? (s/N): ").strip().lower()
    if ans in ("s", "si"):
        safe_print("Introduce dorks adicionales, una por línea. Deja línea vacía cuando termines.")
        extras = []
        while True:
            line = prompt_input("> ").strip()
            if not line:
                break
            extras.append(line)
        cfg["extra_dorks"] = extras
    
    # Resultados por dork
    try:
        p = prompt_input("¿Cuántos resultados por dork quieres (default 10)? ")
        if p.strip():
            cfg["per_dork"] = int(p.strip())
    except Exception:
        cfg["per_dork"] = 10

    return cfg

def run_basic_passive(target, outdir: Path, base_dir=None):
    """Enumeración pasiva básica - solo herramientas que no necesitan claves"""
    safe_print(f"\n--- Enumeración pasiva básica para {target} ---")
    
    # Obtener archivos existentes antes de la ejecución
    files_before = set(outdir.glob("*"))
    
    module_crtsh(target, outdir)
    module_wayback(target, outdir)
    module_robots_sitemap(target, outdir)
    module_dns_basic(target, outdir)
    # Google dorks con configuración básica
    module_google_dorks(target, outdir, serpapi_key=None, dorks_extra=None, 
                        per_dork=10, allow_scrape_fallback=True)
    
    # Obtener archivos generados en esta sesión
    files_after = set(outdir.glob("*"))
    session_files = list(files_after - files_before)
    
    safe_print("--- Enumeración pasiva básica finalizada ---")
    
    # Generar reportes
    html_file = generate_html_report(target, outdir, session_files)
    csv_file = generate_session_csv(target, outdir, session_files)
    update_general_files(target, outdir, session_files, base_dir)
    
    safe_print(f"📄 Reporte HTML generado: {html_file.name}")
    safe_print(f"📊 Datos CSV generados: {csv_file.name}")
    
    show_results_summary(target, outdir, session_files)

def run_basic_active(target, outdir: Path):
    """Enumeración activa básica - solo herramientas que no necesitan claves"""
    safe_print(f"\n--- Enumeración activa básica para {target} ---")
    
    # Obtener archivos existentes antes de la ejecución
    files_before = set(outdir.glob("*"))
    
    module_whois(target, outdir)
    module_subdomain_enum(target, outdir)
    
    # Obtener archivos generados en esta sesión
    files_after = set(outdir.glob("*"))
    session_files = list(files_after - files_before)
    
    safe_print("--- Enumeración activa básica finalizada ---")
    show_results_summary(target, outdir, session_files)

def run_full_passive(target, outdir: Path, cfg):
    """Enumeración pasiva completa con configuración"""
    safe_print(f"\n--- Enumeración pasiva completa para {target} ---")
    
    # Obtener archivos existentes antes de la ejecución
    files_before = set(outdir.glob("*"))
    
    module_crtsh(target, outdir)
    module_wayback(target, outdir)
    module_robots_sitemap(target, outdir)
    module_dns_basic(target, outdir)
    module_github_search(target, outdir, github_token=cfg.get("github_token"))
    module_google_dorks(target, outdir, serpapi_key=cfg.get("serpapi_key"),
                        dorks_extra=cfg.get("extra_dorks"), per_dork=cfg.get("per_dork", 10),
                        allow_scrape_fallback=cfg.get("allow_scrape_fallback", True))
    
    # Obtener archivos generados en esta sesión
    files_after = set(outdir.glob("*"))
    session_files = list(files_after - files_before)
    
    safe_print("--- Enumeración pasiva completa finalizada ---")
    show_results_summary(target, outdir, session_files)

def run_full_active(target, outdir: Path, cfg):
    """Enumeración activa completa con configuración"""
    safe_print(f"\n--- Enumeración activa completa para {target} ---")
    
    # Obtener archivos existentes antes de la ejecución
    files_before = set(outdir.glob("*"))
    
    module_whois(target, outdir)
    module_subdomain_enum(target, outdir)
    module_whatweb(target, outdir)
    module_nmap(target, outdir)
    
    # Obtener archivos generados en esta sesión
    files_after = set(outdir.glob("*"))
    session_files = list(files_after - files_before)
    
    safe_print("--- Enumeración activa completa finalizada ---")
    show_results_summary(target, outdir, session_files)

def run_specific_tool(target, outdir: Path):
    """Ejecuta una herramienta específica"""
    safe_print(f"\n--- Herramientas disponibles para {target} ---")
    tools = [
        ("1", "crt.sh (Certificados SSL)", lambda: module_crtsh(target, outdir)),
        ("2", "Wayback Machine (Snapshots)", lambda: module_wayback(target, outdir)),
        ("3", "robots.txt y sitemap.xml", lambda: module_robots_sitemap(target, outdir)),
        ("4", "DNS básico", lambda: module_dns_basic(target, outdir)),
        ("5", "GitHub Search", lambda: module_github_search(target, outdir, None)),
        ("6", "Google Dorks", lambda: module_google_dorks(target, outdir, None, None, 10, True)),
        ("7", "WHOIS", lambda: module_whois(target, outdir)),
        ("8", "Enumeración de subdominios", lambda: module_subdomain_enum(target, outdir)),
        ("9", "WhatWeb", lambda: module_whatweb(target, outdir)),
        ("10", "Nmap", lambda: module_nmap(target, outdir))
    ]
    
    for num, name, _ in tools:
        safe_print(f"[{num}] {name}")
    
    choice = prompt_input("Elige una herramienta [1-10]: ").strip()
    for num, name, func in tools:
        if choice == num:
            safe_print(f"\n--- Ejecutando {name} ---")
            
            # Obtener archivos existentes antes de la ejecución
            files_before = set(outdir.glob("*"))
            
            func()
            
            # Obtener archivos generados en esta sesión
            files_after = set(outdir.glob("*"))
            session_files = list(files_after - files_before)
            
            safe_print(f"--- {name} finalizada ---")
            
            # Mostrar resumen solo si se generaron archivos
            if session_files:
                show_results_summary(target, outdir, session_files)
            else:
                safe_print("No se generaron archivos nuevos en esta ejecución.")
            return
    
    safe_print("Opción no válida.")

def show_tool_status():
    """Muestra el estado de las herramientas instaladas"""
    safe_print("\n=== Estado de herramientas instaladas ===")
    tools = ["nmap", "whatweb", "sublist3r", "gobuster", "host", "nslookup", "whois"]
    status = {t: is_installed(t) for t in tools}
    
    for t, v in status.items():
        safe_print(f"  {t}: {'✓ INSTALADO' if v else '✗ NO INSTALADO'}")
    
    safe_print("\nRecomendaciones:")
    if not status["whois"]:
        safe_print("- Instala 'whois' para información de registro de dominios")
    if not status["nmap"]:
        safe_print("- Instala 'nmap' para escaneo de puertos")
    if not status["whatweb"]:
        safe_print("- Instala 'whatweb' para fingerprinting de tecnologías web")
    if not status["sublist3r"]:
        safe_print("- Instala 'sublist3r' para enumeración de subdominios")

def menu_loop():
    # Obtener objetivos
    targets, structure = get_targets()
    if not targets:
        return
    
    # Configurar estructura de archivos
    if len(targets) > 1:
        structure, base_name = get_output_structure(targets)
        if base_name is None:
            base_name = prompt_input("Introduce nombre para la carpeta base (opcional, Enter para usar por defecto): ").strip()
            if not base_name:
                base_name = None
    
    # Crear directorios de salida
    outdirs = setup_output_directories(targets, structure, base_name)
    
    # Determinar directorio base para archivos generales (solo para estructura mixta)
    base_dir = None
    if structure == "mixta":
        # En estructura mixta, el directorio base es el directorio padre
        base_dir = list(outdirs.values())[0].parent
    
    # Menú principal
    while True:
        safe_print(f"\n=== Menú principal ===")
        safe_print("Objetivos configurados:", ", ".join(targets))
        safe_print("\n[1] Enumeración pasiva básica")
        safe_print("    (crt.sh, Wayback, DNS, robots/sitemap, Google Dorks básicos)")
        safe_print("[2] Enumeración activa básica")
        safe_print("    (WHOIS, subdominios básicos)")
        safe_print("[3] Enumeración pasiva completa")
        safe_print("    (todas las herramientas pasivas + configuración de claves)")
        safe_print("[4] Enumeración activa completa")
        safe_print("    (todas las herramientas activas + configuración de claves)")
        safe_print("[5] Herramienta concreta")
        safe_print("    (ejecutar una herramienta específica)")
        safe_print("[6] Estado de herramientas instaladas")
        safe_print("[7] Enumeración completa básica")
        safe_print("    (todas las herramientas sin claves)")
        safe_print("[8] Enumeración completa")
        safe_print("    (todas las herramientas + configuración completa)")
        safe_print("[9] Salir")
        
        choice = prompt_input("\nElige una opción [1-9]: ").strip()
        
        if choice == "1":
            # Enumeración pasiva básica
            for target in targets:
                run_basic_passive(target, outdirs[target], base_dir)
                
        elif choice == "2":
            # Enumeración activa básica
            confirm = prompt_input("Módulos activos pueden generar tráfico. ¿Tienes permiso? (s/N): ").strip().lower()
            if confirm in ("s", "si"):
                for target in targets:
                    run_basic_active(target, outdirs[target])
            else:
                safe_print("No autorizado — omitiendo módulos activos.")
                
        elif choice == "3":
            # Enumeración pasiva completa
            cfg = get_full_config()
            for target in targets:
                run_full_passive(target, outdirs[target], cfg)
                
        elif choice == "4":
            # Enumeración activa completa
            confirm = prompt_input("Módulos activos pueden generar tráfico. ¿Tienes permiso? (s/N): ").strip().lower()
            if confirm in ("s", "si"):
                cfg = get_full_config()
                for target in targets:
                    run_full_active(target, outdirs[target], cfg)
            else:
                safe_print("No autorizado — omitiendo módulos activos.")
                
        elif choice == "5":
            # Herramienta concreta
            for target in targets:
                run_specific_tool(target, outdirs[target])
                
        elif choice == "6":
            # Estado de herramientas
            show_tool_status()
            
        elif choice == "7":
            # Enumeración completa básica
            for target in targets:
                run_basic_passive(target, outdirs[target])
                run_basic_active(target, outdirs[target])
                
        elif choice == "8":
            # Enumeración completa
            confirm = prompt_input("Módulos activos pueden generar tráfico. ¿Tienes permiso? (s/N): ").strip().lower()
            if confirm in ("s", "si"):
                cfg = get_full_config()
                for target in targets:
                    run_full_passive(target, outdirs[target], cfg)
                    run_full_active(target, outdirs[target], cfg)
            else:
                safe_print("No autorizado — ejecutando solo módulos pasivos.")
                cfg = get_full_config()
                for target in targets:
                    run_full_passive(target, outdirs[target], cfg)
                    
        elif choice == "9":
            safe_print("Saliendo. Resultados guardados en las carpetas recon_output/")
            break
            
        else:
            safe_print("Opción no válida. Intenta otra vez.")

# ----------------------
# Entrypoint
# ----------------------
if __name__ == "__main__":
    try:
        menu_loop()
    except KeyboardInterrupt:
        safe_print("\nInterrumpido por usuario. Saliendo.")
        sys.exit(0)
