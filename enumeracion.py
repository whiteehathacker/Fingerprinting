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

def generate_summary(target, outdir: Path):
    """Genera un resumen en TXT de todos los resultados"""
    summary_file = outdir / "resumen_total.txt"
    
    with open(summary_file, "w", encoding="utf-8") as f:
        f.write(f"=== RESUMEN DE RECONOCIMIENTO PARA {target} ===\n\n")
        
        # Buscar todos los JSON y CSV en el directorio
        for file in outdir.glob("*.json"):
            module_name = file.stem
            f.write(f"\n=== RESULTADOS DE {module_name.upper()} ===\n")
            
            # Leer JSON
            try:
                with open(file, "r", encoding="utf-8") as json_file:
                    data = json.loads(json_file.read())
                    if isinstance(data, list):
                        for item in data:
                            f.write(f"{str(item)}\n")
                    elif isinstance(data, dict):
                        for key, value in data.items():
                            f.write(f"{key}: {value}\n")
            except Exception as e:
                f.write(f"Error leyendo {file}: {e}\n")
                
    safe_print(f"\nResumen generado en: {summary_file}")
    
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
    """Consulta crt.sh para certificados relacionados con target (más robusto)."""
    safe_print("[crt.sh] consultando...")
    q = f"%25.{target}"
    url = f"https://crt.sh/?q={urllib.parse.quote(q)}&output=json"
    results = []

    # Intentos con backoff
    attempts = 3
    for attempt in range(1, attempts + 1):
        code, text = http_get(url)
        if code != 200:
            safe_print(f"[crt.sh] intento {attempt}/{attempts} -> status={code}")
            # si no fue 200, esperar un poco antes de reintentar (backoff)
            if attempt < attempts:
                time.sleep(1.5 ** attempt)
                continue
            else:
                save_json(outdir / "crtsh_error.json", {"status": code, "text": text})
                return results

        # Si code == 200, intentar parsear
        if isinstance(text, str):
            stripped = text.lstrip()
            parsed = None
            # Caso ideal: la respuesta empieza por '[' (JSON array)
            if stripped.startswith("[") or stripped.startswith("{"):
                try:
                    parsed = json.loads(text)
                except Exception as e:
                    safe_print(f"[crt.sh] intento parse JSON directo: {e}")
            # Si no parsea directamente, intentar extraer el bloque JSON entre el primer '[' y el último ']'
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
                # Normalizar: si es dict con datos incrustados, convertir a lista si procede
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
                # Si quedan intentos, esperar y reintentar
                if attempt < attempts:
                    time.sleep(1.5 ** attempt)
                    continue
                else:
                    # finalizar con lista vacía y archivo raw
                    save_json(outdir / "crtsh_notice.json", {"note": "no JSON parsed; see crtsh_raw.txt"})
                    return results
        else:
            safe_print(f"[crt.sh] respuesta no textual (status={code})")
            if attempt < attempts:
                time.sleep(1.5 ** attempt)
                continue
            else:
                save_json(outdir / "crtsh_error.json", {"status": code, "text": str(text)})
                return results

    # Si llegamos aquí, devolvemos lista vacía
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
    while to_fetch > 0:
        params = {"q": dork, "num": min(10, to_fetch), "start": start, "hl": "es"}
        url = "https://www.google.com/search?" + urllib.parse.urlencode(params)
        code, text = http_get(url)
        if code != 200 or not isinstance(text, str):
            safe_print(f"[Scrape] error status={code}")
            break
        parser = SimpleGoogleParser()
        parser.feed(text)
        for r in parser.results:
            results.append({"title": r.get("title"), "link": r.get("link"), "snippet": r.get("snippet")})
        time.sleep(random.uniform(2.0, 4.0))
        to_fetch -= 10
        start += 10
        if not parser.results:
            break
    safe_print(f"[Scrape] {len(results)} resultados aproximados")
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
    safe_print("--- Módulos pasivos finalizados ---\n")

def run_active_flow(target, outdir: Path, cfg):
    safe_print("\n--- Ejecutando módulos activos (asegúrate de tener permiso) ---")
    module_whois(target, outdir)
    module_subdomain_enum(target, outdir)
    module_whatweb(target, outdir)
    module_nmap(target, outdir)
    safe_print("--- Módulos activos finalizados ---\n")

def menu_loop():
    safe_print("=== Recon Tool (sin deps) - Menú interactivo ===")
    target = prompt_input("Introduce el dominio objetivo (ej: example.com): ").strip()
    if not target:
        safe_print("Dominio no proporcionado. Saliendo.")
        return

    outdir = outdir.mkdir(target)
    if not outdir:
        safe_print("No se pudo crear directorio de salida. Saliendo.")
        return

    safe_print(f"Usando directorio de salida: {outdir}")
    
    # configuración runtime
    cfg = {
        "serpapi_key": None,
        "github_token": None,
        "extra_dorks": [],
        "allow_scrape_fallback": True,
        "per_dork": 10
    }

    # Menú principal
    while True:
        safe_print("\nOpciones disponibles:")
        safe_print("1. Ejecutar módulos pasivos")
        safe_print("2. Ejecutar módulos activos (requiere herramientas instaladas)")
        safe_print("3. Configurar API keys")
        safe_print("4. Generar resumen de resultados")
        safe_print("5. Salir")
        
        choice = prompt_input("\nElige una opción (1-5): ").strip()
        
        if choice == "1":
            run_passive_flow(target, outdir, cfg)
            generate_summary(target, outdir)
        elif choice == "2":
            run_active_flow(target, outdir, cfg)
            generate_summary(target, outdir)
        elif choice == "3":
            cfg["serpapi_key"] = prompt_input("SerpAPI key (Enter para omitir): ").strip() or None
            cfg["github_token"] = prompt_input("GitHub token (Enter para omitir): ").strip() or None
        elif choice == "4":
            generate_summary(target, outdir)
        elif choice == "5":
            break
        else:
            safe_print("Opción no válida")

    safe_print("\n¡Bye!")

# ----------------------
# Entrypoint
# ----------------------
if __name__ == "__main__":
    try:
        menu_loop()
    except KeyboardInterrupt:
        safe_print("\nInterrumpido por usuario. Saliendo.")
        sys.exit(0)
