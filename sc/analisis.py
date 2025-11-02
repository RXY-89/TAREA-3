import os, logging, sys,getpass, argparse, csv, json, subprocess, datetime, dns.resolver, whois, requests, time, re
from pathlib import Path
from requests.exceptions import RequestException
from dns.exception import DNSException
from pathlib import Path

logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')
logger = logging.getLogger("integrador")

AUTHORIZED = os.getenv("FOOTPRINT_AUTH", "0") == "1"
DEFAULT_USER_AGENT = "FootprintOSINT/1.0 (+https://example.org/)"

def timestamp_now():
    return datetime.datetime.utcnow().isoformat() + "Z"

def load_hosts(file_path):

    p = Path(file_path)
    if not p.exists():
        raise FileNotFoundError(f"Hosts file not found: {file_path}")
    hosts = []
    text = p.read_text(encoding="utf-8", errors="ignore")  
    first_line = None
    for ln in text.splitlines():
        if ln.strip():
            first_line = ln
            break
    try:
        if first_line and "," in first_line:
            with p.open("r", encoding="utf-8", errors="ignore") as f:
                reader = csv.DictReader(f)
                if reader.fieldnames:
                    for row in reader:
                        for key in ("subdomain", "host", "hostname", "domain"):
                            if key in row and row[key].strip():
                                hosts.append(row[key].strip())
                                break                    
                    if not hosts:
                        f.seek(0)
                        reader2 = csv.reader(f)
                        for r in reader2:
                            if r and r[0].strip():
                                hosts.append(r[0].strip())
                else:
                    with p.open("r", encoding="utf-8", errors="ignore") as f2:
                        reader2 = csv.reader(f2)
                        for r in reader2:
                            if r and r[0].strip():
                                hosts.append(r[0].strip())
        else:
            for ln in text.splitlines():
                ln = ln.strip()
                if ln and not ln.startswith("#"):
                    hosts.append(ln)
    except Exception as e:
        logger.exception(f"Error parsing hosts file: {e}")
        raise
    normalized = []
    seen = set()
    for h in hosts:
        h = h.strip()
        if not h:
            continue
        if h in seen:
            continue
        seen.add(h)
        normalized.append(h)
    return normalized

def http_get(host, scheme="https", timeout=8):

    url = f"{scheme}://{host}/"
    ts = timestamp_now()
    result = {"host": host, "scheme": scheme, "url": url, "timestamp": ts}
    headers = {"User-Agent": DEFAULT_USER_AGENT}
    try:
        r = requests.get(url, headers=headers, timeout=timeout, allow_redirects=True)
        result.update({
            "status_code": r.status_code,
            "reason": r.reason,
            "content_length": len(r.content),
            "final_url": r.url,
            "elapsed_seconds": r.elapsed.total_seconds() if hasattr(r, "elapsed") else None
        })
        logger.info(f"HTTP {scheme.upper()} {host} -> {r.status_code} ({len(r.content)} bytes)")
    except requests.exceptions.RequestException as e:
        result.update({"error": str(e)})
        logger.warning(f"HTTP error {scheme}://{host} -> {e}")
    return result

def run_nmap(target, ports="1-1024", additional_args=None, output_dir="output", timeout=600):

    additional_args = additional_args or []
    outdir = Path(output_dir)
    outdir.mkdir(parents=True, exist_ok=True)
    safe_target = target.replace("/", "_").replace(":", "_").replace(".", "_")
    outfile = outdir / f"nmap_{safe_target}.txt"
    jsonfile = outdir / f"nmap_{safe_target}.json"
    cmd = ["nmap", "-sV", "-Pn", "-p", ports] + additional_args + [target]
    logger.info("Running nmap: " + " ".join(cmd))
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        with outfile.open("w", encoding="utf-8") as f:
            f.write(proc.stdout)
        parsed = {
            "target": target,
            "returncode": proc.returncode,
            "stdout_snippet": proc.stdout.splitlines()[:80],
            "outfile": str(outfile),
            "completed_at": timestamp_now()
        }
        with jsonfile.open("w", encoding="utf-8") as jf:
            json.dump(parsed, jf, indent=2, ensure_ascii=False)
        logger.info(f"Nmap finished for {target}; saved to {outfile}")
        return parsed
    except FileNotFoundError:
        err = "nmap not installed (install from https://nmap.org/)."
        logger.error(err)
        return {"error": err}
    except subprocess.TimeoutExpired:
        err = f"nmap timed out for {target}"
        logger.error(err)
        return {"error": err}
    except Exception as e:
        logger.exception(f"Unexpected error running nmap for {target}: {e}")
        return {"error": str(e)}

def save_json(obj, path):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(obj, f, indent=2, ensure_ascii=False)
    logger.info(f"Wrote JSON to {path}")

def checar_dominio(d):
    return re.match(r"^(?!\-)(?:[a-zA-Z0-9\-]{1,63}\.)+[a-zA-Z]{2,}$", d) is not None

def certificados(dominio, api_key, max_certificados=500, carpeta="resultados", verbose=False):
    url = "https://api.shodan.io/shodan/host/search"
    pagina = 1
    certificados = []
    fingerprints_vistos = set()
    total_agregados = 0

    os.makedirs(carpeta, exist_ok=True)
    nombre_archivo = os.path.join(carpeta, f"certificados_{dominio.replace('.', '_')}.csv")
    campos = [
        "ip", "port", "common_name", "issuer", "fingerprint", "serial",
        "valid_from", "valid_to", "key_type", "key_bits",
        "tls_version", "cipher", "jarm"
    ]
    escribir_encabezado = not os.path.exists(nombre_archivo)

    with open(nombre_archivo, 'a', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=campos)
        if escribir_encabezado:
            writer.writeheader()

        if not api_key:
            raise ValueError("API key de Shodan no proporcionada. Establece SHODAN_APIKEY o pásala como parámetro.")

        while total_agregados < max_certificados:
            params = {
                "key": api_key,
                "query": f"ssl.cert.subject.CN:{dominio}",
                "page": pagina
            }

            try:
                resp = requests.get(url, params=params, timeout=10)
                resp.raise_for_status()
                resultados = resp.json()
                matches = resultados.get("matches", [])
                if not matches:
                    if verbose:
                        logger.info(f"No hay más coincidencias en página {pagina}.")
                    break

                nuevos = 0
                for match in matches:
                    cert = match.get("ssl", {}).get("cert", {}) or {}

                    fingerprint = None
                    fp_field = cert.get("fingerprint")
                    if isinstance(fp_field, dict):
                        fingerprint = fp_field.get("sha256") or fp_field.get("sha1")
                    elif isinstance(fp_field, str):
                        fingerprint = fp_field
                    if not fingerprint:
                        fingerprint = cert.get("fingerprint_sha256") or cert.get("fingerprint_sha1")

                    if not fingerprint or fingerprint in fingerprints_vistos:
                        continue

                    fingerprints_vistos.add(fingerprint)
                    fila = {
                        "ip": match.get("ip_str"),
                        "port": match.get("port"),
                        "common_name": cert.get("subject", {}).get("CN"),
                        "issuer": cert.get("issuer", {}).get("CN"),
                        "fingerprint": fingerprint,
                        "serial": cert.get("serial"),
                        "valid_from": cert.get("validity", {}).get("start"),
                        "valid_to": cert.get("validity", {}).get("end"),
                        "key_type": cert.get("pubkey", {}).get("type"),
                        "key_bits": cert.get("pubkey", {}).get("bits"),
                        "tls_version": match.get("ssl", {}).get("version"),
                        "cipher": match.get("ssl", {}).get("cipher"),
                        "jarm": match.get("ssl", {}).get("jarm")
                    }
                    writer.writerow(fila)
                    certificados.append(fila)
                    nuevos += 1
                    total_agregados += 1

                    if total_agregados >= max_certificados:
                        break

                if verbose:
                    logger.info(f"Página {pagina}: {nuevos} certificados nuevos, total: {total_agregados}")

                if nuevos == 0:
                    break

                pagina += 1
                time.sleep(1)

            except RequestException as e:
                logger.error(f"Error de red al consultar Shodan en página {pagina}: {e}")
                time.sleep(2)
                try:
                    resp = requests.get(url, params=params, timeout=10)
                    resp.raise_for_status()
                    continue
                except RequestException:
                    logger.error("Reintento fallido, abortando búsqueda de certificados.")
                    break
            except Exception as e:
                logger.exception(f"Error inesperado en página {pagina}: {e}")
                break

    logger.info(f"Certificados guardados en: {nombre_archivo}")

def consultar_dns(dominio, tipos=None, timeout=3, verbose=False):
    if tipos is None:
        tipos = ['A', 'AAAA', 'MX', 'NS', 'TXT']
    resultados = {}
    for rtype in tipos:
        try:
            respuestas = dns.resolver.resolve(dominio, rtype, lifetime=timeout)
            if rtype == 'MX':
                resultados[rtype] = [f"{r.preference} {r.exchange}" for r in respuestas]
            elif rtype == 'TXT':
                resultados[rtype] = ["".join(r.strings).decode('utf-8') if hasattr(r, 'strings') else str(r) for r in respuestas]
            else:
                resultados[rtype] = [str(rdata) for rdata in respuestas]
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers) as e:
            resultados[rtype] = []
            if verbose:
                logger.debug(f"[DNS] {rtype}: no disponible o error ({e})")
        except DNSException as e:
            resultados[rtype] = []
            if verbose:
                logger.error(f"[DNS] Error DNS ({rtype}): {e}")
    return resultados

def consultar_whois(dominio, verbose=False):
    try:
        info = whois.whois(dominio)
        datos = dict(info)
        return datos
    except Exception as e:
        if verbose:
            logger.error(f"[WHOIS] Error al consultar WHOIS: {e}")
        return {}

def evaluar_dominio(dominio, verbose=False):
    dns_resultados = consultar_dns(dominio, verbose=verbose)
    whois_resultados = consultar_whois(dominio, verbose=verbose)

    if all(not v for v in dns_resultados.values()):
        estado = "Dominio probablemente inexistente o sin registros DNS"
    elif whois_resultados.get("domain_name"):
        estado = "Dominio valido con WHOIS disponible"
    elif whois_resultados:
        estado = "Dominio valido sin WHOIS completo"
    else:
        estado = "Dominio con DNS pero sin WHOIS (posible privacidad o error)"

    resultado = {
        "dominio": dominio,
        "estado_inferido": estado,
        "dns": dns_resultados,
        "whois": whois_resultados
    }

def analizar_dominio(dominio, api_key, outdir, http_timeout=8, nmap_ports="1-1024", nmap_args=[], run_active=False):
    if not checar_dominio(dominio):
        logger.warning(f"Dominio inválido: {dominio}")
        return None

    resultado = evaluar_dominio(dominio)
    certificados(dominio, api_key)
    resultado["http"] = []
    resultado["nmap"] = {}

    res_https = http_get(dominio, scheme="https", timeout=http_timeout)
    resultado["http"].append(res_https)
    if "error" in res_https or (res_https.get("status_code") and res_https.get("status_code") >= 400):
        res_http = http_get(dominio, scheme="http", timeout=http_timeout)
        resultado["http"].append(res_http)

    if run_active and AUTHORIZED:
        resultado["nmap"] = run_nmap(dominio, ports=nmap_ports, additional_args=nmap_args, output_dir=str(outdir))

    nombre = dominio.replace(".", "_")
    ruta = outdir / f"{nombre}.json"
    save_json(resultado, str(ruta))
    return resultado

if __name__ == "__main__":
    
    if os.path.exists("apikey.txt"):
        try:
            with open("apikey.txt", "r", encoding='utf-8') as archivo:
                api_key = archivo.read().strip()
        except Exception as e:
            logger.error(f"Error al leer apikey.txt: {e}")
            sys.exit(1)
    else:
        logger.info("No se encontró SHODAN_APIKEY ni apikey.txt. Se pedirá la clave (no se guardará por defecto).")            
        clave = getpass.getpass("Ingresa tu API key: ")
        api_key = clave.strip()
        guardar = input("¿Deseas guardar la API key en 'apikey.txt' para futuros usos? (s/N): ").strip().lower()
        if guardar == 's':
            try:
                with open("apikey.txt", "w", encoding='utf-8') as archivo:
                    archivo.write(api_key)
                logger.info("API key guardada en apikey.txt (revisa que no esté en control de versiones).")
            except Exception as e:
                logger.error(f"No se pudo guardar la API key: {e}")

    dominios = load_hosts("dominios.txt")
    outdir = Path("resultados")
    outdir.mkdir(exist_ok=True)

    resumen = []
    for d in dominios:
        r = analizar_dominio(d, api_key, outdir, run_active=True)
        if r:
            resumen.append(r["dominio"])

    logger.info(f"Análisis completo para {len(resumen)} dominios.")
