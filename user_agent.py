from flask import Flask, request, render_template_string, jsonify
import csv, os
from datetime import datetime
import pandas as pd

app = Flask(__name__)

CSV_FILE = 'headers_log.csv'
XLSX_FILE = 'headers_log.xlsx'

HEADERS_OF_INTEREST = [
    'user-agent', 'accept', 'accept-language', 'host', 'referer', 'origin',
    'x-forwarded-for', 'forwarded', 'via', 'server',
    'strict-transport-security', 'content-security-policy',
    'x-frame-options', 'x-content-type-options', 'referrer-policy',
    'permissions-policy', 'expect-ct'
]

# Crear CSV si no existe
if not os.path.exists(CSV_FILE):
    with open(CSV_FILE, 'w', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        writer.writerow(['timestamp', 'ip', 'method', 'path', 'user-agent', 'headers'])

def get_ip(req):
    xfwd = req.headers.get('X-Forwarded-For')
    return xfwd.split(',')[0].strip() if xfwd else req.remote_addr or 'unknown'

@app.route('/')
def index():
    ts = datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')
    ip = get_ip(request)
    ua = request.headers.get('User-Agent', 'N/A')
    headers = {h: request.headers.get(h) for h in HEADERS_OF_INTEREST if request.headers.get(h)}

    with open(CSV_FILE, 'a', newline='', encoding='utf-8') as f:
        csv.writer(f).writerow([ts, ip, request.method, request.path, ua, str(headers)])

    print(f"[{ts}] Capturado: {ip} - {ua}")

    # Actualizar Excel automáticamente
    df = pd.read_csv(CSV_FILE)
    df.to_excel(XLSX_FILE, index=False)

    return '<h3>✅ Cabeceras registradas correctamente.</h3>'

@app.route('/api/logs')
def logs():
    with open(CSV_FILE, 'r', encoding='utf-8') as f:
        return jsonify(list(csv.DictReader(f)))

@app.route('/panel')
def panel():
    html = """
    <!DOCTYPE html>
    <html lang="es">
    <head>
        <meta charset="UTF-8">
        <title>Panel de Logs</title>
        <script src="https://cdn.jsdelivr.net/npm/axios/dist/axios.min.js"></script>
        <style>
            body { font-family: sans-serif; padding: 20px; background: #fafafa; }
            h1 { text-align: center; }
            table { width: 100%; border-collapse: collapse; margin-top: 20px; }
            th, td { border: 1px solid #ccc; padding: 8px; font-size: 13px; vertical-align: top; }
            th { background: #eee; }
            input { padding: 5px; margin: 5px; }
            #filter { text-align: center; margin-bottom: 15px; }
            button { padding: 6px 10px; margin-left: 5px; }
        </style>
    </head>
    <body>
        <h1>📋 Panel de Cabeceras Capturadas</h1>
        <div id="filter">
            <input id="search" placeholder="Buscar (IP, fecha o User-Agent)">
            <input type="date" id="from"> a <input type="date" id="to">
            <button onclick="loadLogs()">Buscar</button>
            <button onclick="reset()">Reiniciar</button>
            <a href="/headers_log.xlsx" download><button>⬇️ Descargar Excel</button></a>
        </div>

        <table id="tbl">
            <thead>
                <tr>
                    <th>Fecha</th><th>IP</th><th>Método</th><th>Ruta</th><th>User-Agent</th><th>Cabeceras</th>
                </tr>
            </thead>
            <tbody></tbody>
        </table>

        <script>
            async function loadLogs(){
                const res = await axios.get('/api/logs');
                const search = document.getElementById('search').value.toLowerCase();
                const from = document.getElementById('from').value;
                const to = document.getElementById('to').value;
                const data = res.data.filter(l => {
                    const t = l.timestamp;
                    const matches = l['user-agent'].toLowerCase().includes(search)
                        || l.ip.toLowerCase().includes(search)
                        || t.toLowerCase().includes(search);
                    const dateOk = (!from || t >= from) && (!to || t <= to + ' 23:59:59');
                    return matches && dateOk;
                });
                const tbody = document.querySelector('#tbl tbody');
                tbody.innerHTML = '';
                data.reverse().forEach(l => {
                    const row = document.createElement('tr');
                    row.innerHTML = `
                        <td>${l.timestamp}</td>
                        <td>${l.ip}</td>
                        <td>${l.method}</td>
                        <td>${l.path}</td>
                        <td>${l['user-agent']}</td>
                        <td><pre>${l.headers}</pre></td>`;
                    tbody.appendChild(row);
                });
            }
            function reset(){ document.getElementById('search').value=''; document.getElementById('from').value=''; document.getElementById('to').value=''; loadLogs(); }
            loadLogs();
        </script>
    </body>
    </html>
    """
    return render_template_string(html)

# Servir el archivo Excel directamente
@app.route('/headers_log.xlsx')
def download_xlsx():
    return app.send_static_file(XLSX_FILE)

if __name__ == '__main__':
    # Crear archivo estático para Excel si no existe
    if not os.path.exists(XLSX_FILE):
        pd.DataFrame(columns=['timestamp','ip','method','path','user-agent','headers']).to_excel(XLSX_FILE, index=False)
    app.run(host='0.0.0.0', port=3000)
