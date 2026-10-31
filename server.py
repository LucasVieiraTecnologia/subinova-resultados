#!/usr/bin/env python3
"""
Servidor HTTP Multi-threaded com suporte a Range Requests (HTTP 206 Partial Content).
Essencial para streaming de vídeo MP4 e seeking suave no navegador sem travar outros assets.
Suporta múltiplas portas simultaneamente (3000 e 8080).
"""

import os
import sys
import threading
import mimetypes
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler

DIRECTORY = os.path.dirname(os.path.abspath(__file__))

mimetypes.add_type('video/mp4', '.mp4')
mimetypes.add_type('text/css', '.css')
mimetypes.add_type('application/javascript', '.js')
mimetypes.add_type('application/json', '.json')
mimetypes.add_type('text/html; charset=utf-8', '.html')

class RobustRangeRequestHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def translate_path(self, path):
        clean_path = path.split('?', 1)[0].split('#', 1)[0]
        if clean_path in ('', '/'):
            clean_path = '/index.html'
        parts = [p for p in clean_path.split('/') if p]
        blocked_names = {'server.py', 'iniciar.bat', 'supabase_setup.sql'}
        if any(p.startswith('.') or p.lower() in blocked_names for p in parts):
            return None
        local_path = os.path.normpath(os.path.join(DIRECTORY, clean_path.lstrip('/')))
        if not local_path.startswith(DIRECTORY):
            return None
        return local_path

    def end_headers(self):
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.send_header('X-Frame-Options', 'SAMEORIGIN')
        super().end_headers()

    def do_OPTIONS(self):
        self.send_response(200)
        self.end_headers()

    def do_GET(self):
        file_path = self.translate_path(self.path)
        if not file_path or not os.path.exists(file_path) or os.path.isdir(file_path):
            self.send_error(404, "Arquivo nao encontrado")
            return

        file_size = os.path.getsize(file_path)
        mime_type, _ = mimetypes.guess_type(file_path)
        if not mime_type:
            mime_type = 'application/octet-stream'

        range_header = self.headers.get('Range')

        if range_header and range_header.startswith('bytes='):
            try:
                ranges = range_header.replace('bytes=', '').split('-')
                start = int(ranges[0]) if ranges[0] else 0
                end = int(ranges[1]) if len(ranges) > 1 and ranges[1] else file_size - 1
            except ValueError:
                self.send_error(400, "Range invalido")
                return

            if start >= file_size or end >= file_size or start > end:
                self.send_response(416, "Requested Range Not Satisfiable")
                self.send_header('Content-Range', f'bytes */{file_size}')
                self.end_headers()
                return

            length = end - start + 1
            self.send_response(206)
            self.send_header('Content-Type', mime_type)
            self.send_header('Content-Range', f'bytes {start}-{end}/{file_size}')
            self.send_header('Content-Length', str(length))
            self.send_header('Accept-Ranges', 'bytes')
            self.send_header('Cache-Control', 'no-cache')
            self.end_headers()

            with open(file_path, 'rb') as f:
                f.seek(start)
                remaining = length
                chunk_size = 64 * 1024
                while remaining > 0:
                    read_len = min(chunk_size, remaining)
                    buf = f.read(read_len)
                    if not buf:
                        break
                    try:
                        self.wfile.write(buf)
                    except (BrokenPipeError, ConnectionResetError, ConnectionAbortedError):
                        break
                    remaining -= len(buf)
        else:
            self.send_response(200)
            self.send_header('Content-Type', mime_type)
            self.send_header('Content-Length', str(file_size))
            self.send_header('Accept-Ranges', 'bytes')
            self.send_header('Cache-Control', 'no-cache')
            self.end_headers()

            with open(file_path, 'rb') as f:
                chunk_size = 64 * 1024
                while True:
                    buf = f.read(chunk_size)
                    if not buf:
                        break
                    try:
                        self.wfile.write(buf)
                    except (BrokenPipeError, ConnectionResetError, ConnectionAbortedError):
                        break

    def log_message(self, format, *args):
        pass

def run():
    os.chdir(DIRECTORY)
    ThreadingHTTPServer.allow_reuse_address = True
    
    servers = []
    for port in [3000, 8080]:
        try:
            httpd = ThreadingHTTPServer(('127.0.0.1', port), RobustRangeRequestHandler)
            servers.append((port, httpd))
            print(f" Servidor ativo em: http://localhost:{port}")
        except Exception as e:
            print(f" Porta {port} nao pode ser aberta: {e}")

    if not servers:
        print("Erro: Nenhuma porta disponivel.")
        return

    for port, s in servers[1:]:
        t = threading.Thread(target=s.serve_forever, daemon=True)
        t.start()

    try:
        servers[0][1].serve_forever()
    except KeyboardInterrupt:
        for port, s in servers:
            s.server_close()

if __name__ == '__main__':
    run()
