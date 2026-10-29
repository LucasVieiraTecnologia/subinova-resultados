#!/usr/bin/env python3
"""
Servidor HTTP com suporte a Range Requests (HTTP 206 Partial Content).
Essencial para streaming de vídeo MP4 e seeking suave no navegador.
"""

import os
import sys
import mimetypes
from http.server import HTTPServer, BaseHTTPRequestHandler

PORT = 8080
DIRECTORY = os.path.dirname(os.path.abspath(__file__))

class RangeRequestHandler(BaseHTTPRequestHandler):
    def translate_path(self, path):
        # Remove query parameters and hashes
        clean_path = path.split('?', 1)[0].split('#', 1)[0]
        if clean_path in ('', '/'):
            clean_path = '/index.html'
        local_path = os.path.normpath(os.path.join(DIRECTORY, clean_path.lstrip('/')))
        if not local_path.startswith(DIRECTORY):
            return None
        return local_path

    def do_GET(self):
        file_path = self.translate_path(self.path)
        if not file_path or not os.path.exists(file_path) or os.path.isdir(file_path):
            self.send_error(404, "Arquivo não encontrado")
            return

        file_size = os.path.getsize(file_path)
        mime_type, _ = mimetypes.guess_type(file_path)
        if not mime_type:
            mime_type = 'application/octet-stream'

        range_header = self.headers.get('Range')

        if range_header and range_header.startswith('bytes='):
            # Parse Range: bytes=start-end
            try:
                ranges = range_header.replace('bytes=', '').split('-')
                start = int(ranges[0]) if ranges[0] else 0
                end = int(ranges[1]) if len(ranges) > 1 and ranges[1] else file_size - 1
            except ValueError:
                self.send_error(400, "Range inválido")
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
                    except (BrokenPipeError, ConnectionResetError):
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
                    except (BrokenPipeError, ConnectionResetError):
                        break

    def log_message(self, format, *args):
        # Silencia logs repetitivos para manter o terminal limpo
        pass

def run():
    os.chdir(DIRECTORY)
    server_address = ('', PORT)
    httpd = HTTPServer(server_address, RangeRequestHandler)
    print("=" * 65)
    print(f" PORTAL DE RESULTADOS INICIADO COM SUCESSO!")
    print(f" Endereço local: http://localhost:{PORT}")
    print(f" Diretório base: {DIRECTORY}")
    print(f" Senha de acesso criptografada: @3293")
    print(" Pressione Ctrl+C para encerrar o servidor.")
    print("=" * 65)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nServidor encerrado pelo usuário.")
        httpd.server_close()

if __name__ == '__main__':
    run()
