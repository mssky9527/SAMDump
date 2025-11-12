#!/usr/bin/env python3
import socket
import struct
import sys

def receive_files(host='0.0.0.0', port=4444):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((host, port))
        s.listen(1)
        print(f"Escuchando en {host}:{port}...")
        
        conn, addr = s.accept()
        with conn:
            print(f"Conexión establecida desde {addr}")
            
            while True:
                try:
                    # Recibir header (32 + 4 + 4 = 40 bytes)
                    header_data = conn.recv(40)
                    if not header_data:
                        break
                    
                    # Desempaquetar header
                    filename = header_data[:32].decode('utf-8').rstrip('\x00')
                    filesize = struct.unpack('!I', header_data[32:36])[0]
                    checksum = struct.unpack('!I', header_data[36:40])[0]
                    
                    print(f"Recibiendo: {filename} ({filesize} bytes)")
                    
                    # Recibir datos del archivo
                    filedata = b''
                    while len(filedata) < filesize:
                        chunk = conn.recv(min(4096, filesize - len(filedata)))
                        if not chunk:
                            break
                        filedata += chunk
                    
                    # Guardar archivo
                    with open(f"received_{filename}", "wb") as f:
                        f.write(filedata)
                    
                    print(f"Guardado: received_{filename}")
                    
                except Exception as e:
                    print(f"Error: {e}")
                    break

if __name__ == "__main__":
    receive_files()