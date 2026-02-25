import socket
import threading
import time
import hashlib
import os
from datetime import datetime

# Configuration per Specification
PROXY_HOST = '127.0.0.1'
PROXY_PORT = 4000  # Listen on Port 4000
BUFFER_SIZE = 8192
CACHE_DIR = "./proxy_cache"
blocked_urls = set(["instagram.com"]) # Blocklist
lock = threading.Lock()

if not os.path.exists(CACHE_DIR):
    os.makedirs(CACHE_DIR)

def get_cache_filename(url):
    """Creates a unique hash for the URL to store locally."""
    return os.path.join(CACHE_DIR, hashlib.md5(url.encode()).hexdigest())

def handle_client(client_socket, addr):
    """Threaded handler for simultaneous requests."""
    start_time = time.time() # 
    try:
        # Receive raw bytes from the client [cite: 8]
        request = client_socket.recv(BUFFER_SIZE)
        if not request:
            client_socket.close()
            return

        # Decode the first line once for processing 
        first_line_raw = request.split(b'\n')[0]
        first_line = first_line_raw.decode('utf-8', 'ignore')
        
        #  Respond to HTTP & HTTPS requests and display on management console
        print(f"\n[MANAGEMENT CONSOLE] {datetime.now().strftime('%H:%M:%S')} | Request: {first_line} from {addr}")

        # Parse Method and URL
        parts = first_line.split()
        if len(parts) < 2: 
            return
            
        method = parts[0] # This is now a string
        url = parts[1]    # This is now a string

        # [cite: 9] Dynamically block selected URLs via the management console
        with lock:
            if any(blocked in url for blocked in blocked_urls):
                print(f"[!] ACCESS DENIED: {url} is currently blocked.")
                client_socket.sendall(b"HTTP/1.1 403 Forbidden\r\n\r\nBlocked by Proxy Admin.")
                client_socket.close()
                return

        #  Efficiently cache HTTP requests locally
        cache_path = get_cache_filename(url)
        if method == "GET" and os.path.exists(cache_path):
            with open(cache_path, "rb") as f:
                cached_data = f.read()
                client_socket.sendall(cached_data)
            
            #  Gather timing data to prove efficiency
            rtt = (time.time() - start_time) * 1000
            print(f">>> CACHE HIT | RTT: {rtt:.2f}ms | URL: {url}")
            client_socket.close()
            return

        # Pass the raw request to extraction to avoid double-decoding
        host, port = extract_host_port(request, method)
        
        # Connect to Destination Web Server [cite: 8]
        remote_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        remote_socket.connect((host, port))

        if method == "CONNECT":  # HTTPS Tunneling 
            client_socket.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            tunnel(client_socket, remote_socket)
        else:  # Standard HTTP [cite: 8]
            remote_socket.sendall(request)
            response_full = b""
            while True:
                data = remote_socket.recv(BUFFER_SIZE)
                if not data: break
                client_socket.sendall(data)
                response_full += data
            
            #  Save to Cache for bandwidth efficiency
            if response_full:
                with open(cache_path, "wb") as f:
                    f.write(response_full)
            
            #  Final RTT for fresh fetch
            rtt = (time.time() - start_time) * 1000
            print(f">>> FRESH FETCH | RTT: {rtt:.2f}ms | Host: {host}")

    except Exception as e:
        print(f"[!] Error handling request: {e}")
    finally:
        client_socket.close()

def tunnel(client, remote):
    """Relays HTTPS response to browser."""
    def forward(src, dst):
        try:
            while True:
                data = src.recv(BUFFER_SIZE)
                if not data: break
                dst.sendall(data)
        except: pass
    
    # Bi-directional relaying
    threading.Thread(target=forward, args=(client, remote), daemon=True).start()
    forward(remote, client)

def extract_host_port(request, method):
    try:
        lines = request.split(b'\n')
        host = ""
        for line in lines:
            if b'Host:' in line:
                host = line.split(b' ')[1].decode().strip()
                break
        if ":" in host:
            h, p = host.split(":")
            return h, int(p)
        return host, (443 if method == "CONNECT" else 80)
    except:
        return "127.0.0.1", 80

def management_console():
    """Allows dynamic blocking via management console."""
    global blocked_urls
    while True:
        print("\n--- PROXY COMMANDS ---")
        print("1: Block URL | 2: Unblock URL | 3: List Blocked")
        cmd = input("Select: ")
        if cmd == '1':
            url = input("Enter domain to block: ")
            with lock: blocked_urls.add(url)
            print(f"[*] {url} blocked.")
        elif cmd == '2':
            url = input("Enter domain to unblock: ")
            with lock: blocked_urls.discard(url)
            print(f"[*] {url} unblocked.")
        elif cmd == '3':
            print(f"Current Blocklist: {list(blocked_urls)}")

def start():
    """Main threaded server."""
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((PROXY_HOST, PROXY_PORT))
    server.listen(100) 
    
    # Management Console Thread
    threading.Thread(target=management_console, daemon=True).start()
    
    print(f"[*] Multi-threaded Proxy running on Port {PROXY_PORT}...")
    while True:
        conn, addr = server.accept()
        threading.Thread(target=handle_client, args=(conn, addr)).start()

if __name__ == "__main__":
    start()