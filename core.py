import socket
import _thread
import time
import hashlib
import os

# Configuration
PROXY_PORT = 4000
BUFFER_SIZE = 8192
CACHE_DIR = "./proxy_cache"
BLOCKED_URLS = set(["example.com", "socialmedia.com"]) # Management Console Mock

if not os.path.exists(CACHE_DIR):
    os.makedirs(CACHE_DIR)

def get_cache_path(url):
    """Generates a unique filename for a URL using MD5 hashing."""
    return os.path.join(CACHE_DIR, hashlib.md5(url.encode()).hexdigest())

def proxy_thread(conn, addr):
    """Handles individual client requests."""
    try:
        start_time = time.time()
        request = conn.recv(BUFFER_SIZE).decode('utf-8', 'ignore')
        
        if not request:
            conn.close()
            return

        # Parse the first line (e.g., GET http://www.google.com/ HTTP/1.1)
        first_line = request.split('\n')[0]
        url = first_line.split(' ')[1]

        # 2. Blocking Logic
        for blocked in BLOCKED_URLS:
            if blocked in url:
                print(f"[!] Blocked access to: {url}")
                conn.send(b"HTTP/1.1 403 Forbidden\r\n\r\nBlocked by Proxy Admin.")
                conn.close()
                return

        # 3. Caching Logic (HTTP GET only)
        cache_file = get_cache_path(url)
        if os.path.exists(cache_file) and "GET" in first_line:
            with open(cache_file, "rb") as f:
                conn.send(f.read())
            rtt = (time.time() - start_time) * 1000
            print(f"[*] Cache Hit: {url} | RTT: {rtt:.2f}ms")
            conn.close()
            return

        # Parse host and port
        http_pos = url.find("://")
        temp = url if http_pos == -1 else url[(http_pos+3):]
        
        port_pos = temp.find(":")
        webserver_pos = temp.find("/")
        if webserver_pos == -1: webserver_pos = len(temp)

        webserver = ""
        port = 80
        if port_pos == -1 or webserver_pos < port_pos:
            webserver = temp[:webserver_pos]
        else:
            port = int((temp[(port_pos+1):])[:webserver_pos-port_pos-1])
            webserver = temp[:port_pos]

        # Connect to destination Web Server
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((webserver, port))
        
        # HTTPS Tunneling (CONNECT)
        if "CONNECT" in first_line:
            conn.send(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            conn.setblocking(0)
            s.setblocking(0)
            while True:
                try:
                    data = conn.recv(BUFFER_SIZE)
                    if not data: break
                    s.send(data)
                except: pass
                try:
                    reply = s.recv(BUFFER_SIZE)
                    if not reply: break
                    conn.send(reply)
                except: pass
        # Standard HTTP
        else:
            s.send(request.encode())
            full_response = b""
            while True:
                reply = s.recv(BUFFER_SIZE)
                if len(reply) > 0:
                    conn.send(reply)
                    full_response += reply
                else:
                    break
            
            # Save to Cache
            if len(full_response) > 0:
                with open(cache_file, "wb") as f:
                    f.write(full_response)

        rtt = (time.time() - start_time) * 1000
        print(f"[*] Fetched: {webserver} | RTT: {rtt:.2f}ms")
        s.close()
        conn.close()

    except Exception as e:
        print(f"[!] Error: {e}")
        conn.close()

def start_server():
    """Initializes the listening socket on Port 4000."""
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(('', PROXY_PORT))
    server.listen(50)
    print(f"[*] Proxy Server running on port {PROXY_PORT}...")

    while True:
        conn, addr = server.accept()
        # 1. Multi-threading Concurrency
        _thread.start_new_thread(proxy_thread, (conn, addr))

if __name__ == "__main__":
    start_server()