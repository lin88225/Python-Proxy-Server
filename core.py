import socket
import threading
import time
import hashlib
import os
from datetime import datetime


# Configuration per the specifications
PROXY_HOST = '127.0.0.1'
PROXY_PORT = 4000  # Listens on Port 4000
BUFFER_SIZE = 8192
CACHE_DIR = "./proxy_cache"
blocked_urls = set(["instagram.com"])
lock = threading.Lock()


if not os.path.exists(CACHE_DIR):
   os.makedirs(CACHE_DIR)


def get_cache_filename(url):
   """Creates a unique hash for the URL to store locally."""
   return os.path.join(CACHE_DIR, hashlib.md5(url.encode()).hexdigest())


def handle_client(client_socket, addr):
   """
   Threaded handler for simultaneous requests.
   Uses raw socket.recv to manually capture the byte stream from the client.
   """
   start_time = time.time()
   try:
       # Raw sockets (socket.recv) are used here to access the low-level byte data.
       request = client_socket.recv(BUFFER_SIZE)
       if not request:
           client_socket.close()
           return


       # Manual parsing of the byte stream to extract the request line
       first_line_raw = request.split(b'\n')[0]
       first_line = first_line_raw.decode('utf-8', 'ignore')
      
       # Display each request on management console
       print(f"\nCONSOLE: {datetime.now().strftime('%H:%M:%S')} Request: {first_line} from {addr}")


       # Manual string splitting to identify HTTP Method and Target URL
       parts = first_line.split()
       if len(parts) < 2:
           return
          
       method = parts[0]
       url = parts[1]   


       # Blocking Logic
       with lock:
           if any(blocked in url for blocked in blocked_urls):
               print(f"ACCESS DENIED: {url} is blocked.")
               # Construct and send a raw HTTP response manually
               client_socket.sendall(b"HTTP/1.1 403 Forbidden\r\n\r\nBlocked by Proxy Admin.")
               client_socket.close()
               return


       # Local Caching Logic
       cache_path = get_cache_filename(url)
       if method == "GET" and os.path.exists(cache_path):
           with open(cache_path, "rb") as f:
               cached_data = f.read()
               # Sending raw bytes directly from disk to the socket
               client_socket.sendall(cached_data)
          
           # Timing data gathered to show efficiency (RTT)
           rtt = (time.time() - start_time) * 1000
           print(f">>> CACHE HIT | RTT: {rtt:.2f}ms | URL: {url}")
           client_socket.close()
           return


       # Manual extraction of Host/Port from the raw request headers
       host, port = extract_host_port(request, method)
      
       # Establishing a manual TCP connection to the destination server
       # This uses AF_INET (IPv4) and SOCK_STREAM (TCP) sockets.
       remote_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
       remote_socket.connect((host, port))


       if method == "CONNECT":  # HTTPS Tunneling (TCP Relay)
           # Send a manual 200 OK to the client to begin the tunnel
           client_socket.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
           tunnel(client_socket, remote_socket)
       else:  # HTTP Proxying
           # Manually relaying the client's request bytes to the remote server
           remote_socket.sendall(request)
           response_full = b""
           while True:
               # Manually receiving response chunks from web server
               data = remote_socket.recv(BUFFER_SIZE)
               if not data: break
               # Relaying chunks back to the client socket
               client_socket.sendall(data)
               response_full += data
          
           # Save the raw response bytes to cache for future bandwidth efficiency
           if response_full:
               with open(cache_path, "wb") as f:
                   f.write(response_full)
          
           rtt = (time.time() - start_time) * 1000
           print(f"FETCH, RTT is {rtt:.2f}ms, Host: {host}")


   except Exception as e:
       print(f"Error handling request: {e}")
   finally:
       client_socket.close()


def tunnel(client, remote):
   """
   Relays HTTPS traffic. Low-level bi-directional byte relay is used
   to handle the CONNECT method without decrypting the TLS payload.
   """
   def forward(src, dst):
       try:
           while True:
               data = src.recv(BUFFER_SIZE)
               if not data: break
               dst.sendall(data)
       except: pass
  
   # Spawning threads for manual bi-directional data transfer
   threading.Thread(target=forward, args=(client, remote), daemon=True).start()
   forward(remote, client)


def extract_host_port(request, method):
   """
   Manual header parsing: raw request lines are iterated through
   to find the hosts header and port information.
   """
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
   """CLI interface to manage blocklist"""
   global blocked_urls
   while True:
       print("\nPROXY COMMANDS")
       print("1: Block URL, 2: Unblock URL, 3: List Blocked")
       cmd = input("Select:")
       if cmd == '1':
           url = input("Enter site to block:")
           with lock: blocked_urls.add(url)
           print(f"[*] {url} blocked.")
       elif cmd == '2':
           url = input("Enter site to unblock:")
           with lock: blocked_urls.discard(url)
           print(f"[*] {url} unblocked.")
       elif cmd == '3':
           print(f"Current Blocklist: {list(blocked_urls)}")


def start():
   """
   Initialises master server socket.
   Using 'SO_REUSEADDR' ensures port can be reclaimed immediately.
   """
   server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
   server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
   server.bind((PROXY_HOST, PROXY_PORT))
   server.listen(100) # Queue of up to 100 concurrent requests
  
   # Threading used to keep the console alive while the server runs
   threading.Thread(target=management_console, daemon=True).start()
  
   print(f"[*] Multi-threaded Proxy running on Port {PROXY_PORT}...")
   while True:
       conn, addr = server.accept()
       # Threading for each connection allows for handling multiple clients at once
       threading.Thread(target=handle_client, args=(conn, addr)).start()


if __name__ == "__main__":
   start()