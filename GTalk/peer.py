import socket
import threading
import os
import time
from datetime import datetime, timedelta
from kademlia.network import Server as DHTServer  # DHT Library for peer discovery

# Configuration
CHAT_PORT = 12345               # Port for chat communication
CHAT_HISTORY_FILE = 'chat_history.txt'
HISTORY_SYNC_PERIOD = 24 * 60 * 60  # Sync 24 hours of history

# DHT Server to discover peers globally
dht_server = DHTServer()
bootstrap_nodes = [('router.bittorrent.com', 6881), ('dht.transmissionbt.com', 6881)]

# Global list of discovered peers (based on DHT)
peers = set()

# Function to save message to chat history
def save_message(message):
    with open(CHAT_HISTORY_FILE, 'a') as f:
        f.write(f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')} {message}\n")

# Function to load chat history for the last 24 hours
def load_chat_history():
    if not os.path.exists(CHAT_HISTORY_FILE):
        return []

    history = []
    with open(CHAT_HISTORY_FILE, 'r') as f:
        lines = f.readlines()

    now = datetime.now()
    for line in lines:
        timestamp_str, message = line.split(' ', 1)
        timestamp = datetime.strptime(timestamp_str, '%Y-%m-%d %H:%M:%S')
        if now - timestamp <= timedelta(seconds=HISTORY_SYNC_PERIOD):
            history.append(line)

    return history

# Function to send the last 24 hours of chat history to a peer
def send_chat_history(client_socket):
    history = load_chat_history()
    for line in history:
        client_socket.send(line.encode('utf-8'))

# Function to handle incoming messages and save them
def handle_client(client_socket, client_address):
    print(f"[NEW CONNECTION] A peer connected.")
    while True:
        try:
            message = client_socket.recv(1024).decode('utf-8')
            if not message:
                break
            print(f"[PEER] Someone said: {message}")
            save_message(f"Someone said: {message}")
        except:
            break
    client_socket.close()

# Server thread for accepting connections
def start_server():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(('', CHAT_PORT))
    server.listen()

    print(f"[LISTENING] Server is listening on port {CHAT_PORT}")

    while True:
        client_socket, client_address = server.accept()
        send_chat_history(client_socket)  # Send chat history upon connection
        thread = threading.Thread(target=handle_client, args=(client_socket, client_address))
        thread.start()

# Function to send messages to the peer
def send_messages(client_socket):
    while True:
        message = input("You: ")
        client_socket.send(message.encode('utf-8'))
        save_message(f"You: {message}")

# Function to receive messages from the peer
def receive_messages(client_socket):
    while True:
        try:
            message = client_socket.recv(1024).decode('utf-8')
            if not message:
                break
            print(f"[PEER] Someone said: {message}")
            save_message(f"Someone said: {message}")
        except:
            print("[ERROR] Connection lost.")
            break

# Client thread for connecting to peers and syncing history
def connect_to_peer(peer_ip):
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect((peer_ip, CHAT_PORT))

    send_thread = threading.Thread(target=send_messages, args=(client_socket,))
    receive_thread = threading.Thread(target=receive_messages, args=(client_socket,))
    
    send_thread.start()
    receive_thread.start()

    send_thread.join()
    receive_thread.join()

# DHT Peer Discovery
def start_dht():
    global peers
    dht_server.listen(8468)
    dht_server.bootstrap(bootstrap_nodes)

    while True:
        for peer_id, peer_addr in dht_server.get_known_peers():
            if peer_addr not in peers:
                peers.add(peer_addr)
                print(f"[PEER DISCOVERED] {peer_addr}")
                threading.Thread(target=connect_to_peer, args=(peer_addr,)).start()
        time.sleep(10)  # Check every 10 seconds

# Main function to start both server and peer discovery
if __name__ == "__main__":
    # Start server for chat communication
    server_thread = threading.Thread(target=start_server)
    server_thread.start()

    # Start DHT peer discovery
    dht_thread = threading.Thread(target=start_dht)
    dht_thread.start()

    server_thread.join()
    dht_thread.join()
