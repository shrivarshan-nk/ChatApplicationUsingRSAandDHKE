import socket
import tkinter as tk
from tkinter import scrolledtext
import threading
import random
import sympy

class ChatServer:
    def __init__(self, host, port):
        # Socket setup
        self.s = socket.socket()
        self.s.bind((host, port))
        print('Server will start on host:', host)
        print('Waiting for connections')
        self.s.listen(2)

        # GUI setup
        self.root = tk.Tk()
        self.root.title('Chat Server')

        self.chat_box = scrolledtext.ScrolledText(self.root, width=40, height=10)
        self.chat_box.pack(padx=10, pady=10)

        # Dictionary to store connected clients and their shared keys
        self.clients = {}

        # Start accepting clients in a separate thread
        accept_clients_thread = threading.Thread(target=self.accept_clients)
        accept_clients_thread.start()

        # Close the GUI properly
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)
        self.root.mainloop()

    def handle_client_connection(self, client_socket, address):
        # Perform Diffie-Hellman key exchange
        user=client_socket.recv(1024)
        user=user.decode()
        prime, primitive_root = self.get_prime_and_primitive_root()
        private_key, public_key = self.generate_key_pair(prime, primitive_root)
        
        # Send prime and public_key to the client
        client_socket.send(f'{prime},{primitive_root},{public_key}'.encode())

        # Receive the client's public key
        client_public_key = int(client_socket.recv(1024).decode())

        # Calculate the shared secret key
        shared_key = self.calculate_shared_secret(client_public_key, private_key, prime)
        
        #RSA public key
        client_n_rsa = int(client_socket.recv(1024).decode())
        client_e_rsa = int(client_socket.recv(1024).decode())
        client_public_key_rsa=(client_n_rsa,client_e_rsa)
        print("RSA Client",client_public_key_rsa)
        
        # Store client data
        self.clients[address] = {"socket": client_socket, "shared_key": shared_key,"username":user,"rsa_public_key":client_public_key_rsa}
        question="Whom would you chat to ?"
        encrypted_message = self.encrypt_message(question,shared_key)
        client_socket.send(encrypted_message.encode())
        chat_username = client_socket.recv(1024)
        chat_username = chat_username.decode()
        decrypted_username = self.decrypt_message(chat_username, shared_key)
        self.chat_box.insert(tk.END, f'{decrypted_username}\n')
        
        #Send Rsa public key
        for client_data in self.clients.values():
            if client_data["username"]==decrypted_username:
                receiver_public_key_rsa=client_data["rsa_public_key"]
        
        self.send_rsa_public_key(receiver_public_key_rsa, client_socket,shared_key)
        
        
        while True:
            try:
                incoming_message = client_socket.recv(1024)
                if not incoming_message:
                    break
                incoming_message = incoming_message.decode()                    
                decrypted_message = self.decrypt_message(incoming_message, shared_key)
                # Display the encrypted and decrypted messages in the server's GUI
                self.chat_box.insert(tk.END, f'{user} to server: {incoming_message}\n')
                self.chat_box.insert(tk.END, f'{user} to server decrypted: {decrypted_message}\n')
                self.broadcast(f'{decrypted_message}', client_socket,decrypted_username)
            except socket.error:
                break

        # Remove the client from the dictionary upon disconnection
        del self.clients[address]
        client_socket.close()

    def accept_clients(self):
        while True:
            try:
                conn, addr = self.s.accept()
                print(addr, 'has connected to the server')

                # Start a new thread to handle the client connection
                client_thread = threading.Thread(target=self.handle_client_connection, args=(conn, addr))
                client_thread.start()
            except socket.error:
                break

    def on_closing(self):
        for client_data in self.clients.values():
            client_data["socket"].close()
        self.s.close()
        self.root.destroy()
        
    def send_rsa_public_key(self,rsa_public_key,sender_socket,shared_key):
      
        encrypted_message = self.encrypt_message("Sending RSA Key", shared_key)
        sender_socket.send(encrypted_message.encode())
        encrypted_message = self.encrypt_message(str(rsa_public_key[0]), shared_key)
        sender_socket.send(encrypted_message.encode())
        encrypted_message = self.encrypt_message(str(rsa_public_key[1]), shared_key)
        sender_socket.send(encrypted_message.encode())

    def broadcast(self, message, sender_socket,user):
        for client_data in self.clients.values():
            if client_data["socket"] != sender_socket and client_data["username"]==user:
                encrypted_message = self.encrypt_message(message, client_data["shared_key"])
                client_data["socket"].send(encrypted_message.encode())
                self.chat_box.insert(tk.END, f'Server to {user}: {encrypted_message}\n')

    def get_prime_and_primitive_root(self):
        prime = sympy.randprime(10, 922337)
        primitive_root = self.find_primitive_root(prime)
        return prime, primitive_root

    def is_primitive_root(self, g, p):
        residues = set()
        for i in range(1, p):
            residues.add(pow(g, i, p))
        return len(residues) == p - 1

    def find_primitive_root(self, p):
        for g in range(2, p):
            if self.is_primitive_root(g, p):
                return g

    def mod_exp(self, base, exp, mod):
        result = 1
        base = base % mod
        while exp > 0:
            if exp % 2 == 1:
                result = (result * base) % mod
            exp = exp // 2
            base = (base * base) % mod
        return result

    def generate_key_pair(self, prime, primitive_root):
        private_key = random.randint(2, prime - 2)
        public_key = self.mod_exp(primitive_root, private_key, prime)
        return private_key, public_key

    def calculate_shared_secret(self, public_key, private_key, prime):
        return self.mod_exp(public_key, private_key, prime)

    def encrypt_message(self, message, key):
        encrypted_message = "".join([chr(ord(char) ^ key) for char in message])
        return encrypted_message

    def decrypt_message(self, encrypted_message, key):
        decrypted_message = "".join([chr(ord(char) ^ key) for char in encrypted_message])
        return decrypted_message
    



if __name__ == "__main__":
    server = ChatServer(socket.gethostname(), 8080)