import socket
import tkinter as tk
from tkinter import scrolledtext, Entry, Button
import threading
import random,sympy

class ChatClient:
    def __init__(self, host, port,username):
        self.s = socket.socket()

        # GUI setup
        self.root = tk.Tk()
        self.root.title(username+' Chat Client')

        self.chat_box = scrolledtext.ScrolledText(self.root, width=40, height=10)
        self.chat_box.pack(padx=10, pady=10)

        self.message_entry = Entry(self.root, width=30)
        self.message_entry.pack(padx=10, pady=10)

        self.send_button = Button(self.root, text='Send', command=self.send_message)
        self.send_button.pack(padx=10, pady=10)

        # Connect to the server
        self.s.connect((host, port))
        print('Connected to chat server')
        self.s.send(str(username).encode())
        # Receive prime and base from the server
        prime, base, server_public_key = map(int, self.s.recv(1024).decode().split(','))

        # Generate private key and send the public key to the server
        self.private_key, self.public_key = self.generate_key_pair(prime, base)
        self.s.send(str(self.public_key).encode())
        #print("Client_public_key", self.public_key)

        # Calculate the shared secret key
        self.shared_key = self.calculate_shared_secret(server_public_key, self.private_key, prime)
        #print("Shared key", self.shared_key)
        
        #Generate RSA 
        self.public_key_rsa,self.private_key_rsa=self.generate_keypair_rsa()
        #print("Rsa public",self.public_key_rsa)
        self.s.send(str(self.public_key_rsa[0]).encode())
        self.s.send(str(self.public_key_rsa[1]).encode())
        self.user_public_rsa_key=()

        # Notify the user about successful key exchange
        self.chat_box.insert(tk.END, "Key exchange successful.\n")

        # Start receiving messages in a separate thread
        self.receive_thread = threading.Thread(target=self.receive_messages)
        self.receive_thread.start()
        

        # Close the socket and GUI properly
        self.root.protocol("WM_DELETE_WINDOW", lambda: self.close())
        self.root.mainloop()

    def receive_messages(self):
        while True:
            try:
                incoming_message = self.s.recv(1024)
                incoming_message = incoming_message.decode()
                if len(self.user_public_rsa_key)==0:
                    decrypted_message = self.decrypt_message(incoming_message, self.shared_key)
                    if decrypted_message=="Sending RSA Key":
                        user_public_rsa_n_key=self.s.recv(1024)
                        user_public_rsa_n_key=user_public_rsa_n_key.decode()
                        user_public_rsa_n_key=self.decrypt_message(user_public_rsa_n_key, self.shared_key)
                        user_public_rsa_e_key=self.s.recv(1024)
                        user_public_rsa_e_key=user_public_rsa_e_key.decode()
                        user_public_rsa_e_key=self.decrypt_message(user_public_rsa_e_key, self.shared_key)
                        self.user_public_rsa_key=(int(user_public_rsa_n_key),int(user_public_rsa_e_key))  
                        self.chat_box.insert(tk.END, "RSA Key exchange successful. You can now start chatting.\n")
                        self.chat_box.insert(tk.END, "Receipient RSA Key: \n")
                        self.chat_box.insert(tk.END, f'{self.user_public_rsa_key}\n')
                        #print("Other client key ",self.user_public_rsa_key)
                    else:
                        self.chat_box.insert(tk.END, f'{decrypted_message}\n')
                else:
                    decrypted_message = self.decrypt_message(incoming_message, self.shared_key)
                    decrypted_message = self.to_list(decrypted_message)                   
                    #print("Before decryption",decrypted_message)
                    #print()
                    decrypted_message=''.join(str(p) for p in self.rsa_decoder(decrypted_message))
                    # decrypted_message=self.rsa_decoder(decrypted_message, self.private_key_rsa)
                    self.chat_box.insert(tk.END, f'{decrypted_message}\n')
                    
                    
            except socket.error:
                break
    def receive_rsa_key(self):
        pass
        

    def send_message(self):
        message = self.message_entry.get()
        
        if message:
            self.message_entry.delete(0, tk.END)
            if len(self.user_public_rsa_key)==0:
                encrypted_message = self.encrypt_message(message, self.shared_key)
                self.s.send(encrypted_message.encode())
            else:
                encrypted_message=self.rsa_encoder(message, self.user_public_rsa_key)
                encrypted_message_str=str(encrypted_message)
                #print(encrypted_message_str)
                encrypted_message_dh = self.encrypt_message(encrypted_message_str, self.shared_key)
                self.s.send(encrypted_message_dh.encode())
            self.chat_box.insert(tk.END, f'{" " * (35 - len(message))}You: {message}\n')

                
    def encrypt_message(self, message, key):
        encrypted_message = "".join([chr(ord(char) ^ key) for char in message])
        return encrypted_message

    def decrypt_message(self, encrypted_message, key):
        decrypted_message = "".join([chr(ord(char) ^ key) for char in encrypted_message])
        return decrypted_message

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
    
    #RSA Functions
    def generate_keypair_rsa(self):
        # Generate two large prime numbers, p and q
        p = sympy.randprime(2,5000)
        q = sympy.randprime(2,5000)
    
        # Calculate n (the modulus)
        n = p * q
    
        # Calculate the totient of n
        totient = (p - 1) * (q - 1)
    
        # Choose an e that is relatively prime to totient
        e = self.choose_public_exponent(totient)
    
        # Calculate the private key (d)
        d = sympy.mod_inverse(e, totient)
    
        # Return the public and private keys
        return (n, e), (n, d)
    
    
    def choose_public_exponent(self,totient):
        # Choose a public exponent (e) that is relatively prime to totient
        e = random.randint(2, totient - 1)
        while not self.is_relatively_prime(e, totient):
            e = random.randint(2, totient - 1)
        return e
    
    def is_relatively_prime(self,a, b):
        # Check if two numbers are relatively prime
        while b:
            a, b = b, a % b
        return a == 1
    
    def rsa_encrypt(self,message,public_key):
    	n,e = public_key
    	encrypted_text = 1
    	while e > 0:
    		encrypted_text *= message
    		encrypted_text %= n
    		e -= 1
    	return encrypted_text
    
    def rsa_decrypt(self,encrypted_text,private_key):
    	n, d = private_key
    	decrypted = 1
    	while d > 0:
    		decrypted *= encrypted_text
    		decrypted %= n
    		d -= 1
    	return decrypted
    
    def rsa_encoder(self,message,key):
    	encoded = []
    	# Calling the encrypting function in encoding function
    	for letter in message:
    		encoded.append(self.rsa_encrypt(ord(letter),key))
    	return encoded
    
    def rsa_decoder(self,encoded):
    	s = ''
    	# Calling the decrypting function decoding function
    	for num in encoded:
    		s += chr(self.rsa_decrypt(num,self.private_key_rsa))
    	return s
    
    def to_list(self,message):
        message=message.split("[")
        inter_msg=message[1].split("]")
        inter_msg.pop(-1)
        msg=inter_msg[0].split(",")
        final_list=[]
        for i in range(len(msg)):
            final_list.append(int(msg[i]))
        return final_list    

    def close(self):
        self.s.close()
        self.root.destroy()

if __name__ == "__main__":
    username= input("Enter Username: ")
    host_input = input(str('Enter hostname or host IP: '))
    port_input = 8080
    client = ChatClient(host_input, port_input,username)
