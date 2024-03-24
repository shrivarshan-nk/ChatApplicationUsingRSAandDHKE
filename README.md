# ChatApplicationUsingRSAandDHKE
This is a simple chat application which uses the concept of DHKE and RSA to securely encrypt and decrypt messages.

Protocol Steps:
The proposed model for the secure chat application involves a combination of the DiffieHellman key exchange protocol for user authentication and the RSA encryption protocol 
for end-to-end communication. Below are the protocol steps outlining how these 
cryptographic protocols are utilized in the proposed model:
1. User Authentication using Diffie-Hellman Key Exchange:
1. Server Initialization:
  • The server initializes a socket and GUI components for communication.
  • It starts listening for incoming connections.
2. Client Connection:
  • A client initiates a connection to the server.
  • The server accepts the client connection and starts a separate thread to 
handle the communication with that client.
3. Diffie-Hellman Key Exchange:
  • The server and client engage in the Diffie-Hellman key exchange for user 
authentication.
  • The server generates a prime number (prime) and a primitive root 
(primitive_root) and shares them with the client.
  • The server and client each generate a private key (private_key) and a 
public key (public_key) using the received prime and primitive root.
  • The client sends its public key to the server.
4. Shared Secret Calculation:
  • The server and client calculate a shared secret key (shared_key) using 
their private and the received public keys.
5. RSA Key Exchange:
  • The client generates RSA public and private key pairs (public_key_rsa, 
private_key_rsa).
  • The client sends its RSA public key to the server.
6. Client Authentication and User Interaction:
  • The server receives the client's RSA public key and stores it along with the 
shared key for that client.
  • The server prompts the user to choose a chat partner and initiates a secure 
question-answer exchange to establish a shared RSA public key for 
communication.
  • The server sends the RSA public key of the chosen chat partner to the 
client.
2. End-to-End Communication using RSA Encryption:
1. Secure Question-Answer Exchange:
  • The server sends a secure question to the client, encrypted using the shared 
key.
  • The client decrypts the question using the shared key and responds 
securely.
2. RSA Key Exchange Confirmation:
  • The client sends a confirmation to the server, indicating successful RSA 
key exchange.
  • Both the server and client update their dictionaries to include the RSA 
public key of their chat partner.
3. Message Sending (Client):
  • The client enters a message in the GUI, encrypts it using RSA, and sends 
the encrypted message to the server.
4. Message Receiving (Server):
  • The server receives the encrypted message from the client and decrypts it 
using its RSA private key.
  • The decrypted message is then broadcasted to the chosen chat partner(s).
5. Message Display (Client):
  • The client receives the encrypted message from the server, decrypts it 
using its RSA private key, and displays the decrypted message in the GUI.
6. Real-time Communication:
  • The server and clients continue to exchange messages in real-time, 
ensuring that all communications are securely encrypted and decrypted 
using the shared keys and RSA key pairs.
