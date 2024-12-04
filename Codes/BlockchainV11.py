import time
import struct
import socket
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os


'''
This code receive data from Simulink using UDP block, after that process 
data and sign them each agent using its private key and send it to blockchain.
blockchain with public key of each agent do the validation of data and put the datas in each 
step in a block. After that blockchain sign the data and send them to each agent and each agent do the validation using 
public key of each agent. Finally the data send to Simulink using UDP block for process the data for control the system. 
'''
# Blockchain setup
class Blockchain:
    def __init__(self):
        self.private_key = None
        self.public_key = None
        self.agent_keys = {}  # Public keys of agents
        self.chain = []  # Blockchain
        self.generate_keys()

    def generate_keys(self):
        """
        Generate RSA key pair for the blockchain.
        """
        self.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        self.public_key = self.private_key.public_key()

    def add_agent_key(self, agent_id, public_key):
        """
        Add the public key of an agent to the blockchain.
        """
        self.agent_keys[agent_id] = public_key

    def verify_signature(self, public_key, data, signature):
        """
        Verify the signature using the public key of the agent.
        """
        hashed_data = self.hash_data(data)
        try:
            public_key.verify(
                signature,
                hashed_data,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            return True
        except Exception as e:
            print(f"Signature verification failed: {e}")
            return False

    def sign_data(self, data):
        """
        Sign data with the blockchain's private key.
        """
        hashed_data = self.hash_data(data)
        signature = self.private_key.sign(
            hashed_data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return signature

    def add_block(self, data):
        """
        Add a new block to the blockchain.
        """
        block = {
            "index": len(self.chain) + 1,
            "timestamp": time.time(),
            "data": data
        }
        self.chain.append(block)

    @staticmethod
    def hash_data(data):
        """
        Create a SHA-256 hash of the data.
        """
        digest = hashes.Hash(hashes.SHA256())
        digest.update(data.encode('utf-8'))
        return digest.finalize()

    @staticmethod
    def encrypt_data(data, key):
        """
        Encrypt data using AES encryption with a shared key.
        """
        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(key), modes.CFB(iv))
        encryptor = cipher.encryptor()
        encrypted_data = encryptor.update(data.encode()) + encryptor.finalize()
        return iv + encrypted_data

    @staticmethod
    def decrypt_data(encrypted_data, key):
        """
        Decrypt AES encrypted data with the shared key.
        """
        iv = encrypted_data[:16]
        ciphertext = encrypted_data[16:]
        cipher = Cipher(algorithms.AES(key), modes.CFB(iv))
        decryptor = cipher.decryptor()
        decrypted_data = decryptor.update(ciphertext) + decryptor.finalize()
        return decrypted_data.decode()


# Agent setup
class Agent:
    def __init__(self, agent_id):
        self.agent_id = agent_id
        self.private_key = None
        self.public_key = None
        self.shared_key = os.urandom(32)  # Shared AES key for encryption
        self.generate_keys()

    def generate_keys(self):
        """
        Generate RSA key pair for the agent.
        """
        self.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        self.public_key = self.private_key.public_key()

    def sign_data(self, data):
        """
        Sign data with the agent's private key.
        """
        hashed_data = Blockchain.hash_data(data)
        signature = self.private_key.sign(
            hashed_data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return signature

    def verify_signature(self, public_key, data, signature):
        """
        Verify the signature using the public key.
        """
        hashed_data = Blockchain.hash_data(data)
        try:
            public_key.verify(
                signature,
                hashed_data,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            return True
        except Exception as e:
            print(f"Signature verification failed for {self.agent_id}: {e}")
            return False



# UDP Configuration
UDP_RECEIVE_IP = "127.0.0.1"  # IP for receiving data from Simulink
UDP_RECEIVE_PORT = 5005       # Port for receiving data from Simulink
UDP_SEND_IP = "127.0.0.1"     # IP for sending data back to Simulink
UDP_SEND_PORT = 5006          # Port for sending data back to Simulink
BUFFER_SIZE = 1024            # Buffer size for UDP packets

# Initialize UDP sockets
udp_receive_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
udp_receive_socket.bind((UDP_RECEIVE_IP, UDP_RECEIVE_PORT))
udp_send_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)


def process_data():
    """
    Process real-time data from Simulink and handle encryption, signing, and verification.
    """
    # Initialize blockchain and agents
    blockchain = Blockchain()
    agents = {f"agent_{i}": Agent(f"agent_{i}") for i in range(1, 7)}  # Example: 6 agents

    # Register agent public keys in the blockchain
    for agent_id, agent in agents.items():
        blockchain.add_agent_key(agent_id, agent.public_key)

    while True:
        # Step 1: Receive data from Simulink
        data, addr = udp_receive_socket.recvfrom(BUFFER_SIZE)

        # Step 2: Unpack data (6 agents * 2 values for voltage and frequency)
        received_data = {}
        for i in range(6):
            voltage, frequency = struct.unpack('<dd', data[i * 16:(i + 1) * 16])
            received_data[f"agent_{i + 1}"] = {"voltage": voltage, "frequency": frequency}

        # Step 3: Each agent signs and encrypts data, then sends to blockchain
        for raw_agent_id, values in received_data.items():
            agent = agents[raw_agent_id]  # استفاده مستقیم از کلید درست

            payload = {
                "voltage": values["voltage"],
                "frequency": values["frequency"],
                "time": time.time()
            }
            payload_str = str(payload)

            # Agent signs data
            signature = agent.sign_data(payload_str)

            # Encrypt data with blockchain's shared key
            encrypted_data = Blockchain.encrypt_data(payload_str, agent.shared_key)

            # Blockchain verifies signature
            is_valid = blockchain.verify_signature(agent.public_key, payload_str, signature)
            if is_valid:
                blockchain.add_block(payload)  # Add block to the blockchain
                # print(f"Data from {raw_agent_id} added to blockchain.")
            # else:
                # print(f"Data verification failed for {raw_agent_id}.")

            # Step 4: Blockchain signs and encrypts data for agent
            blockchain_signature = blockchain.sign_data(payload_str)
            encrypted_response = Blockchain.encrypt_data(payload_str, agent.shared_key)

            # Agent decrypts and verifies
            decrypted_response = Blockchain.decrypt_data(encrypted_response, agent.shared_key)
            response_valid = agent.verify_signature(blockchain.public_key, decrypted_response, blockchain_signature)

            if response_valid:
                # print(f"Response verified successfully by {raw_agent_id}.")

                # Step 7: Send back to Simulink
                response_data = struct.pack('<dd', values["voltage"], values["frequency"])
                udp_send_socket.sendto(response_data, (UDP_SEND_IP, UDP_SEND_PORT))
            # else:
                # print(f"Response verification failed for {raw_agent_id}.")


# Run the process_data function
process_data()
