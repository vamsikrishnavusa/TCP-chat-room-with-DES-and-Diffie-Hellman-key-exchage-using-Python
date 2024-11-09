import socket, threading
from AES import AESCipher
from key_exchange import DiffieHellman

class Server:
    def __init__(self):
        # default port is choosen as 5068
        self.port=10544
        self.host=socket.gethostbyname(socket.gethostname())
        # server socket object
        self.server=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # message size
        self.header=1024
        # encoding format
        self.format="utf-8"
        self.server_key=DiffieHellman()
        self.server_pub_key=str(self.server_key.gen_public_key())
        # map to store the names of client
        self.client_names={}
        # map to store the keys of client
        self.client_keys={}
        self.disconnect='exit'


    # function to send messages to all other host
    def broadcast(self,msg):
        for client in self.client_names:
            # creating aes object of client
            aes=AESCipher(self.client_keys[client])
            # encrypting the message and sending it
            crypted_msg=aes.encrypt(msg)
            client.send(crypted_msg)
    
    def askName(self, client):
        # get the name of the client and store it in the map
        msg=client.recv(self.header).decode(self.format)
        self.client_names[client]=msg

    def exchangeKeys(self, client):
        # exchanging keys
        # sending public key of server
        client.send((self.server_pub_key).encode(self.format))
        # receiving public key of client
        client_pub_key=int(client.recv(self.header).decode(self.format))
        # generating pvt key
        client_pvt_key=self.server_key.gen_shared_key(client_pub_key)
        # storing the pvt key of server for that client
        self.client_keys[client]=client_pvt_key

    # function to handle a client
    def handle_client(self,client,client_addr):

        client_pvt_key=self.client_keys[client]
        client_name=self.client_names[client]

        print(f"[{client_addr[0]}]-{client_addr[1]} - [{client_name}] - Connected")
        print(f"Active Connections - {threading.active_count()-1}")
        # inform everyone that 'this client' has joined the server
        self.broadcast(f'{client_name} has joined the chat!\n')
        # receive message until there is an error at client side

        # creating aes object with the pvt key
        aes=AESCipher(client_pvt_key)
        

        while True:
            try:
                # decrypt the received message
                msg = aes.decrypt(client.recv(self.header))
                # if message states to disconnect then break from the loop
                if msg==self.disconnect:
                    break
                print(f"[{client_addr[0]}]-{client_addr[1]} - [{client_name}] - {msg}")
                # add client name to the message and broadcast to every clients
                msg=f'{client_name}: {msg}'
                self.broadcast(msg)
            except:
                break
        # close the connection
        client.close()
        print(f"[{client_addr[0]}]-{client_addr[1]} - [{client_name}] - Disconnected")
        del self.client_names[client]
        del self.client_keys[client]
        # inform everyone 'this client' has left the server
        self.broadcast(f'{client_name} has left the chat\n')
        print(f"Active Connections - {threading.active_count()-2}")


    # function to start the server
    def start_server(self):
        self.server.bind((self.host,self.port))
        # set the server to listening mode
        self.server.listen()
        print(f"Server is starting...\nServer [{self.host}] is ready to accept connections!")
        while True:
            # server accepting new socket object i.e. our client
            # and it's address
            client, client_addr = self.server.accept()
            self.askName(client)
            self.exchangeKeys(client)
            # Running multiple client/s concurrently using threading
            thread = threading.Thread(target=self.handle_client, args=(client, client_addr))
            thread.start()
       
# start server
s=Server()
s.start_server()