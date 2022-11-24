# Server to implement the simplified RSA algorithm and receive encrypted
# integers from a client.
# The server waits for the client to say Hello. Once the client says hello,
# the server sends the client a public key. The client uses the public key to
# send a session key with confidentiality to the server.

# Author: 
# Last modified: 2022-11-13
# Version: 0.1
#!/usr/bin/python3

import socket
import random
import math
import hashlib
import time
import sys
import simplified_AES
import NumTheory


class RSAServer(object):
    
    def __init__(self, port, p, q):
        self.socket = socket.socket()
        # The option below is to permit reuse of a socket in less than an MSL
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.socket.bind(("", int(port)))
        self.socket.listen(5)
        self.lastRcvdMsg = None
        self.sessionKey = None		#For storing the symmetric key
        self.modulus = None		#For storing the server's n in the public/private key
        self.pubExponent = None	#For storing the server's e in the public key
        self.privExponent = None	#For storing the server's d in the private key
        self.nonce = None
        self.decryptedNonce = None
        self.p = p 
        self.q = q 
        # Call the methods to compute the public private/key pairs
        # Add code to initialize the candidates and their IDs

    def send(self, conn, message):
        #self.socket.connect((self.address, self.port))
        conn.send(bytes(message,'utf-8'))

    def read(self, conn):
        try:
            data = conn.recv(4096).decode('utf-8')
        except BlockingIOError:
            pass
        else:
            if data:
                self.lastRcvdMsg = data
            else:
                raise RuntimeError("Client is unavailable")

    def close(self, conn):
        print("closing server side of connection")
        try:
            conn.close()
        except OSError as e:
            print(
                "error: socket.close() exception for",
                f" {repr(e)}",
            )
        finally:
            # Delete reference to socket object
            conn = None    

    def RSAencrypt(self, msg):
        """Encryption side of RSA"""
        """"This function will return (msg^exponent mod modulus) and you *must*"""
        """ use the expMod() function. You should also ensure that msg < n before encrypting"""
        """You will need to complete this function."""
        """You will need to complete this function."""
        return NumTheory.NumTheory.expMod(cText, self.pubExponent, self.modulus)

    def RSAdecrypt(self, cText):
        """Decryption side of RSA"""
        """"This function will return (cText^exponent mod modulus) and you *must*"""
        """ use the expMod() function"""
        """You will need to complete this function."""
        return NumTheory.NumTheory.expMod(cText, self.privExponent, self.modulus)

    def AESdecrypt(self, cText):
        """Decryption side of AES"""
        simplified_AES.keyExp(self.sessionKey)
        return simplified_AES.decrypt(cText)

    def AESencrypt(self, plaintext):
        """Computes the simplified AES encryption of some plaintext"""
        simplified_AES.keyExp(self.sessionKey) # Generating round keys for AES.
        ciphertext = simplified_AES.encrypt(plaintext) # Running simplified AES.
        return ciphertext

    def generateNonce(self):
        """This method returns a 16-bit random integer derived from hashing the
            current time. This is used to test for liveness"""
        hash = hashlib.sha1()
        hash.update(str(time.time()).encode('utf-8'))
        self.nonce = int.from_bytes(hash.digest()[:2], byteorder=sys.byteorder)

    def findE(self, phi):
        """Method to randomly choose a good e given phi"""
        """You will need to complete this function."""
        phiVal = phi
        dp = -1
        while (phiVal >=1):
            phiVal = phiVal/10
            dp += 1

        ph = 10**dp + 1

        e = random.randrange(ph, phi-1)
        prime = NumTheory.NumTheory.gcd_iter(e, phi)
        while (e < phi):
            if (prime == 1):
                return e
            e = random.randrange(ph, phi-1)
        

    def genKeys(self, p, q):
        """Generates n, phi(n), e, and d"""
        """You will need to complete this function."""
        """Generates n, phi(n), e, and d"""
        """You will need to complete this function."""
        "Write a function that receives as its parameters primes p and q, calculates "
        "public and private RSA keys using these parameters. You should print n, φ(n), d,"
        "and e to standard output. You must use the Extended Euclidean Algorithm to compute d."
        n = p * q 
        phi = (p-1) * (q-1)
        e = 0
        d = 0

        while (e == d):
            e = self.findE(phi)
            d = NumTheory.NumTheory.ext_Euclid(phi, e)
            if (d < 0):
                d += phi

        self.modulus = n
        self.privExponent = d
        self.pubExponent = e
        
        print ("n = " + str(n))
        print ("phi(n) = " + str(phi))
        print ("e = " + str(e))
        print ("d = " + str(d))
        



    def clientHelloResp(self):
        """Generates response string to client's hello message"""
        self.generateNonce()
        status = "102 Hello AES, RSA16 " + str(self.modulus) + " " + \
         str(self.pubExponent) + " " + str(self.nonce)
        return status

    def getSessionKey(self,msg):
      
        return self.RSAdecrypt(int(msg.split(" ")[-2]))

    def getNonce(self,msg):
        """Function to get the Nonce sent by the client"""
        return self.AESdecrypt(int(msg.split(" ")[-1]))

    def nonceVerification(self, decryptedNonce):
        """Verifies that the transmitted nonce matches that received
        from the client."""
        """You will need to complete this function."""
        if (self.nonce == decryptedNonce):
            return True
        else:
            return False


    def start(self):
        """Main sending and receiving loop"""
        """You will need to complete this function"""
        while True:
            # print ("p = " + str(self.p))
            self.genKeys(self.p, self.q)
            connSocket, addr = self.socket.accept()
            msg = connSocket.recv(1024).decode('utf-8')
            print (msg)
            self.send(connSocket, self.clientHelloResp())
            self.read(connSocket)
            msg = self.lastRcvdMsg
            print (msg)
            self.sessionKey = self.getSessionKey(self.lastRcvdMsg)
            # print("key =  ",self.sessionKey)
            self.decryptedNonce = self.getNonce(self.lastRcvdMsg)
            print("nonce =  ",self.decryptedNonce)
            if self.nonceVerification(self.decryptedNonce):
                self.send(connSocket, "106 Nonce Verified")
                self.read(connSocket)
                msg = self.lastRcvdMsg
                print (msg)
                firstPrime = self.lastRcvdMsg.split(" ")[-1] 
                SecondPrime = self.lastRcvdMsg.split(" ")[-2] 
                firstPrime = self.AESdecrypt(int(firstPrime))
                SecondPrime = self.AESdecrypt(int(SecondPrime))
                print (firstPrime)
                print (SecondPrime)
                # product = firstPrime * SecondPrime
                product = math.prod([int(firstPrime), int(SecondPrime)])
                print (product)
                product = self.AESencrypt(product)
                self.send(connSocket, "125 CompositeEncrypted " + str(product))
                self.read(connSocket)
                print(self.lastRcvdMsg)
                self.close(connSocket)
                self.socket.close()
                print()
            # else:
            #     self.send(connSocket, "404 Error")
            self.close(connSocket)
            break

def main():
    """Driver function for the project"""
    args = sys.argv
    if len(args) != 2:
        print ("Please supply a server port.")
        sys.exit()
        
    HOST = ''		# Symbolic name meaning all available interfaces
    PORT = int(args[1])     # The port on which the server is listening
    if PORT < 1023 or PORT > 65535:
        print("Invalid port specified.")
        sys.exit()
    print("Server of ________")
    print ("Enter prime numbers. One should be between 211 and 281, and\
 the other between 229 and 307")
    p = int(input('Enter P: '))
    q = int(input('Enter Q: '))
    
    server = RSAServer(PORT, p, q)
    server.start()

if __name__ == "__main__":
    main()
