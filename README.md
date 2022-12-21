## Introduction: 
The group chat program created allows for group message sharing between a minimum of three members. In this report, a brief overview of the communication process is explained, followed by a discussion on the security mechanisms put in place. The security features used are then justified and tested to ensure integrity, authenticity and confidentiality is established in each message sent. 

## Communication process:
The server class is run first and continuously listens for any incoming client connections entering its socket through its port. For a client class to establish a connection once it is run, it needs to create its socket with the server’s IP address/local host name and port number. Once the server accepts the TCP connection, it moves and runs the instance of the client on a new thread. The client then registers with the server by sending the server its certificate containing its public key KUCLIENT, signed with the certificate authority’s (CA) private key KRCA. The server verifies the authenticity of the certificate sent and either accepts the client, if the server’s CA public key is its pair, or rejects the client and disconnects that client from the socket. When the client is accepted, a session key KSServerClient is generated and sent to that individual client instance, which will be used for encrypting the messages sent between that instance of the client and the server. The certificates of all connected clients are then encrypted on the server with their individual KSServerClient and broadcasted to those clients to enable each individual client to store the other clients’ certificates in their respective key store. Once 3 clients are validated, the communication process commences. Clients write their desired message and encrypt it using PGP cryptographic functions(discussed in the following sections). This is then further encrypted using their individual KSServerClient and is sent to the server. The server then decrypts using that respectful KSServerClient and re-encrypts using the other clients KSServerClient and flushes those output streams to those respectful clients. The input stream is then decrypted by the client using their individual KSServerClient. The message contents are then extracted by decrypting using the PGP cryptographic functions. 

## Key exchange:
The client registers with the server by sending the server its certificate signed with the CA private key KRCA, containing the clients public key KUCLIENT. Verification occurs if there is a match (they are a pair) between the sent KRCA and the server’s KUCA. The server generates a session key KSServerClient and encrypts it using the KUCLIENT. The message that the server sends to the Client A looks like:
EKUA [KSServerA]

The server stores the certificates of each client, containing their individual KUCLIENT. When the Server broadcasts these certificates to each client, whenever a new client joins the server, the message is encrypted using the KSServerClient for each client. Each client then stores the other clients’ KUCLIENT in their keystore. 

When the Clients send messages to each other, a new shared key KSClientClient is generated for each message. The KSClientClient encrypts the message and the hash sent and is concatenated with this encrypted message and hash. The KSClientClient is, however, encrypted with the KRCLIENT of the receiving client. 

## Integrity: 
The integrity of the message is accomplished through the hash of the message that is sent. The hash of the message is computed using the SHA512 algorithm. The hash of the message is then encrypted using the KRCLIENT of the sending Client. When the message is received, the hash function is re-computed on the message using the SHA512 algorithm by the receiving client. This calculated hash is then compared to the hash that was computed by the sending client. If both hashes’ are equal, that means the contents of the message has not been changed.  
Because the Hash value is encrypted using KRCLIENT, this means that only the sender could have calculated this value. The receiving client uses the sending client’s KUCLIENT to decrypt this calculated hash value. This means that no other user could have sent this hash as they would require the associated KRCLIENT of the sender to encrypt a newly calculated hash if that user were to modify/fabricate a message. This also serves as an authenticity check. 
 
## Authenticity: 
Before connection commences, the Certificate class is run to generate the certificate authority’s (CA) key pair and stores the certificate in the src folder to be used by the Client and Server classes. Both Client and Server classes loads the certificate.store object to sign their own key pair. This serves as a means of verifiability for the Client and Server. 
The authenticity of a Client is checked by the Server. When the TCP connection is established, the client sends the server their certificate containing the KUCLIENT and encrypted with KRCA . Validation occurs only when the server’s KUCA verifies with the KRCA , allowing the server to know that the client was verified by the CA. 

Authenticity of the messages sent by each client is capture through the encrypting used on the sender’s hash value. This hash is encrypted using the KRCLIENT of the sender, with the intended purpose of being unlocked by the KUCLIENT of the sender which the receiving client would have. Because the hash of the message is authenticated through it being encrypted, the message can also be authenticated. 

## Confidentiality: 
Confidentiality in the group chat is applied to both the data and meta data. The meta data is protected through the use of the KSServerClient when messages travel between Clients and Server. This is the key generated by the Server and is encrypted with the KUCLIENT, meaning that the KSServerClient can only be accessed by decrypting using the KRCLIENT. 

Confidentiality of messages is done through the use of a different shared key KSClientClient. The KSClientClient encrypts the message and the hash function. Because this key is encrypted with the KUCLIENT of the receiver, only the receiving client would have access to the KSClientClient by decrypting it using their KRCLIENT. 
#Compression:
Compression is achieved through the use of zipping the byte stream before flushing. The zipping not only reduces the size of the output stream, but also allows for the concatenation of multiple components of the message. This is necessary because when the client sends a message, it needs to be concatenated with the hash value of the message. After that is encrypted, the encrypted KSClientClient is concatenated and sent. 

## Shared key usage:
 The shared keys that are generated throughout the program makes use of AES algorithm. There are two types shared keys that are used for the sending and receiving of messages: 
KSClientClient 
KSServerClient 

KSClientClient is used for the confidentiality of messages and is generated by the client every time that client wants to send a message. The KSClientClient is used to encrypt the byte array of the desired message and this newly generated key is concatenated with the encrypted message. However, the KSClientClient is first encrypted using the public key of each of the receiving client’s public key KUCLIENT before concatenation. This means that if there are three clients(Client A, B and C) in the group chat and Client A wants to send a message, then 2 shared keys (KSAB, KSAC) will be generated to encrypt the message, and KSAB will be encrypted using KUA while and KSAC will be encrypted using KUC. The output stream will contain 4 elements and will look like:
EKSAB[M, EKRA[hash(M)]], EKUB[KSAB], EKSAC[M, KRA(hash(M))], EKUC[KSAC]

KSServerClient differs to KSClientClient in the number of times the key is generated as well as its encryption purpose. KSServerClient is only generated once by the server per client and is distributed to that respectful client. This means that if three clients (Client A, B and C) are verified then three shared keys (KSServerA, KSServerB and KSServerC) are generated. This is used to encrypt the message being sent by a client to the server the relayed messages from the server to the client. The reason for this shared key is for the protection of meta data. This means that there is confidentiality with respect to the constitution/composition of the group, meaning that the identities of the group members are protected using the KSServerClient. Therefore, the final output stream that is flushed by client A, and the incoming input stream for Client B and C, relayed via the server, will look like: 

Output Stream A: 
EKSServerA [ EKSAB[M, EKRA[hash(M)]], EKUB[KSAB], EKSAC[M, KRA(hash(M))], EKUC[KSAC] ]

Input Stream B:
EKSServerB[ EKSAB[M, EKRA[hash(M)]], EKUB[KSAB], EKSAC[M, KRA(hash(M))], EKUC[KSAC] ]

Input Stream C:
EKSServerC[ EKSAB[M, EKRA[hash(M)]], EKUB[KSAB], EKSAC[M, KRA(hash(M))], EKUC[KSAC] ]

## Justification and validity of secured messaging:
All keys and certificates have been used to implement some form of integrality, authenticity and/or confidentiality. The certificate authority serves as a figure of validation, meaning that the private and public keys obtained using this certificate are verified. This allows for the server to check the authenticity of any Client wanting to connect. The KUCLIENT and KRCLIENT key pair is used for the authenticity of a Client. The KRCLIENT is used to encrypt the hash of the message showing that the hash is authentic because only the sending client knows the KRCLIENT. Because the key pair allows the hash to be decrypted using the KUCLIENT, the receiver knows that the owner of the KUCLIENT used to decrypt, is in fact the sender. This is also the mechanism used for integrity. The shared keys are used for confidentiality. The KSClientClient is used for message confidentiality. Because messages are encrypted using this KSClientClient, and this key is only accessible by decrypting using the receiver's private key, only the receiver would be able to view the contents of the message. The KSClientClient is generated for every message to ensure freshness of keys so that no key can be used twice (in case that key is intercepted). The meta data confidentiality is achieved through the use of the KSServerClient. This is justified in the confidentiality section. Together, the overall encryption of the message follows the PGP standards. The order of encryption can be viewed by the diagram called encyptiondiagram.PNG, where Client A is the sender and Client B is the receiver

## Testing:
Testing is done for two aspects of the group chat program: 
Run Time/Logical Testing 
Security Testing for authenticity, integrity and confidentiality

Run Time/Logical testing was done through the use of printing statements to understand the execution order of our code. Therefore, the precise location of any logical errors can be determined more efficiently. In addition to this, catch statements are more detailed to allow us to have a faster understanding of the problem so solving them can be done timelier. These can be seen through analysis of our submitted java files in the src folder.  
Authenticity testing was done through the generation of a rogue client to simulate a possible attack certificate case. This was executed this test by trying to connect a client with an unidentifiable certificate with the server. When the certificate class is executed, the certificate.store object is created by the certificate authority and is loaded into the Server and Client class to generate their keys. Before the third client connected, the Certificate class was re-run to create a different certificate.store object. This client loaded the new certificate.store object implying the KUCA and KRCA generated would be different because for the certificate authority. When client verification happens on the server side, there is a mismatch between the sets of CA keys, so the client was disconnected from the server socket. 
Testing message integrity was done through adding additional code to change the message content. After the hash of the message was computed, the content of the message was then altered by appending the start of the message string with a new string. This means that when the receiving client’s calculated hash would not match the message content, which is used to simulate an integrity attack through modification of messages.

Testing message confidentiality was done through trying to decrypt the message after the KSClientClient encryption during the message sharing pipeline. This was attempted by printing the encoded message in the server class. Code was added to decrypt the message using a different set of shared keys. When that didn’t work, the KRCA  was used tried to decrypt the KSClientClient to be used to decrypt the message. However, because the KRCA was not the same as the KRCLIENT, the message could not be decoded. 

