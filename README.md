# Asymmetric-Encryption-Program-Server-Client
A program designed for private messaging with end-to-end encryption and an emphasis on non-repudiation and privacy. Implements: Encryption, Hashing, Signatures. (Built in Java) 

# Generating Keys
Each user has a unique userid, which is a simple string like alice, bob etc. Each user is associated with a pair of RSA public and private keys, with ﬁlenames of the form <userid>.pub and <userid>.prv. Thus the key ﬁles are named alice.pub, bob.prv, etc. These keys are generated separately by a program RSAKeyGen.java.

# Server Side
After generating keys for each user, run the server. This will act to store and send the messages to the desired recipeint. 

**javac Server.java**

**java Server [port]**

# Client Side
Finally use the client to interract with the server and send your encrypted messages

**javac Client.java**

**java Client [host] [port] [userID]**

# Enjoy!
