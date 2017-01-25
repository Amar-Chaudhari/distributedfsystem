# TLEN 5330 Programming Assignment 3

## Objectives
- To create a distributed file system for reliable and secure file storage

## Background
-  A distributed filesytem is a client/server based application that allows client to store and receive files from multiple servers
- Every server stores some part of the file while multiple servers store multiple parts. Hence, even if one of the servers go down the file still can be re-created

### Requirments
- Python 2.7

## Implementation Details
### Put Files on Servers
- Client divides a file into 4 equal parts to be stored on the servers.
- A function which is based on the hash of the data of a file decides which part has to stored on what server.
- Client then sends that part with filename as `.filename.part_number` to respective server.
- Client also ecryptes the chunk before sending it to server

### Get Files on Servers
- Client will request parts of the file to servers.
- Client starts by requesting server DFS1, DFS3 for the parts.
- If the parts are enough to re-construct the file then the file is writen to clients home directory
- If the parts are not enough then next servers are tried, ie. DFS2, DFS4

### List Files on Servers
- Similar to Get function, we first try DFS3 server to retrive the parts
- If the parts are not enough to re-construct the file then we try next servers, ie. DFS1,DFS2,DFS4
- If after trying all the servers the parts are not enough then we show [incomplete] in the file name.

### Make directory on Servers
- `mkdir` function will create new directories in users home directory on servers
- It will return error if the requested directory already exists.

## Encryption of data
- All data stored on the servers is encrypted before sending to servers
- We use `XOR` cipher to encrypt the data. Although it is a weak cipher we use sha256 to increase the length of the key.
- The key used is the users password from the configuration file.
- If the user changes his password then he can not see the old file on the server.

### How to run the program
#### Start the Servers
```
python2.7 dfs.py DFS1 10001
python2.7 dfs.py DFS2 10002
python2.7 dfs.py DFS3 10003
python2.7 dfs.py DFS4 10004
```
#### Start Clients
```
python2.7 dfc.py dfc.conf
```
