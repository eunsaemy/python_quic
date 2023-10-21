# python_quic

## A basic QUIC Python Library and Distributed File System (DFS) Application

The QUIC Python library supports 0-RTT handshake, secures data using both asymmetric and symmetric cryptography, and transports these packets over UDP sockets. The DFS application is used to demonstrate the functionality of the library.

### Install cryptography and rsa using the commands

```pip install cryptography```

```pip install rsa```

### For help function:

```python server.py -h```

```python client.py -h```

### To run server.py:

```python server.py -p [port-number]```

### To run client.py:

```python client.py -p [port-number] -u [username]```
