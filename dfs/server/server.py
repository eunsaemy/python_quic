# built-in modules
import __init__
import argparse
import logging
import os
import sys
import time
from rsa import (
    newkeys,
    PrivateKey,
    PublicKey,
)

# custom module
from quic import QuicServer

# logging module
FORMAT = "[%(filename)s:%(lineno)s:%(funcName)20s() ] %(message)s"
logging.basicConfig(filename="test_server.log", filemode="w", level=logging.INFO, format=FORMAT)
logger = logging.getLogger(__name__)

HOST = "10.0.0.111"
BUFFER_SIZE = 1024
CHUNK_SIZE = 100


def load_arguments():
    parser = argparse.ArgumentParser(
        description="Distributed File System (Server)")
    parser.add_argument("-p", "--port", help="port number", required=True)
    return parser.parse_args()


def generate_keys():
    current_path = os.getcwd()
    private_path = os.path.join(current_path, "private")

    public_key_file = "server_public.pem"
    private_key_file = "server_private.pem"

    def write_keys(public_key: PublicKey, private_key: PrivateKey):
        with open(os.path.join(private_path, public_key_file), "wb") as f:
            f.write(public_key.save_pkcs1("PEM"))
        with open(os.path.join(private_path, private_key_file), "wb") as f:
            f.write(private_key.save_pkcs1("PEM"))

    if not os.path.isdir(private_path):
        os.mkdir(private_path)
        public_key_client, private_key_client = newkeys(BUFFER_SIZE)
        write_keys(public_key_client, private_key_client)

    elif not os.path.isfile(os.path.join(private_path, public_key_file)):
        public_key_client, private_key_client = newkeys(BUFFER_SIZE)
        write_keys(public_key_client, private_key_client)

    with open(os.path.join(private_path, public_key_file), "rb") as file:
        public_key_file = PublicKey.load_pkcs1(file.read())
    with open(os.path.join(private_path, private_key_file), "rb") as file:
        private_key_file = PrivateKey.load_pkcs1(file.read())

    return public_key_file, private_key_file


def init():
    current_path = os.getcwd()
    username_path = os.path.join(current_path, username)

    print(f"loaded {username_path}")
    logger.info(f"loaded {username_path}")

    if not os.path.isdir(username_path):
        os.mkdir(username_path)

    return username_path


def create_file(file_name, addr):
    file_path = os.path.join(user_path, file_name)

    if not os.path.isfile(file_path):
        file = open(file_path, "w")
        file.close()
        res = f"File ({file_name}) was successfully created"
    else:
        res = f"File ({file_name}) already exists"

    server_socket.sendto(res.encode(), addr)
    print(res)
    logger.info(res)


def split_file(file_path, file_name, addr):
    with open(file_path, "r") as file:
        data = file.read()

        count = 0

        while count < len(data):
            trunc_data = data[count:count + CHUNK_SIZE]
            server_socket.sendto(trunc_data.encode(), addr)
            count += CHUNK_SIZE

    print(f"File ({file_name}) was successfully sent")
    logger.info(f"File ({file_name}) was successfully sent")


def send_file(file_name, addr):
    file_path = os.path.join(user_path, file_name)

    if os.path.isfile(file_path):
        server_socket.sendto("ok".encode(), addr)
        print(f"Sending file ({file_name}) ...")
        logger.info(f"Sending file ({file_name}) ...")
        split_file(file_path, file_name, addr)
    else:
        server_socket.sendto("error".encode(), addr)
        print(f"No such file ({file_name}) exists")
        logger.info(f"No such file ({file_name}) exists")


def recv_file(file_name):
    file_path = os.path.join(user_path, file_name)

    file = open(file_path, "w")
    file.close()

    file = open(file_path, "a")
    while True:
        data = server_socket.recv().decode()
        if data == "exit":
            break
        file.write(data)
    file.close()

    print(f"File ({file_name}) was successfully updated")
    logger.info(f"File ({file_name}) was successfully updated")


def delete_file(file_name, addr):
    file_path = os.path.join(user_path, file_name)

    if os.path.isfile(file_path):
        os.remove(file_path)
        res = f"File ({file_name}) was successfully deleted"
    else:
        res = f"No such file ({file_name}) exists"

    server_socket.sendto(res.encode(), addr)
    print(res)
    logger.info(res)


def list_files(addr):
    files = os.listdir(user_path)

    if not files:
        res = "There are no files in the directory."
        server_socket.sendto(res.encode(), addr)
        print(f"{res}")
        logger.info(f"{res}")
    else:
        for file in os.listdir(user_path):
            server_socket.sendto(file.encode(), addr)
            print(file)
            logger.info(file)


def menu():
    while True:
        # receive command from the user
        data, addr = server_socket.recvfrom()
        command = data.decode()

        # create
        if command == "1":
            file_name = server_socket.recv().decode()
            create_file(file_name, addr)
        # read
        elif command == "2":
            file_name = server_socket.recv().decode()
            send_file(file_name, addr)
        # update
        elif command == "3":
            file_name = server_socket.recv().decode()
            recv_file(file_name)
        # delete
        elif command == "4":
            file_name = server_socket.recv().decode()
            delete_file(file_name, addr)
        # list
        elif command == "5":
            list_files(addr)
        # exit
        elif command == "exit":
            print("Goodbye.")
            logger.info("Goodbye.")
            sys.exit(0)

        time.sleep(0.1)
        server_socket.sendto("exit".encode(), addr)


public, private = generate_keys()

args = load_arguments()
logger.debug(f"loaded port: {args.port}")
print(f"loaded port: {args.port}")
port = int(args.port)

server_socket = QuicServer(crypto=(public, private))

server_socket.bind((HOST, port))
print("Server is listening...")
logger.info("Server is listening...")

username= server_socket.recv().decode()
print(f"loading {username}...")
logger.info(f"loading {username}...")
user_path = init()

menu()
