# built-in modules
import __init__
import argparse
import logging
import os
import sys
from rsa import (
    newkeys,
    PrivateKey,
    PublicKey,
)

# custom module
from quic import QuicClient

# logging module
FORMAT = "[%(filename)s:%(lineno)s:%(funcName)20s() ] %(message)s"
logging.basicConfig(filename="test_client.log", filemode="w", level=logging.INFO, format=FORMAT)
logger = logging.getLogger(__name__)

HOST = "10.0.0.111"
BUFFER_SIZE = 1024
CHUNK_SIZE = 100


def load_arguments():
    parser = argparse.ArgumentParser(
        description="Distributed File System (Client")
    parser.add_argument("-p", "--port", help="port number", required=True)
    parser.add_argument("-u", "--username", help="username", required=True)
    return parser.parse_args()


def generate_keys():
    current_path = os.getcwd()
    private_path = os.path.join(current_path, "private")

    public_filename = "client_public.pem"
    private_filename = "client_private.pem"

    def write_keys(public_key: PublicKey, private_key: PrivateKey):
        with open(os.path.join(private_path, public_filename), "wb") as f:
            f.write(public_key.save_pkcs1("PEM"))
        with open(os.path.join(private_path, private_filename), "wb") as f:
            f.write(private_key.save_pkcs1("PEM"))

    if not os.path.isdir(private_path):
        os.mkdir(private_path)
        public_key_client, private_key_client = newkeys(BUFFER_SIZE)
        write_keys(public_key_client, private_key_client)

    elif not os.path.isfile(os.path.join(private_path, public_filename)):
        public_key_client, private_key_client = newkeys(BUFFER_SIZE)
        write_keys(public_key_client, private_key_client)

    with open(os.path.join(private_path, public_filename), "rb") as file:
        public_key_file = PublicKey.load_pkcs1(file.read())
    with open(os.path.join(private_path, private_filename), "rb") as file:
        private_key_file = PrivateKey.load_pkcs1(file.read())

    return public_key_file, private_key_file


def print_res():
    print("")

    while True:
        res = client_socket.recv().decode()
        if res == "exit":
            break
        print(f"{res}")
        logger.info(f"{res}")


def check_recv():
    print("")

    res = client_socket.recv().decode()
    logger.info(f"{res}")
    if res == "ok":
        return True
    elif res == "error":
        return False


def recv_file(file_name):
    current_path = os.getcwd()
    file_path = os.path.join(current_path, file_name)

    file = open(file_path, "w")
    file.close()

    file = open(file_path, "a")
    while True:
        data = client_socket.recv().decode()
        if data == "exit":
            break
        file.write(data)
    file.close()

    print(f"File ({file_name}) was successfully created")


def split_file(file_path, file_name):
    with open(file_path, "r") as file:
        data = file.read()

        count = 0

        while count < len(data):
            trunc_data = data[count:count + CHUNK_SIZE]
            client_socket.send(trunc_data.encode())
            count += CHUNK_SIZE

    client_socket.send("exit".encode())
    print(f"File ({file_name}) was successfully sent")
    logger.info(f"File ({file_name}) was successfully sent")


def send_file(file_name):
    current_path = os.getcwd()
    file_path = os.path.join(current_path, file_name)

    if os.path.isfile(file_path):
        client_socket.send("3".encode())
        client_socket.send(file_name.encode())
        print(f"Sending file ({file_name}) ...")
        logger.info(f"Sending file ({file_name}) ...")
        split_file(file_path, file_name)
    else:
        print(f"No such file ({file_name}) exists")
        logger.info(f"No such file ({file_name}) exists")


def menu():
    print("")
    print("   1. Create a file")
    print("   2. Read a file")
    print("   3. Update a file")
    print("   4. Delete a file")
    print("   5. Get a list of all the files for the user")
    print("   0. Quit")
    print("")

    choice = input("Please choose an option: ")

    print("")

    # create
    if choice == "1":
        client_socket.send(choice.encode())
        file_name = input("File name to create: ")
        client_socket.send(file_name.encode())
        print_res()
    # read
    elif choice == "2":
        client_socket.send(choice.encode())
        file_name = input("File name to read: ")
        client_socket.send(file_name.encode())
        if check_recv():
            recv_file(file_name)
        else:
            print(f"No such file ({file_name}) exists")
    # update
    elif choice == "3":
        file_name = input("File name to update: ")
        send_file(file_name)
    # delete
    elif choice == "4":
        client_socket.send(choice.encode())
        file_name = input("File name to delete: ")
        client_socket.send(file_name.encode())
        print_res()
    # list
    elif choice == "5":
        client_socket.send(choice.encode())
        print_res()
    # exit
    elif choice == "0":
        client_socket.send("exit".encode())
        print("Goodbye.")
        sys.exit(0)
    else:
        print("Invalid option. Please try again.")

    menu()


public, private = generate_keys()

args = load_arguments()
port = int(args.port)
username = args.username

try:
    client_socket = QuicClient(crypto=(public, private))
    client_socket.connect((HOST, port))
    print("Connected to the server")
    logger.info("Connected to the server")
except ConnectionError:
    print("Client could not connect to the server")
    logger.info("Client could not connect to the server")
    sys.exit(0)

client_socket.send(username.encode())

menu()
