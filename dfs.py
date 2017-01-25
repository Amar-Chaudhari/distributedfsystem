import os
import re
import socket
import sys
import time
from io import open
from multiprocessing import Process

# Class to handle all server related operations
class DFS_Server(object):

    # Configuration file is hard coded in to every server
    config_file = os.path.dirname(os.path.realpath(__file__)) + '/' + 'dfs.conf'
    BUFFER_SIZE = 1500

    def __init__(self, directory, port):
        self.port = port
        self.dir = os.path.dirname(os.path.realpath(__file__)) + '/' + directory
        self.Users = dict()
        self.svr_ip = '127.0.0.1'

    # Method to load all users and passwords
    def load_configuration(self):
        tuser = ""

        if os.path.isfile(DFS_Server.config_file):
            with open(DFS_Server.config_file) as fh:
                while fh:
                    line = fh.readline()

                    if not line:
                        break
                    elif 'Username' in line:
                        self.Users[line.split(':')[1].strip()] = ""
                        tuser = line.split(':')[1].strip()
                    elif 'Password' in line:
                        try:
                            self.Users[tuser] = line.split(':')[1].strip()
                        except KeyError:
                            print "Error: file error\nUsername not found"
                            sys.exit(0)
        else:
            print "Configuration file not present"
        if not os.path.exists(self.dir):
            os.makedirs(self.dir)

    # Method to accept new connections and create a thread per connections
    def start_server(self):
        # Socket creation part
        server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_sock.bind((self.svr_ip, self.port))
        if server_sock:
            try:
                server_sock.listen(10)
                while True:
                    # Accept new connections from clients
                    client_connection, client_address = server_sock.accept()
                    # Process is just another library to handle threading
                    t = Process(target=DFS_Server.start_forever, args=(self, client_connection,))
                    # Kill all threads when the main process exits
                    t.daemon = True
                    # Start the thread execution
                    t.start()
            except KeyboardInterrupt:
                server_sock.close()
                sys.exit(0)

    # Method to validate user credentials received from client
    def validate_user(self, client_connection):
        try:

            credentials = client_connection.recv(DFS_Server.BUFFER_SIZE)
            if credentials:
                (username, password) = credentials.split()
                test_pass = self.Users.get(username)
                if test_pass:
                    if test_pass == password:
                        client_connection.sendall('OK')
                        print "Info: %s User Authorized" % username
                        if not os.path.exists(self.dir + '/' + username):
                            os.makedirs(self.dir + '/' + username)
                        return self.dir + '/' + username
                    else:
                        print "Info: %s User Not Authorized" % username
                        return False
                else:
                    return False

        except socket.error as e:
            return False
        except ValueError:
            client_connection.sendall('NOTOK')
            return False

    def accept_files(self, userdir, client_connection):
        try:
            fname_1 = client_connection.recv(DFS_Server.BUFFER_SIZE)
            client_connection.sendall('SEND_DATA')
            fname_1_data = self.recv_all(client_connection)
            if fname_1_data:
                with open(userdir + '/' + fname_1, 'wb') as fh:
                    fh.write(fname_1_data)
            fname_2 = client_connection.recv(DFS_Server.BUFFER_SIZE)
            client_connection.sendall('SEND_DATA')
            fname_2_data = self.recv_all(client_connection)
            if fname_2_data:
                with open(userdir + '/' + fname_2, 'wb') as fh:
                    fh.write(fname_2_data)
        except IOError:
            pass

    def start_forever(self, client_connection):
        try:
            while True:
                data = client_connection.recv(DFS_Server.BUFFER_SIZE)
                if not data:
                    break
                if "put" in data:
                    client_connection.sendall('STATUSOK')
                    userdir = self.validate_user(client_connection)
                    if userdir:
                        self.accept_files(userdir, client_connection)
                elif "list" in data:
                    command,subfolder = data.split()
                    client_connection.sendall('STATUSOK')
                    userdir = self.validate_user(client_connection)
                    if userdir:
                        status = client_connection.recv(DFS_Server.BUFFER_SIZE)
                        if status == 'OK':
                            client_connection.sendall('Username?')
                            user = client_connection.recv(DFS_Server.BUFFER_SIZE)
                            if user:
                                if subfolder == '.':
                                    user_files = os.listdir(userdir)
                                else:
                                    user_files = os.listdir(userdir + '/' + subfolder)
                                if user_files:
                                    files_str = ','.join(user_files)
                                    client_connection.sendall(files_str)
                                else:
                                    client_connection.sendall(' ')
                            else:
                                client_connection.sendall(' ')
                    else:
                        client_connection.sendall('USER_NOT_AUTHENTICATED')

                elif data == "get":
                    client_connection.sendall('STATUSOK')
                    userdir = self.validate_user(client_connection)
                    if userdir:
                        status = client_connection.recv(DFS_Server.BUFFER_SIZE)
                        if status == 'OK':
                            client_connection.sendall('FileName?')
                            fname = client_connection.recv(DFS_Server.BUFFER_SIZE)
                            if fname:
                                try:
                                    filename,subfolder = fname.split()
                                except ValueError:
                                    subfolder = '.'

                                fname_parts = self.get_file_parts(userdir + '/' + subfolder, filename)
                                if fname_parts:
                                    client_connection.sendall(str(','.join(fname_parts)))
                                    for part in fname_parts:
                                        transfer_status = client_connection.recv(DFS_Server.BUFFER_SIZE)
                                        if transfer_status == 'STATUSOK':
                                            with open(userdir + '/' + subfolder + part, "rb") as fh:
                                                fdata = fh.read()
                                            client_connection.sendall(fdata)
                                            time.sleep(0.10)
                                            client_connection.send('EOF')
                                else:
                                    client_connection.sendall('File_NOT_PRESENT')
                elif "mkdir" in data:
                    command, directory = data.split()
                    client_connection.sendall('STATUSOK')
                    userdir = self.validate_user(client_connection)
                    if userdir:
                        if os.path.exists(userdir + '/' + directory):
                            client_connection.sendall('DIR_EXISTS')
                        else:
                            os.makedirs(userdir + '/' + directory)
                            client_connection.sendall('DIR_CREATED')

                elif data == "Hello":
                    client_connection.sendall("Hello".encode())

        except socket.error as e:
            print e

        client_connection.close()
        return

    def get_file_parts(self, userdir, fname):
        try:
            res = []
            user_files = os.listdir(userdir)
            for file in user_files:
                file_name_check = re.sub(r'.([1-9])$', '', file)
                file_name_check_final = file_name_check[1:]
                if fname == file_name_check_final:
                    res.append(file)
            return res
        except IOError:
            return False

    # Method to receive all data from a socket.
    # TCP sockets have a method to sendall data but do have a method to receive all data
    def recv_all(self, client_connection):
        try:
            chunks = []
            res_data = b''
            while True:
                fdata = client_connection.recv(DFS_Server.BUFFER_SIZE)
                if fdata == 'EOF':
                    break
                chunks.append(fdata)

            res_data = b''.join(chunks)
            return res_data

        except socket.error:
            return False

    def print_configuration(self):
        print self.Users


if __name__ == "__main__":
    if len(sys.argv) == 3:
        dfs = DFS_Server(sys.argv[1], int(sys.argv[2]))
        dfs.load_configuration()
        dfs.start_server()
    else:
        print "Error: Invalid Arguments\nError: python3.4 dfc.py dfc.conf"
