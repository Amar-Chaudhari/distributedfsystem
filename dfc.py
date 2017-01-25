import hashlib
import math
import os
import re
import socket
import sys
import time
from io import open

from Crypto.Cipher import XOR

# Class to handle DFC client
# Contains methods for get, put, list and authenticate users
class DFC(object):

    # MAX buffer size accepted in unix systems
    BUFFER_SIZE = 1500

    # Current running dir of the project
    PROJECT_DIR = os.path.dirname(os.path.realpath(__file__)) + '/'

    # Constructor called while creating object of this class
    def __init__(self, config):
        self.config_file = config
        self.user = ""
        self.password = ""
        self.Servers = dict()
        self.userdir = ""

    # Method to load configuration from the dfc.conf specified at command line
    def load_configuration(self):
        if os.path.isfile(self.config_file):
            with open(self.config_file) as fh:
                while fh:
                    line = fh.readline()
                    if not line:
                        break
                        # Ignore lines starting with #
                        # Use full to add comments in the file and skip any configuration
                        # temporarily
                    if not line.startswith('#'):
                        if line.startswith('Server'):
                            self.Servers[line.split()[1]] = line.split()[2]
                        elif 'Username' in line:
                            self.user = line.split(':')[1].strip()
                        elif 'Password' in line:
                            self.password = line.split(':')[1].strip()

    def print_configuration(self):
        print self.Servers

    # Method to encrypt chunk of data
    # Uses the key as sha256 of password from the configuration
    # Cipher used is XOR
    def encrypt(self, key, plaintext):
        cipher = XOR.new(key)
        return cipher.encrypt(plaintext)

    # Method to decrypt chunk of data
    # if the key is wrong then the function returns un-decrypted data
    # There is no way to know if the decryption was successfully or not
    def decrypt(self,key, ciphertext):
        cipher = XOR.new(key)
        return cipher.decrypt(ciphertext)

    # Method to close server connections
    def close_server_connections(self, server_sockets):
        try:
            for key, val in server_sockets.items():
                if val:
                    val.close()
        except socket.error:
            pass

    def start_forever(self):
        try:
            if self.login():
                while True:
                    # Get command/input from user
                    client_input = raw_input(self.print_menu())
                    if client_input:
                        if client_input.lower() == "exit":
                            sys.exit(0)
                        else:
                            try:
                                # split the command into command and argument
                                # Need to catch expection for commands like list
                                (command, fname) = client_input.split(' ',1)
                            except ValueError as e:
                                # if there is no argument
                                command = client_input
                                fname = False

                            # Accept commands which are implemented by this program
                            # Eg: get, put, list
                            if self.check_command(command):

                                # If command is list
                                if command.lower() == "list":
                                    # Create sockets to servers
                                    # We need to create these before every command as we close sockets at end of command execution

                                    server_sockets,all_sockets_alive = self.create_sockets()
                                    self.list_user_files(server_sockets,fname)

                                elif command.lower() == "put":
                                    try:
                                        # Put command can have either a directory or or not
                                        filename,subfolder = fname.split()
                                    except ValueError as e:
                                        # if there was no directory then we put in home directory '.'
                                        subfolder = '.'
                                        filename = fname

                                    if self.isfile(filename):
                                        # Create sockets to servers
                                        # We need to create these before every command as we close sockets at end of command execution

                                        server_sockets,all_sockets_alive = self.create_sockets()
                                        self.put_file_to_dfs(server_sockets, filename,subfolder)
                                    else:
                                        print "Error: %s File Not Present!" % fname

                                elif command.lower() == "get":
                                    try:
                                        # Get command can have either a directory or or not
                                        filename,subfolder = fname.split()
                                    except ValueError as e:
                                        # if there was no directory then we get in home directory '.'
                                        subfolder = '.'
                                        filename = fname

                                    server_sockets,all_sockets_alive = self.create_sockets()
                                    self.get_file_from_servers(filename, server_sockets,subfolder)

                                elif command.lower() == "mkdir":
                                    server_sockets,all_sockets_alive = self.create_sockets()
                                    self.create_directory(server_sockets,directory=fname)
            else:
                print "Login Failed\nExiting Gracefully..."
                sys.exit(0)

        except KeyboardInterrupt:
            self.close_server_connections(server_sockets)
            sys.exit(0)
        except EOFError:
            print "Error: Un-Supported Charactors entered in input\nError: Exiting..."
            sys.exit(0)

    def create_directory(self,server_sockets,directory):

        # if there was no directory specified then we have nothing to do
        if not directory:
            return

        # is the dictionary of servername:socket
        for key,val in server_sockets.items():
            try:
                if val:
                    # send command to make directory
                    val.sendall('mkdir '+directory)
                    status_1 = val.recv(DFC.BUFFER_SIZE)
                    if status_1 == 'STATUSOK':
                        if self.send_credentials(key, val):
                            status_dir_creation = val.recv(DFC.BUFFER_SIZE)
                            # status_dir_creation will tell if the directory creation was successfully
                            # or if the directory already existed.
                            if status_dir_creation:
                                if status_dir_creation == "DIR_EXISTS":
                                    print "Info: %s Directory Already Exists on %s" % (directory,key)
                                elif status_dir_creation == "DIR_CREATED":
                                    print "Info: %s Directory Created on %s" % (directory,key)
                    # Close socket when finished working in it
                    val.close()
            except socket.timeout:
                # if the sever timedout then we skip it
                print "Error: %s Server Timeout..skipping.." % key

    # Methid to handle get file from servers
    def get_file_from_servers(self, fname, server_sockets,subfolder):
        try:
            if not subfolder.endswith('/'):
                subfolder += '/'
            Files = dict()

            # encryption key is sha256 of the password
            # this is done just to increase the size of the key

            pass_key = hashlib.sha256(self.password).digest()

            # In get we first check for the parts on DFS1 and DFS3
            # if the parts are enough to re-construct the files
            # ie. we have parts .1, .2, .3, .4
            # then we do not check other servers, this done for traffic optimization
            # If the parts are not enough then we check DFS2
            # If the parts are still not enough then we check DFS4
            # If after checking all online servers the parts are still not enough
            # then  we can not re-construct the file.
            for key, val in server_sockets.items():
                try:
                    if key == 'DFS1' or key == 'DFS3':
                        if not val:
                            continue
                        val.sendall('get')
                        status_1 = server_sockets[key].recv(DFC.BUFFER_SIZE)
                        if status_1 == 'STATUSOK':
                            if self.send_credentials(key, server_sockets[key]):
                                val.sendall('OK')
                                filename_status = val.recv(DFC.BUFFER_SIZE)
                                if filename_status == 'FileName?':
                                    val.sendall(fname + ' ' + subfolder)
                                    file_part_names = val.recv(DFC.BUFFER_SIZE)
                                    if file_part_names == 'File_NOT_PRESENT':
                                        print "Error: File Not Present on %s" %key
                                        continue
                                    else:
                                        for part in file_part_names.split(','):
                                            val.sendall('STATUSOK')
                                            fdata = self.recv_all(val)
                                            if fdata:
                                                Files[part] = self.decrypt(pass_key,fdata)
                                                print "Info: File chunk received from %s" % key
                                            else:
                                                Files[part] = ''
                except socket.timeout:
                    # skip the server is it timedout
                    print "Error: %s Server Timeout..skipping.." % key

            # check_received_parts method checks if the acquired parts are enough to re-construct or not
            if not self.check_received_parts(Files):
                for key, val in server_sockets.items():
                    try:
                        if key == 'DFS2':
                            if not val:
                                break
                            val.sendall('get')
                            status_1 = server_sockets[key].recv(DFC.BUFFER_SIZE)
                            if status_1 == 'STATUSOK':
                                if self.send_credentials(key, server_sockets[key]):
                                    val.sendall('OK')
                                    filename_status = val.recv(DFC.BUFFER_SIZE)
                                    if filename_status == 'FileName?':
                                        val.sendall(fname + ' ' + subfolder)
                                        file_part_names = val.recv(DFC.BUFFER_SIZE)
                                        if file_part_names == 'File_NOT_PRESENT':
                                            print "Error: File Not Present on %s" % key
                                            continue
                                        else:
                                            for part in file_part_names.split(','):
                                                val.sendall('STATUSOK')
                                                fdata = self.recv_all(val)
                                                if fdata:
                                                    Files[part] = self.decrypt(pass_key,fdata)
                                                    print "Info: File chunk received from %s" % key
                                                else:
                                                    Files[part] = ''
                    except socket.timeout:
                        print "Error: %s Server Timeout..skipping.." % key


            if not self.check_received_parts(Files):
                for key, val in server_sockets.items():
                    try:
                        if key == 'DFS4':
                            if not val:
                                break
                            val.sendall('get')
                            status_1 = server_sockets[key].recv(DFC.BUFFER_SIZE)
                            if status_1 == 'STATUSOK':
                                if self.send_credentials(key, server_sockets[key]):
                                    val.sendall('OK')
                                    filename_status = val.recv(DFC.BUFFER_SIZE)
                                    if filename_status == 'FileName?':
                                        val.sendall(fname + ' ' + subfolder)
                                        file_part_names = val.recv(DFC.BUFFER_SIZE)
                                        if file_part_names == 'File_NOT_PRESENT':
                                            print "Error: File Not Present on %s" % key
                                            continue
                                        else:
                                            for part in file_part_names.split(','):
                                                val.sendall('STATUSOK')
                                                fdata = self.recv_all(val)
                                                if fdata:
                                                    Files[part] = self.decrypt(pass_key,fdata)
                                                    print "Info: File chunk received from %s" % key
                                                else:
                                                    Files[part] = ''
                    except socket.timeout:
                        print "Error: %s Server Timeout..skipping.." % key


            # Finally if the parts are enough we reconstruct the file
            if self.check_received_parts(Files):
                write_data = []
                # Here the key is the part number
                # Eg. txt.1, txt.2
                for key in sorted(Files.keys()):
                    write_data.append(Files[key])

                with open(self.userdir + '/received_' + fname, "wb") as fh:
                    fh.write(b''.join(write_data))
            else:
                print "\nError: %s file can not be reconstructed with available online DFS servers" % fname

            # Close all available sockets
            for val in server_sockets.values():
                if val:
                    val.close()
        except socket.error as e:
            print e
            pass

    # Method to check if available parts are ==4
    # As we require 4 parts to re-construct the file
    def check_received_parts(self, Files):
        try:

            if not len(Files) == 4:
                return False
            else:
                return True
        except KeyError:
            return False

    # Method to send user credentials to servers
    # Server checks for credentials before executing any command
    # ie. get, put, list, mkdir
    def send_credentials(self, key, server_socket):
            server_socket.sendall(self.user + ' ' + self.password)
            status = server_socket.recv(1500)
            # if the server successful authenticated the user then it will return OK
            if status == 'OK':
                print "Info: %s User Authenticated on %s" % (self.user, key)
                return True

            # if the server can not authenticat the user then it will return USER_NOT_AUTHENTICATED
            elif status == 'USER_NOT_AUTHENTICATED':
                return False

    # Method to handle put to servers
    def put_file_to_dfs(self, server_sockets, fname, subfolder):
        try:
            # Initialize hash function
            hash = hashlib.md5()

            # Read the file contents in buffer
            with open(fname, 'rb') as fh:
                buffer = fh.read()

            hash.update(buffer)

            # Value of x is needed to decide which file chunks go on which server
            x = int(hash.hexdigest(), 16) % 4

            # Upload options contains which chunk goes to what server
            upload_options = self.get_upload_options(x)
            chunks = []

            # Calculate the spiltsize
            # spiltsize should divide the file buffer into 4 parts
            splitsize = int(math.ceil(os.path.getsize(fname) / 4))

            pass_key = hashlib.sha256(self.password).digest()

            # Chunks list contains the encrypted file data
            for i in xrange(0, len(buffer), splitsize + 1):
                chunks.append(self.encrypt(pass_key,buffer[i:i + splitsize + 1]))

            # upload_options : {'DFS4': (3, 4), 'DFS3': (2, 3), 'DFS1': (4, 1), 'DFS2': (1, 2)}
            for key, value in upload_options.items():
                try:
                    if not server_sockets[key]:
                        print "\nError: %s Server Seems to be Down!" % key
                        continue
                    # Server will enter the put routine
                    server_sockets[key].sendall('put')
                    status_1 = server_sockets[key].recv(DFC.BUFFER_SIZE)
                    # Server will return STATUSOK if it can enter put routing
                    if status_1 == 'STATUSOK':
                        # Next we authenticate the user
                        if self.send_credentials(key, server_sockets[key]):

                            # Construct the file name with subfolder if specified
                            if subfolder == '.':
                                file_part_name_1 = '.' + fname + '.' + str(value[0])
                                file_part_name_2 = '.' + fname + '.' + str(value[1])
                            else:
                                if subfolder.endswith('/'):
                                    file_part_name_1 = subfolder + '.' + fname + '.' + str(value[0])
                                    file_part_name_2 = subfolder + '.' + fname + '.' + str(value[1])
                                else:
                                    file_part_name_1 = subfolder + '/' + '.' + fname + '.' + str(value[0])
                                    file_part_name_2 = subfolder + '/' + '.' + fname + '.' + str(value[1])

                            # Send file name to server and accept some status
                            server_sockets[key].send(file_part_name_1)
                            check = server_sockets[key].recv(DFC.BUFFER_SIZE)
                            # Send data if server sends SEND_DATA
                            if check == 'SEND_DATA':
                                server_sockets[key].sendall(chunks[value[0] - 1])
                                # if time.sleep is not added then EOF goes with the contents
                                time.sleep(0.05)
                                server_sockets[key].send('EOF')
                            time.sleep(0.05)
                            server_sockets[key].send(file_part_name_2)
                            check = server_sockets[key].recv(DFC.BUFFER_SIZE)
                            if check == 'SEND_DATA':
                                server_sockets[key].sendall(chunks[value[1] - 1])
                                time.sleep(0.05)
                                server_sockets[key].send('EOF')
                            print "Info: Files transfered on server %s" % key
                            server_sockets[key].close()
                        else:
                            print "Error: Credentials do not match on " + key
                            server_sockets[key].close()
                except socket.timeout as e:
                    print "Error: %s Server Does Not Seem to be Responding..Skipping..." % key

        except socket.error:
            print "Error in sockets"

        # Close all available sockets
        for val in server_sockets.values():
            if val:
                val.close()

    # Method to decide what chunk should go on what server
    def get_upload_options(self, x):

        if x == 0:
            return {'DFS1': (1, 2), 'DFS2': (2, 3), 'DFS3': (3, 4), 'DFS4': (4, 1)}
        elif x == 1:
            return {'DFS1': (4, 1), 'DFS2': (1, 2), 'DFS3': (2, 3), 'DFS4': (3, 4)}
        elif x == 2:
            return {'DFS1': (3, 4), 'DFS2': (4, 1), 'DFS3': (1, 2), 'DFS4': (2, 3)}
        elif x == 3:
            return {'DFS1': (2, 3), 'DFS2': (3, 4), 'DFS3': (4, 1), 'DFS4': (1, 2)}

        return False

    # Check if the file mentioned exists or not
    def isfile(self, fname):
        try:
            return os.path.isfile(fname)
        except:
            pass

    # Method to handle listing files of user from servers
    # It checks to see if a file can be constructed with minimum servers
    def list_user_files(self, server_sockets,subfolder):
        all_files = set()
        incomplete_file_parts = set()

        if not subfolder:
            subfolder = '.'

        # Get all files and parts from DFS3
        # If there are incomplete parts then check DFS1,DFS2,DFS4
        all_files,incomplete_file_parts = self.get_complete_parts(server_sockets, 'DFS3', all_files, incomplete_file_parts,subfolder)
        all_files,incomplete_file_parts = self.get_complete_parts(server_sockets, 'DFS1', all_files,incomplete_file_parts,subfolder)

        # check_file_parts checks to see if available file parts are enough to re-construct the file
        # status - True if file can be reconstructed
        # status - False if file can not be re-constructed
        Files,status = self.check_file_parts(all_files, incomplete_file_parts)
        if not status:
            all_files, incomplete_file_parts = self.get_complete_parts(server_sockets, 'DFS2', all_files,incomplete_file_parts,subfolder)

        Files,status = self.check_file_parts(all_files, incomplete_file_parts)
        if not status:
            all_files, incomplete_file_parts = self.get_complete_parts(server_sockets, 'DFS4', all_files,incomplete_file_parts,subfolder)

        Files,status = self.check_file_parts(all_files, incomplete_file_parts)
        print "\n### Files on System ###"

        for file,count in Files.items():

            # Regex to check if the file is a directory or not
            # this system does not support directories ending with .number

            check = re.search('\.[a-z]+$',file)
            if check:
                if count != 4:
                    print file + ' [incomplete]'
                else:
                    print file
            else:
                print file + '/'

        # Close all available sockets
        for val in server_sockets.values():
            if val:
                val.close()

    # Method to get file parts from a given server
    def get_complete_parts(self,server_sockets,server,all_files,incomplete_file_parts,subfolder):

        Files = dict()
        try:
            if server_sockets[server]:
                try:
                    server_sockets[server].sendall('list '+subfolder)
                    status_1 = server_sockets[server].recv(DFC.BUFFER_SIZE)
                    if status_1 == 'STATUSOK':
                        if self.send_credentials(server, server_sockets[server]):
                            server_sockets[server].sendall('OK')
                            status = server_sockets[server].recv(DFC.BUFFER_SIZE)
                            if status == 'Username?':
                                server_sockets[server].sendall(self.user)
                                user_files = server_sockets[server].recv(DFC.BUFFER_SIZE)
                                if user_files == ' ':
                                    Files[server] = None
                                else:
                                    Files[server] = user_files
                        else:
                            print "Error: Invalid Username/Password. Please try again"
                    server_sockets[server].close()
                except AttributeError as e:
                    print e
            else:
                Files[server] = None
        except socket.timeout:
                print "Error: %s Server Timeout...skipping.." % server
                Files[server] = None

        for key, value in Files.items():
            new_values = []
            if value:
                for f in value.split(','):
                    check = re.search("\.\d$",f)
                    if check:
                        f_new = re.sub(r'.[1-9]$', '', f)
                    else:
                        f_new = f
                    if f.startswith('.'):
                        new_values.append(f[1:])
                    else:
                        new_values.append(f)
                    if f_new.startswith('.'):
                        all_files.add(f_new[1:])
                    else:
                        all_files.add(f_new)
                new_values.sort()
                incomplete_file_parts |= set(new_values)

        return all_files,incomplete_file_parts

    # Method to check if available file parts are enough to re-construct the file or not
    # If we have 4 parts then file can be re-constructed
    # Exception are directories
    def check_file_parts(self,all_files,incomplete_file_parts):
        Files = dict()
        if not all_files:
            return Files,False
        for file in all_files:
            Files[file] = 0
            for f in incomplete_file_parts:
                f_new = re.sub(r'.[1-9]$', '', f)
                if file == f_new.strip():
                    Files[file] += 1

        for value in Files.values():
            if value != 4:
                return Files,False
        return Files,True

    # Method to receive all data from a socket.
    # TCP sockets have a method to sendall data but do have a method to receive all data
    def recv_all(self, client_connection):
        try:
            chunks = []
            res_data = b''

            # Accept data until EOF is received
            while True:
                fdata = client_connection.recv(DFC.BUFFER_SIZE)
                if fdata == 'EOF' or not fdata:
                    break
                chunks.append(fdata)
            # Join the chunks of 1500 bytes and return the whole data
            res_data = b''.join(chunks)

            return res_data

        except socket.error:
            return False

    # Method to create sockets to 4 servers
    def create_sockets(self):
        sockets = dict()
        all_sockets_alive = True
        for s in self.Servers.keys():
            try:
                dfs = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                dfs.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                # Every server has a default timeout of 1 second
                # If any command is not executed in 1 second then we term the server as down
                dfs.settimeout(1.0)
                dfs.connect((self.Servers[s].split(':')[0], int(self.Servers[s].split(':')[1])))
                dfs.sendall("Hello")
                rcv_data = dfs.recv(DFC.BUFFER_SIZE).decode()
                if rcv_data == "Hello":
                    sockets[s] = dfs
                else:
                    sockets[s] = False
                    all_sockets_alive = False
            except (socket.error,socket.timeout):
                sockets[s] = False
                all_sockets_alive = False
                pass

        return (sockets,all_sockets_alive)

    # Method to print menu displayed to user
    def print_menu(self):
        return "\nMenu:\nlist - List current users files\nget [fname]\nput [fname]\nmkdir [directory_name]\nExit\nEnter Command: "

    # Method to verify user credentials of user upon startup
    def login(self):
        try:
            username = raw_input("Username: ")
            password = raw_input("Password: ")
            if username and password:
                if self.user == username and self.password == password:
                    self.userdir = DFC.PROJECT_DIR + self.user
                    if not os.path.exists(self.userdir):
                        os.makedirs(self.userdir)
                        self
                    return True
            return False

        except EOFError:
            sys.exit(0)

    def check_command(self, command):
        try:
            if command:
                if command.lower() == "get":
                    return True
                elif command.lower() == "put":
                    return True
                elif command.lower() == "list":
                    return True
                elif command.lower() == "mkdir":
                    return True
                elif command.lower() == "hello":
                    return True
                else:
                    raise ValueError
        except ValueError:
            return False

# Main method where the execution starts
# A object of DFC class is created and then execution is basically passed to start_forever method
if __name__ == "__main__":
    if len(sys.argv) == 2:
        if os.path.isfile(sys.argv[1]):
            client = DFC(sys.argv[1])
            client.load_configuration()
            client.start_forever()
        else:
            print "Error: Invalid Arguments\nError: python3.4 dfc.py dfc.conf"
    else:
        print "Error: Invalid Number of Arguments\nError: python3.4 dfc.py dfc.conf"
