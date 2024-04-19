import socket
import subprocess
import sys
import time
import threading
import asyncio
import io
import os
import colorama
from colorama import Fore, Back, Style
import signal
import random
import select
import argparse

# List of ASCII art banners
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
    [  /   ,'   "serving Justice, one shell at a time"
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
    # Add more banners as needed
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
  list        - List all sessions
  session <id> - Interact with a session
  exit | Ctrl +c*2    - Exit the SwordShell
"""
# Clear the terminal screen
os.system('cls' if os.name == 'nt' else 'clear')

# Print the ASCII art banner
print(random.choice(colors) + random.choice(banners) +"\n" +'\033[0m' + commands)  # '\033[0m' resets the color# def shellreceiver(conn):
#     global session_started
#     while True:
        
           
#         try:
            
            
#             data=conn.recv(1)
#             print(data.decode(), end="", flush=True)
#         except :
#             print("server/socket must have died...time to hop off")
#             remove_connection(conn)
#             session_started = False
#             break

# def shellsender(conn):
#     global session_started
#     while True:
       
#         try:
#             mycmd=input(Fore.YELLOW + "\n" + Fore.WHITE)
#             mycmd=mycmd+"\n"
#             conn.send(mycmd.encode())
        
#         except :
#             print("server/socket must have died...time to hop off")
#             remove_connection(conn)
#             session_started = False
#             break


parser = argparse.ArgumentParser(description="Run the Swordshell program.")

# Add the arguments
parser.add_argument('-host', type=str, default='0.0.0.0', help='The host to connect to.')
parser.add_argument('-port', type=int, default=5555, help='The port to connect to.')

# Parse the arguments
args = parser.parse_args()

# Use the arguments
host = args.host
port = args.port


def handle_client(conn, addr):
    print(Fore.GREEN, f'\n[*] Connecting to session: {addr[0]}:{addr[1]}', Fore.WHITE)
    print(f'\n[*] press Ctrl+c to go back ', Fore.WHITE)

    while True:
        read_sockets, _, _ = select.select([conn, sys.stdin], [], [], 1)

        for sock in read_sockets:
            if sock == conn:
                data = conn.recv(1024)
                if not data:
                    print("Connection closed by the client")
                    return
                print(data.decode(), end="")
            else:
                mycmd = input()
                mycmd = mycmd + "\n"
                conn.send(mycmd.encode())


s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind((host, port))
s.listen(5)
print(Fore.YELLOW + "[+] listening on port "+str(port), Fore.WHITE)

connections = []

def remove_connection(conn):
    global connections
    connections = [(c, addr) for c, addr in connections if c != conn]

non_daemon_threads = []


def accept_connections():
    while True:
        conn, addr = s.accept()
        if addr[0] not in (connection[1][0] for connection in connections):
            connections.append((conn, addr))
            print(Fore.GREEN, f'\n[*] Accepted new connection from: {addr[0]}:{addr[1]}', Fore.WHITE)
           
        else:
            conn.close()
# Create a new thread that will run the accept_connections function
accept_thread = threading.Thread(target=accept_connections)
# Start the new thread
accept_thread.start()

# This function will be called when the alarm signal is raised
def handler(signum, frame):
     pass

# Set the signal handler
signal.signal(signal.SIGALRM, handler)
first_press_time = None

ctrl_c_count = 0
session_started = False
while True:
    
    signal.alarm(1)
   
    try:
        
        
        while True:
            if not session_started:
                command = input(Fore.YELLOW + "\n-{-->> " + Fore.GREEN)
                if command.strip() == '':
                     break
                     
                if command == 'list':
                    print("\nAvailable sessions:")
                    for i, connection in enumerate(connections):
                        print(f"{i+1}. {connection[1][0]}:{connection[1][1]}")
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
                            print("Session interrupted. Returning to menu.")
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
