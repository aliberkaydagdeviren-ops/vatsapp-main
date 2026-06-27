# tkinter
import tkinter as tk
from tkinter import messagebox
from tkinter import colorchooser

from cryptography.fernet import Fernet
import threading
import hashlib
import socket
import base64
import time
import json
import uuid
import os


class Root(tk.Tk):
    def __init__(self):
        super().__init__()
        #information
        self.username = None
        self.id = None
        self.ip = socket.gethostbyname(socket.gethostname())
        self.isOnline = True
        self.users = {}
        
        self.theUser = None
        #window
        self.title("Vatapp")
        self.geometry("400x300")
        self.resizable(False,False)

        self.theFrame = None
        #threads
        udp_listen_thread = threading.Thread(target=self.UDP_Listen, daemon=True)
        udp_listen_thread.start()

        tcp_liste_thread = threading.Thread(target=self.TCP_listen, daemon=True)
        tcp_liste_thread.start()

        #pages
        container = tk.Frame(self, bg="red")
        container.pack(fill="both", expand=True)

        container.rowconfigure(0, weight=1)
        container.columnconfigure(0, weight=1)

        self.frames = {} 

        for F in (HomePage, NamePage, ChatPage, FindPage, settingsPage, userSettingsPage):
            frame = F(parent=container, controller=self)
            self.frames[F] = frame
            frame.grid(row=0, column=0, sticky="nsew")
        # --------------
              
        if os.path.exists("bin/settings.json"):
            self.show_frame(HomePage)
            with open("bin/settings.json",  "r") as file:
                data = json.load(file)
                self.username = data["username"]
                self.id = data["id"]
            self.ServiceAnnouncer()
        else:
            self.show_frame(NamePage)

        self.checkUsers()

    def show_frame(self, page_class):
        frame = self.frames[page_class]
        frame.tkraise()
        self.theFrame = page_class

    def ServiceAnnouncer(self):
        data = {
            "username" : self.username,
            "id" : self.id
        }

        if self.isOnline:

            self.UDP_Broadcast(data)

        self.after(3000, self.ServiceAnnouncer)

    def checkUsers(self):
        timeout = 5
        now = time.time()
        offlineUsers= []

        
        for id, data in self.users.items():
            if timeout < (now - data["timestamp"]):
                offlineUsers.append(id)
        for id in offlineUsers:
            del self.users[id]
        
        offlineUsers.clear()

        self.after(1000, self.checkUsers)

    #network
    
    def UDP_Broadcast(self, data):
        braodcast_ip = "255.255.255.255"
        PORT = 6000

        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)

        sock.sendto(json.dumps(data).encode(), (braodcast_ip, PORT))
        sock.close()

    def UDP_Listen(self):
        UDP_Port = 6000
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind(('',UDP_Port))
        sock.settimeout(3)

        while True:
            try:
                data, addr = sock.recvfrom(1024)
                msg =  json.loads(data.decode())
                
                if msg["id"] not in self.users:
                    self.users[msg["id"]] = {"ip" : addr[0], "username" : msg["username"], "timestamp" : time.time()}
                else:
                    self.users[msg["id"]]["timestamp"] = time.time()
                    self.users[msg["id"]]["username"] = msg["username"]

                    with open(f"bin/chatlog/{msg["id"]}.json", "r") as file:
                        oldData = json.load(file)

                    oldData["timestamp"] = time.time()
                    oldData["ip"] = addr[0]
                    oldData["username"] = msg["username"]

                    with open(f"bin/chatlog/{msg["id"]}.json", "w") as file:
                        json.dump(oldData, file)


            except Exception as e:
                continue
                print(f"Listen error | {e} |")

    def TCP(self, ip, data, state):
        TCP_Port = 6001
        

        try:
            if state == 1:            
                with open(f"bin/chatlog/{self.theUser}.json", "r") as file:
                    fileData = json.load(file)
                    file.close()
                    
                    p = int(fileData["key"]["p"])
                    g = int(fileData["key"]["g"])

                    my_secret = int(fileData["key"]["my_secret"])

                    user_key = int(fileData["key"]["user_key"])
                    mykey = pow(g, my_secret, p)

                    secret_key = pow(user_key, my_secret, p)

                fernet_key = hashlib.sha256(str(secret_key).encode()).digest()[:32]
                print("->TCP | ", fernet_key)
                fernet_key = base64.urlsafe_b64encode(fernet_key)
                cipher = Fernet(fernet_key)

        except TypeError:
            self.TCP(ip, f"{self.id}###KEY_TAKE###", 0)
            return
        except Exception as e:
            print(f"TCP Error -> crypt | {e} |")
            sock.close()

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)

        try:
            sock.connect((ip, TCP_Port))

            if state == 1:
                encrypted_message = cipher.encrypt(data.encode())
                encoded_message = base64.b64encode(encrypted_message).decode('utf-8')

                data = {"encrypted_message" : encoded_message, "key" : mykey}
                
                message = json.dumps(data).encode() + b"###END###"
                
                sock.send(message)

            elif state == 0: #unencrypted message
                data = {"unencrypted_message" : data}
                message = json.dumps(data).encode() + b"###END###"
                sock.send(message)

            response = sock.recv(1024).decode()
                
            if response != "###ACK###":
                messagebox.showwarning("Warning", "User couldn't take the message")   

        except UnboundLocalError:
            pass
        except socket.timeout:
            messagebox.showwarning("Warning", f"The message couldn't send \n'{data}' couldn't send")   
            sock.close()
        except Exception as e:
            print(f"TCP Error -> send | {e} |")
            sock.close()

    def TCP_listen(self):
        def listenALL(conn):
            allData = b""
            while True:
                partData = conn.recv(1024)
                allData += partData
                if b"###END###" in allData:
                    break
            return allData

        ip = socket.gethostbyname(socket.gethostname())
        TCP_Port = 6001

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.bind((ip, TCP_Port))
        sock.listen(5)
        while True:
            try:
                conn, addr = sock.accept()

                data = listenALL(conn)
                reciveData = json.loads(data.decode().replace("###END###", ""))

                conn.sendall("###ACK###".encode())

                if "unencrypted_message" in reciveData and isinstance(self.frames[ChatPage], ChatPage):
                    if "###KEY###" in reciveData["unencrypted_message"]:
                        with open(f"bin/chatLog/{self.theUser}.json", "r+") as file:
                            oldData = json.load(file)
                            oldData["key"]["user_key"] = int(reciveData["unencrypted_message"].replace("###KEY###", ""))
                            file.truncate(0)
                            file.seek(0)
                            json.dump(oldData, file)
                            file.close()
                    
                    elif "###KEY_TAKE###" in reciveData["unencrypted_message"]:
                        with open(f"bin/chatLog/{reciveData["unencrypted_message"].replace("###KEY_TAKE###", "")}.json", "r") as f:
                            fileData = json.load(f)
                            file.close()
                        
                        p = int(fileData["key"]["p"])
                        g = int(fileData["key"]["g"])
                        secret = int(fileData["key"]["my_secret"])
                        key = pow(g, secret) % p

                        self.TCP(addr[0], f"{key}###KEY###", 0)
                    
                    else:
                        print("unencrypted_message mesaj alındı", reciveData["unencrypted_message"])
                        self.frames[ChatPage].insertMessage(0, f"{reciveData["unencrypted_message"]}\n{time.strftime("%H:%M:%S")}", True)

                if "encrypted_message" in reciveData and ChatPage:
                    with open(f"bin/chatlog/{self.theUser}.json", "r+") as file:
                        fileData = json.load(file)
                        fileData["key"]["user_key"] = reciveData["key"]

                        file.truncate(0)
                        file.seek(0)
                        
                        json.dump(fileData, file)
                        
                        file.close()


                    p = int(fileData["key"]["p"])
                    g = int(fileData["key"]["g"])
                    my_secret = int(fileData["key"]["my_secret"])

                    user_key = int(fileData["key"]["user_key"])
                    mykey = pow(g, my_secret) % p
                    secret_key = pow(user_key, my_secret) % p

                    encoded_message = reciveData["encrypted_message"]
                    encrypted_message = base64.b64decode(encoded_message)

                    fernet_key = hashlib.sha256(str(secret_key).encode()).digest()[:32]
                    fernet_key = base64.urlsafe_b64encode(fernet_key)

                    cipher = Fernet(fernet_key)

                    decrypted_message = cipher.decrypt(encrypted_message).decode()

                    if isinstance(self.frames[ChatPage], ChatPage):
                            self.frames[ChatPage].insertMessage(0, f"{decrypted_message}\n{time.strftime("%H:%M:%S")}", True)
                    print(f"encrypted_message mesaj alındı | {decrypted_message} | {encrypted_message}")

            except Exception as e:
                print(f"TCP listen Error | {e} |")
            finally:
                conn.close()

class HomePage(tk.Frame):
    def __init__(self, parent, controller):
        super().__init__(parent)
        #self window
        self.controller = controller
        self.config(bg="yellow", width=1000)

        # widgets ------------------------------------------
        # top widgets
        top_frame = tk.Frame(self, bg="#55f")
        top_frame.pack(side=tk.TOP, fill=tk.X)

        name_lab = tk.Label(top_frame, text="Vatapp", bg="#55f", fg="white", font=("Arial", 20, "bold"))
        name_lab.pack(side=tk.LEFT, padx=5)

        online_btn = tk.Button(top_frame, bd=0, fg='#000', activebackground='#fff', activeforeground='#fff',
            text="online" if controller.isOnline else "offline", 
            bg='#5f5' if controller.isOnline else '#f55',  
            command=lambda: (setattr(controller, 'isOnline', not controller.isOnline), 
                online_btn.config(text="online" if controller.isOnline else "offline",
                    bg='#5f5' if controller.isOnline else '#f55'
                )
            )
        )
        online_btn.pack(side=tk.RIGHT, padx=5)
        # middle widget
        def _on_mousewheel(event):
            self.canvas.yview_scroll(int(-1*(event.delta/120)), "units")
    
        def update_scrollregion(event = None):
            self.canvas.configure(scrollregion=self.canvas.bbox("all"))

        def update_frame_width(event):
            canvas_width = event.width
            self.canvas.itemconfig(self.canvas_frame, width = canvas_width)

        self.user_btn = {}

        self.mid_frame = tk.Frame(self)
        self.mid_frame.pack()

        self.canvas = tk.Canvas(self.mid_frame, height=225)
        self.canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        scroll = tk.Scrollbar(self.mid_frame, orient=tk.VERTICAL, command=self.canvas.yview)
        scroll.pack(side = tk.RIGHT, fill=tk.Y)

        self.canvas.configure(yscrollcommand=scroll.set)

        self.contentFrame = tk.Frame(self.canvas)
        self.canvas_frame = self.canvas.create_window((0, 0), window=self.contentFrame, anchor="nw")

        self.canvas.bind("<Configure>", update_frame_width)

        self.contentFrame.bind("<Configure>", update_scrollregion)

        self.canvas.bind_all("<MouseWheel>", _on_mousewheel)

        # bot widgets
        bot_frame = tk.Frame(self, bg="#55f")
        bot_frame.pack(side=tk.BOTTOM, fill=tk.X)



        settings_btn = tk.Button(bot_frame, text="Settings", bd=0, bg="#fff", command=lambda: (self.controller.show_frame(settingsPage), self.controller.frames[settingsPage].refresh()))
        settings_btn.pack(side=tk.LEFT, padx=5, pady=5)       

        find_btn = tk.Button(bot_frame, text="Find", bd=0, bg="#fff", command=lambda: controller.show_frame(FindPage))
        find_btn.pack(side=tk.RIGHT, padx=5, pady=5)
        # ---------------------------------------------------
        
        self.updateWidgets()
        self.canvas.yview_moveto(1.0)

    def updateWidgets(self):
        for ip, btn in self.user_btn.items():
            btn.destroy()        
        self.user_btn.clear()

        try:
            for filename in os.listdir("bin/chatlog"):
                if not filename.endswith(".json"):
                    continue;
                try:
                    with open(f"bin/chatlog/{filename}", "r") as file:
                        data = json.load(file)
                        self.user_btn[data["id"]] = tk.Button(self.contentFrame, bd=0, bg="#55f", 
                                                              command = lambda id=data["id"]: self.goUser(id))
                        self.user_btn[data["id"]].pack(fill= tk.X, pady= 5, padx= 10)
                        if data["id"] in self.controller.users:
                            self.user_btn[data["id"]].config(bg="#5f5", text=data["username"])
                        else:
                            self.user_btn[data["id"]].config(bg="#f55", 
                                                             text=f"{data["username"]} - {int(time.time() - data["timestamp"])}'s ago")
                except ValueError:
                    os.remove(f"bin/chatlog/{filename}")
                except Exception as e:
                    print(f"Error Home Page -> updateWidgets -> Inner Error | {e} |")
        except Exception as e:
            print(f"Error Home Page -> updateWidgets -> Outer Error | {e} |")

        self.after(1000, self.updateWidgets)

    def goUser(self, id):
        if self.controller.isOnline:
            self.controller.show_frame(ChatPage)
            self.controller.theUser = id
            self.controller.title(f"Chat | {self.controller.users[self.controller.theUser]["username"]} |")

            if isinstance(self.controller.frames[ChatPage], ChatPage):
                self.controller.frames[ChatPage].write()
     
            with open(f"bin/chatlog/{id}.json", "r") as file:
                data = json.load(file)
                file.close()

            p = int(data["key"]["p"])
            g = int(data["key"]["g"])
            secret = int(data["key"]["my_secret"])
            key = pow(g, secret) % p

            self.controller.TCP(self.controller.users[self.controller.theUser]["ip"], f"{key}###KEY###", 0)

class FindPage(tk.Frame):
    def __init__(self, parent, controller):
        super().__init__(parent)
        self.controller = controller

        self.config()

        top_frame = tk.Frame(self, bg="#00f")
        top_frame.pack(side=tk.TOP, fill=tk.X)

        label = tk.Label(top_frame, text="Find Someone", fg="#fff", bg="#00f",font=("Arial", 16))
        label.pack(side=tk.RIGHT, padx=10, pady=5)

        back_btn = tk.Button(top_frame, text="Back", bd=0, command=lambda: controller.show_frame(HomePage))
        back_btn.pack(side=tk.LEFT, padx=10, pady=5)

        self.userButton = {}

        self.updateWidgets()

    def updateWidgets(self):
        for id, btn in self.userButton.items():
            btn.destroy()
        self.userButton.clear()

        for id, data in self.controller.users.items():
            self.userButton[id] = tk.Button(self, text = f"{data["username"]}", bg="#55f", fg="#fff", bd = 0, command = lambda id=id: self.goUser(id))
            self.userButton[id].pack(fill = tk.X, padx = 10, pady = 5)
            
            for filename in os.listdir("bin/chatlog"):
                if filename.endswith(".json") and filename.replace(".json", "") in self.controller.users: 
                    self.userButton[id].destroy()


        self.after(1000, self.updateWidgets)
    
    def goUser(self, id):
        self.controller.show_frame(HomePage)

        data = {
            "id" : id,
            "username" : self.controller.users[id]["username"],
            "ip" : self.controller.users[id]["ip"],
            "timestamp" : time.time(),
            "key" : {
                "p" : 1000000000039,
                "g" : 2,
                "my_secret" :12,
                "user_key" : None
            },
            "messages" : {
                "send" : [],
                "receive" : []
            }
        }
        with open(f"bin/chatlog/{id}.json", "w") as file:
            json.dump(data, file)

class ChatPage(tk.Frame):
    def __init__(self, parent, controller):
        super().__init__(parent)
        self.controller = controller

        self.isCrypt = True

        # widgets
        # top widgets ----------------------------------
        def back():
            controller.show_frame(HomePage)
            self.controller.theUser = None
            self.controller.title("Vatapp")
            self.clearLabel()

        top_frame = tk.Frame(self, bg="#55f")
        top_frame.pack(side=tk.TOP, fill=tk.X)

        back_btn = tk.Button(top_frame, text="Back", bd=0, fg="#55f", bg="#fff", activebackground="#55f", activeforeground="#fff", command=back)
        back_btn.pack(side= tk.LEFT, padx=10)

        self.user_btn = tk.Button(top_frame, bd=0 ,fg="#fff", bg="#99f", font=("Arial", 16), command=lambda:(self.controller.show_frame(userSettingsPage), self.controller.frames[userSettingsPage].refresh()))
        self.user_btn.pack(side=tk.RIGHT, padx=10)
        
        self.crypt_btn = tk.Button(top_frame, bd=0, fg='#000', activebackground='#fff', activeforeground="#fff",
            text="Safe" if controller.isOnline else "Unsafe", 
            bg='#5f5' if controller.isOnline else '#f55',  
            command=lambda: (setattr(self, 'isCrypt', not self.isCrypt), 
                self.crypt_btn.config(text="Safe" if self.isCrypt else "Unsafe",
                    bg='#5f5' if self.isCrypt else '#f55'
                )
            )
        )

        self.crypt_btn.pack(side=tk.RIGHT)

        # middle widgets
        color = "#f0f0f0"

        def update_scrollregion(event=None):
            self.canvas.configure(scrollregion=self.canvas.bbox("all"))
        
        def _on_mousewheel(event):
            self.canvas.yview_scroll(int(-1*(event.delta/120)), "units")
        
        self.msg_labels = []

        chatFrame = tk.Frame(self)
        chatFrame.pack(fill=tk.BOTH, expand=True)
        
        self.canvas = tk.Canvas(chatFrame, height=225, bg=color)
        self.canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        scroll = tk.Scrollbar(chatFrame, orient="vertical")
        scroll.pack(side=tk.RIGHT, fill=tk.Y)

        scroll.config(command=self.canvas.yview)
        self.canvas.configure(yscrollcommand=scroll.set)

        contentFrame = tk.Frame(self.canvas)

        self.canvas.create_window((0,0), window=contentFrame, anchor="nw")

        self.leftFrame = tk.Frame(contentFrame)
        self.leftFrame.grid(row=0, column=0, padx=10, pady=10)
        self.rightFrame = tk.Frame(contentFrame)
        self.rightFrame.grid(row=0, column=1, padx=10, pady=10)

        contentFrame.bind("<Configure>", update_scrollregion)

        self.canvas.bind_all("<MouseWheel>", _on_mousewheel)

        tk.Label(self.leftFrame, text= "-" * 33, bg="#f0f0f0", fg="#f0f0f0").pack(anchor="w")
        tk.Label(self.rightFrame, text="-" * 33, bg="#f0f0f0", fg="#f0f0f0").pack(anchor="e")


        # bottom widgets
        bot_frame = tk.Frame(self, bg="#55f")
        bot_frame.pack(side=tk.BOTTOM, fill=tk.X)

        self.entry = tk.Entry(bot_frame, width=50, bd=0)
        send_btn = tk.Button(bot_frame, text="send", bd=0, bg="#fff", fg="#55f", activebackground="#55f", activeforeground="#fff",
                             command=lambda:self.send())
        send_btn.pack(side=tk.RIGHT, pady=5, padx=10)
        self.entry.pack(side=tk.LEFT, padx=10)
        #-----------
        
        self.refresh()

    def refresh(self):
        try:
            self.user_btn["text"] = self.controller.users[self.controller.theUser]["username"]
        except Exception as e:
            pass
        self.after(1000, self.refresh)
    
    def send(self):
        if "###" in self.entry.get():
            messagebox.showwarning("Warning", "You cannot send message\nThis type of message doesn't support!")
        elif not self.controller.theUser in self.controller.users:
            messagebox.showwarning("Warning", "You cannot send message\nUser is not Online!")
        elif not self.controller.isOnline:
            messagebox.showwarning("Warning", "You cannot send message\nYou are not Online!")
        elif self.entry.get() == "":
            pass
        elif self.entry.get() != "" and self.controller.theUser in self.controller.users and self.controller.isOnline:
            self.insertMessage(1, f"{self.entry.get()}\n{time.strftime("%H:%M:%S")}", True)
            if self.isCrypt:
                self.controller.TCP(self.controller.users[self.controller.theUser]["ip"], self.entry.get(), 1)
            else:
                self.controller.TCP(self.controller.users[self.controller.theUser]["ip"], self.entry.get(), 0)
        self.entry.delete(0, tk.END)

    def insertMessage(self, side, msg, save):
        for i in range(0,int(len(msg) / 26)):
            msg = msg[:26*(i+1)] + "\n" + msg[26*(i+1):]

        self.canvas.yview_moveto(1.0)
        
        if save == True:
            with open(f"bin/chatlog/{self.controller.theUser}.json", "r") as file:
                data = json.load(file)
                file.close()
            
            if side == 1:
                data["messages"]["send"].append((msg, time.time()))
            elif side == 0:
                data["messages"]["receive"].append((msg, time.time()))

            with open(f"bin/chatlog/{self.controller.theUser}.json", "w") as file:
                json.dump(data, file)
                file.close()
        

        if side == 0:
            self.msg_labels.append(tk.Label(self.leftFrame, text=msg, bg="#99f", fg="#fff"))
            self.msg_labels[-1].pack(anchor="w", pady=2)
            self.msg_labels.append(tk.Label(self.rightFrame, text=msg, bg="#f0f0f0", fg="#f0f0f0"))
            self.msg_labels[-1].pack(anchor="e", pady=2)
        elif side == 1:
            self.msg_labels.append(tk.Label(self.rightFrame, text=msg, bg="#fff", fg="#99f"))
            self.msg_labels[-1].pack(anchor="e", pady=2)
            self.msg_labels.append(tk.Label(self.leftFrame, text=msg, bg="#f0f0f0", fg="#f0f0f0"))
            self.msg_labels[-1].pack(anchor="w", pady=2)


        self.update_scrollregion()

    def update_scrollregion(self):
        self.canvas.update_idletasks()
        self.canvas.configure(scrollregion=self.canvas.bbox("all"))

    def clearLabel(self):
        for lab in self.msg_labels:
            lab.destroy()
        self.msg_labels.clear()

    def write(self):
        
        with open(f"bin/chatLog/{self.controller.theUser}.json", "r") as file:
            data = json.load(file)
            file.close()

        rcv_msg = data["messages"]["receive"]
        snd_msg = data["messages"]["send"]

        index_rcv = 0
        index_snd = 0

        while True:
            if index_snd == len(snd_msg) and index_rcv == len(rcv_msg):
                break
            elif index_rcv == len(rcv_msg):
                for msg in snd_msg[index_snd:]:
                    self.insertMessage(1, snd_msg[index_snd][0], False)
                break
            elif index_snd == len(snd_msg):
                for msg in rcv_msg[index_rcv:]:
                    self.insertMessage(0, rcv_msg[index_rcv][0], False)
                break

            if rcv_msg[index_rcv][1] > snd_msg[index_snd][1]:
                self.insertMessage(1, snd_msg[index_snd][0], False)
                index_snd += 1
            elif rcv_msg[index_rcv][1] < snd_msg[index_snd][1]:
                self.insertMessage(0, rcv_msg[index_rcv][0], False)
                index_rcv += 1

        snd_msg = data["messages"]["send"]
        
class NamePage(tk.Frame):
    def __init__(self, parent, controller):
        super().__init__(parent)
        self.controller = controller

        self.config(bg="#55f")

        label = tk.Label(self, text="Vatsapp", bg="#55f", fg="#fff", font=("Arial", 25, "bold"))
        label.pack(padx=15, pady=20, fill=tk.X)

        label = tk.Label(self, text="Enter a Name", bg="#55f", fg="#fff", font=("Arial", 16))
        label.pack(padx=5, anchor=tk.W)

        self.entry = tk.Entry(self, font=("Arial", 16), bd=0, fg="#55f")
        self.entry.pack(fill=tk.X, padx=5, pady=5)

        enter_btn = tk.Button(self, text="Enter", bd=0, bg="#fff", fg="#55f", activebackground="#55f", activeforeground="#fff",
                              command=lambda: self.nameYes() if self.entry.get() != "" else self.nameNo())
        enter_btn.pack(padx=20, pady=15, fill=tk.X)

        clear_btn = tk.Button(self, text="Clear", bd=0, bg="#fff", fg="#55f", activebackground="#55f", activeforeground="#fff",
                              command=lambda: self.entry.delete(0, tk.END))
        clear_btn.pack()
    def nameYes(self):
        name = self.entry.get()
        id = str(uuid.uuid4())

        self.controller.username = name
        self.controller.id = id
        self.controller.ServiceAnnouncer()
        self.controller.show_frame(HomePage)

        data = {
            "username" : name,
            "id" : id
        }

        with open("bin/settings.json", "w") as file:
            json.dump(data, file)
            file.close()
        
    def nameNo(self):
        self.entry["bg"] = "#f55"
        tk.Label(self, text="The name cannot be empty", bg="#55f",fg="red", font=("Arial", 8)).pack(side=tk.BOTTOM)

class settingsPage(tk.Frame):
    def __init__(self, parent, controller):
        super().__init__(parent)
        self.controller = controller

        # widgets
        # top widgets
        top_frame = tk.Frame(self, bg="#55f")
        top_frame.pack(side=tk.TOP, fill=tk.X)

        name_lbl = tk.Label(top_frame, text="Settings", bg="#55f", fg="white", font=("Arial", 15))
        name_lbl.pack(side=tk.RIGHT, padx=10, pady=5)
        back_btn = tk.Button(top_frame, text="back", bd=0, bg="#fff", fg="#55f", activebackground="#55f", activeforeground="#fff", command=lambda: self.controller.show_frame(HomePage))
        back_btn.pack(side=tk.LEFT, padx=10, pady=5)

        # username
        username_frame = tk.Frame(self)
        username_frame.pack(fill=tk.X, padx=15, pady=10)

        self.username_btn = tk.Button(username_frame, text=None, bd=0, bg="#55f", fg="#fff", activebackground="#fff", activeforeground="#55f" ,font=("Arial", 10), command=self.nameChange)
        self.username_btn.pack(side=tk.LEFT)
        
        self.username_ent = tk.Entry(username_frame, bd=0, bg="#fff", fg="#55f")

        self.username_enter_btn = tk.Button(username_frame, text="Enter", bd=0, bg="#55f", fg="#fff", activebackground="#fff", activeforeground="#55f" ,font=("Arial", 10), command=self.nameChanged)

        # id
        id_frame = tk.Frame(self)
        id_frame.pack(fill=tk.X, padx=15, pady=10)

        self.id_lbl = tk.Label(id_frame, text=None, font=("Arial", 10))
        self.id_lbl.pack(side=tk.LEFT)
        #ip 
        ip_frame = tk.Frame(self)
        ip_frame.pack(fill=tk.X, padx=15, pady=10)

        self.ip_lbl = tk.Label(ip_frame, text=None, font=("Arial", 10))
        self.ip_lbl.pack(side=tk.LEFT)

    def refresh(self):
        self.username_btn["text"] = f"name : {self.controller.username}"
        self.id_lbl["text"] = f"ID : {self.controller.id}"
        self.ip_lbl["text"] = f"IP : {self.controller.ip}"

    def nameChanged(self):
        self.controller.username = self.username_ent.get()
        data = {
            "username" : self.username_ent.get(),
            "id" : self.controller.id
        }

        with open("bin/settings.json", "w") as file:
            json.dump(data, file)
            file.close()


        self.username_btn.pack(side=tk.LEFT)
        self.username_ent.pack_forget()
        self.username_enter_btn.pack_forget()
    def nameChange(self):

        self.username_btn.pack_forget()
        self.username_ent.pack(side=tk.LEFT)
        self.username_enter_btn.pack(side=tk.LEFT)

class userSettingsPage(tk.Frame):
    def __init__(self, parent, controller):
        super().__init__(parent)
        self.controller = controller

        # widgets
        # top widgets
        top_frame = tk.Frame(self, bg="#55f")
        top_frame.pack(side=tk.TOP, fill=tk.X)

        back_btn = tk.Button(top_frame, text="Back", bd=0, fg="#55f", bg="#fff", activebackground="#55f", activeforeground="#fff", command=lambda:self.controller.show_frame(ChatPage))
        back_btn.pack(side=tk.LEFT, padx=10, pady=5)

        self.name_lbl = tk.Label(top_frame, bg="#55f", fg="#fff", font=("Arial", 15))
        self.name_lbl.pack(side=tk.RIGHT, padx=10, pady=5)
        
        # key change
        def keyBtn():
            self.key_btn.pack_forget()
            self.key_ent.pack(side=tk.LEFT, padx=10)
            self.key_enter_back_btn.pack(side=tk.RIGHT, padx=10)
            self.key_enter_btn.pack(side=tk.RIGHT, padx=10)

        def keyBack():
            self.key_btn.pack()
            self.key_enter_back_btn.pack_forget()
            self.key_ent.pack_forget()
            self.key_enter_btn.pack_forget()

        key_Frame = tk.Frame(self)
        key_Frame.pack(fill=tk.X, padx=15, pady=10)

        self.key_btn = tk.Button(key_Frame, text="Change Key", bd=0, bg="#55f", fg="#fff", activebackground="#fff", activeforeground="#55f" ,font=("Arial", 10), command=keyBtn)
        self.key_btn.pack()
        
        self.key_ent = tk.Entry(key_Frame, bd=0, bg="#fff", fg="#55f")
        self.key_enter_btn = tk.Button(key_Frame, text="Enter", bd=0, bg="#55f", fg="#fff", activebackground="#fff", activeforeground="#55f" ,font=("Arial", 10), command=self.keyChanged)
        self.key_enter_back_btn = tk.Button(key_Frame, text="Back", bd=0, bg="#55f", fg="#fff", activebackground="#fff", activeforeground="#55f" ,font=("Arial", 10), command=keyBack)

        # chat clear
        chatClear_frame = tk.Frame(self)
        chatClear_frame.pack(fill=tk.X, padx=15, pady=10)

        chatClear_btn = tk.Button(chatClear_frame, text="Clear", bd=0, bg="#55f", fg="#fff", activebackground="#fff", activeforeground="#55f" ,font=("Arial", 10), command=self.chatClear)
        chatClear_btn.pack(pady=20)



    def keyChanged(self):
        if self.controller.theUser in self.controller.users and self.controller.isOnline:
            key = self.key_ent.get()

            with open(f"bin/chatLog/{self.controller.theUser}.json", "r") as file:
                data = json.load(file)
                file.close()

            p = int(data["key"]["p"])
            g = int(data["key"]["g"])
            secret = int(key)
            
            data["key"]["my_secret"] = key
            
            key = pow(g, secret) % p

            #self.controller.TCP(self.controller.users[self.controller.theUser]["ip"], f"{key}###KEY###", 0)
            
            with open(f"bin/chatLog/{self.controller.theUser}.json", "w") as file:
                json.dump(data, file)
                file.close()

            self.key_ent.delete(0, tk.END)
        elif not self.controller.theUser in self.controller.users:
            messagebox.showwarning("Warning", "You cannot change settings \nUser is not Online!")            
        elif not self.controller.isOnline:
            messagebox.showwarning("Warning", "You cannot change settings \nYour are not Online!")

        self.key_btn.pack()
        self.key_enter_back_btn.pack_forget()
        self.key_ent.pack_forget()
        self.key_enter_btn.pack_forget()

    def chatClear(self):
        with open(f"bin/chatLog/{self.controller.theUser}.json", "r+") as file:
            fileData = json.load(file)
            fileData["messages"] = { "send" : [], "receive" : [] }

            file.truncate(0)
            file.seek(0)

            json.dump(fileData, file)

        self.controller.frames[ChatPage].clearLabel()

    def refresh(self):
        try:
            self.name_lbl["text"] = f"{self.controller.users[self.controller.theUser]["username"]} Settings"
        except:
            pass

if __name__ == "__main__":
    
    try:
        with open("bin/settings.json", 'r') as file:
            json.load(file)
            file.close()
    except json.JSONDecodeError:
        os.remove("bin/settings.json")
    except:
        pass

    if not os.path.exists("bin/chatLog"):
        os.makedirs("bin/chatLog")


    root = Root()
    root.mainloop()
