#!/usr/bin/python

# Student name and No.: Sun Peigen 3035084548
# Student name and No.: Xu Fangyuuan 3035085530
# Development platform: Ubuntu
# Python version: 2.7.9
# Version: 2.1


from Tkinter import *
import sys
import socket
import threading
import time
import select

#
# Global variables
#

# self info, chatroom, and client_sk socket
# client_sk socket is for connection to the server
# p2pclient_sk is to set up connection the forward link, only one.
# p2pserver_sk is to receive the backward link, only one.
# be_in_chatroom is the Flag for checking whether the client_sk has already in a chatroom

#TODO:
#Locks for multiple variables
#Cannot send message through forward link
#Self link

myself = None
forward_user = None
user_list = []
back_list = []

user_lock = threading.Lock()
write_lock = threading.Lock()
client_lock = threading.Lock()
server_lock = threading.Lock()
lock = threading.Lock()

keepalive_thread = None
p2pclient_thread = None
p2pserver_thread = None
thread_List = []

chatroom = ""
be_in_chatroom = False
connected_to_server = False
all_thread_running = True

client_sk = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
p2pclient_sk = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
p2pserver_sk = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
write_sk_list = []


#
# This is the hash function for generating a unique
# Hash ID for each peer.
# Source: http://www.cse.yorku.ca/~oz/hash.html
#
# Concatenate the peer's username, str(IP address),
# and str(Port) to form the input to this hash function
#
def sdbm_hash(instr):
	hash = 0L
	for c in instr:
		hash = long(ord(c)) + (hash << 6) + (hash << 16) - hash
	return hash & 0xffffffffffffffff

class user:
	'''
	A class to store the user's information.
	'''
	def __init__(self, name="", IP="", port="", id=0):
		self.name = name
		self.IP = IP
		self.port = port
		self.rehash()
		self.id = id

	def set(self, other):
		self.name = other.name
		self.IP = other.IP
		self.port = other.port
		self.rehash()
		self.id = other.id

	def setname(self, name):
		self.name = name
		self.rehash()

	def setIP(self, IP):
		self.IP = IP
		self.rehash()

	def setport(self, port):
		self.port = port
		self.rehash()

	def setid(self, id):
		self.id = id

	def rehash(self):
		self.hash_id = sdbm_hash(self.name+self.IP+self.port)

	def getname(self):
		return self.name

	def getIP(self):
		return self.IP

	def getport(self):
		return self.port

	def gethash(self):
		return self.hash_id

	def getid(self):
		return self.id

	def __str__(self):
		return self.name+":"+self.IP+":"+self.port

	def __eq__(self, other):
		return self.gethash() == other.gethash()

	def __lt__(self,other):
		return self.gethash() < other.gethash()

	def isNone(self):
		if self.name == "" and self.IP == "" and self.port == "":
			return True
		return False

def hand_shake(this_user):
	global myself, forward_user, lock, chatroom, client_lock
	try:
		client_lock.acquire()
		p2pclient_sk.send("P:"+chatroom+":"+myself.getname()+":"+myself.getIP()+":"+myself.getport()+":"+str(myself.getid())+"::\r\n")
		client_lock.release()
	except socket.error:
		return False
	else:
		msg = p2pclient_sk.recv(1024)
		if msg == "":
			return False
		elif msg[0] == 'S':
			lock.acquire()
			forward_user = this_user
			forward_user.setid(int(msg[2:-4]))
			lock.release()
			return True
		else:
			return False

def keepalive():
	global all_thread_running, thread_List, myself, chatroom, lock, client_sk, client_lock
	wait_time = 0
	while all_thread_running:
		if wait_time < 20:
			time.sleep(1)
			wait_time += 1
		else:
			update_user_list()
			CmdWin.insert(1.0, "\nSend keepalive JOIN message to server")
			wait_time = 0



def update_user_list():
	global client_lock, client_sk, user_list, user_lock, be_in_chatroom, keepalive_thread, myself
	try:
		client_lock.acquire()
		client_sk.send("J:"+chatroom+":"+myself.getname()+":"+myself.getIP()+":"+myself.getport()+"::\r\n")
	except socket.error, err:
		client_sk.close()
		client_sk = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		try:
			client_sk.connect((sys.argv[1],int(sys.argv[2])))
		except socket.error, err:
			return
		finally:
			client_lock.release()
		CmdWin.insert(1.0, "\nConnect to server at " + sys.argv[1] + ":" + sys.argv[2])
		return
	msg = client_sk.recv(1024)
	client_lock.release()
	if msg[0] == "M":
		# use thread to active the keepalive procedure
		be_in_chatroom = True
		if keepalive_thread.isAlive() != True:
			keepalive_thread.start()
		user_lock.acquire()
		temp_user_list=[]
		info = msg[2:-4].split(":")
		while info:
			new_user = user(info.pop(0),info.pop(0),info.pop(0))
			temp_user_list.append(new_user)
		mark_list = []
		for u in user_list:
			if u not in temp_user_list:
				mark_list.append(u)
		for u in mark_list:
			user_list.remove(u)
		for u in temp_user_list:
			if u not in user_list:
				user_list.append(u)
        
        mark_list=[]
		user_list.sort()
        for u in back_list:
            if u not in user_list:
                mark_list.append(u)
        for u in mark_list:
            back_list.remove(u)
		user_lock.release()

def p2pserver():
	global all_thread_running, lock, write_sk_list, user_list, thread_List, p2pserver_sk, myself, chatroom, user_lock, server_lock
	server_lock.acquire()
	p2pserver_sk.bind((myself.getIP(),int(myself.getport())))
	p2pserver_sk.listen(5)
	p2pserver_sk.settimeout(1.0)
	server_lock.release()

	CmdWin.insert(1.0,"\nMy IP address: "+myself.getIP()+" My listening port: "+myself.getport())
	while all_thread_running:
		try:
			new_sk, who = p2pserver_sk.accept()
		except socket.timeout:
			continue
		msg = new_sk.recv(1024)
		if msg[0] == 'P':
			# acknowledge hand shake
			info = msg[2:-4].split(':')
			if chatroom == info.pop(0):
				new_user = user(info.pop(0), info.pop(0), info.pop(0), info.pop(0))
				try:
					new_sk.send("S:"+str(myself.getid())+"::\r\n")
				except socket.error, err:
					print "Error:", err
				CmdWin.insert(1.0, "\n"+new_user.getname()+" has linked to me with msg id " + str(new_user.getid()))
				user_lock.acquire()
				if not new_user in user_list:
					user_list.append(new_user)
					user_list.sort()
				else:
					user_list[user_list.index(new_user)]=new_user #update message id
				write_sk_list.append(new_sk)
				back_list.append(new_user)
				new_thread = threading.Thread(target=socket_listen, args=(new_sk,))
				new_thread.start()
				thread_List.append(new_thread)
				user_lock.release()


def p2pclient():
	global p2pclient_sk, lock, myself, chatroom, thread_List, user_list, client_sk, back_list,user_lock,client_lock, all_thread_running

	# lock.acquire()
	# addr, dummy_port = client_sk.getsockname()
	# myself.setIP(addr)
	# myself.setport(sys.argv[3])
	# lock.release()

	while all_thread_running:
		temp_forward_user = None
		start = 0
		update_user_list()
		user_lock.acquire()

		for u in user_list:
			if u == myself:
				start = (user_list.index(u) + 1) % len(user_list)
		while not user_list[start] == myself:
			if user_list[start] in back_list:
				start = (start + 1) % len(user_list)
			else:
				temp_forward_user = user_list[start]
				break
		user_lock.release()
		if temp_forward_user != None:
			p2pclient_sk = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
			try:
				p2pclient_sk.connect((temp_forward_user.getIP(), int(temp_forward_user.getport())))
			except socket.error, error:
				print "Cannot connect to forward user : ", user_list[start], "\n", error
				time.sleep(1)
				continue
			else:
				if not hand_shake(temp_forward_user):
					continue
			CmdWin.insert(1.0, "\nSuccessfully link to the group -- via "+temp_forward_user.getname())
			write_sk_list.append(p2pclient_sk)
			socket_listen(p2pclient_sk)
			CmdWin.insert(1.0, "\nFoward link broke")
		else:
			time.sleep(1)


def socket_listen(sockfd):
	global all_thread_running, lock, write_sk_list, user_list, thread_List, p2pclient_sk, write_lock, myself
	sockfd.settimeout(1.0)
	while all_thread_running:
		try:
			msg = sockfd.recv(1000)
		except socket.timeout:
			continue
		except socket.error:
			continue
		else:
			if msg != "":

				current_sender = None   #TODO: error messages
				pos = 1
				new_pos = msg.find(':', pos+1)
				roomname = msg[pos+1 : new_pos]
				pos = new_pos
				new_pos = msg.find(':', pos+1)
				temp_HID = int(msg[pos+1 : new_pos])
				pos = new_pos
				new_pos = msg.find(':', pos+1)
				temp_name = msg[pos+1 : new_pos]
				pos = new_pos
				new_pos = msg.find(':', pos+1)
				temp_msgID = int(msg[pos+1 : new_pos])
				pos = new_pos
				new_pos = msg.find(':', pos+1)
				msg_len= int(msg[pos+1 : new_pos])
				message = msg[new_pos+1: new_pos+1+msg_len]

				if roomname!= chatroom:
					CmdWin.insert(1.0, "\nError: Received a message from another chatroom")
				else:
					user_lock.acquire()
					for u in user_list:
						if u.gethash() == temp_HID:
							current_sender = u
					user_lock.release()


					if current_sender is None:
						update_user_list()
						MsgWin.insert(1.0, "\n["+temp_name+"] "+message)
						send_message(msg, sockfd)
						CmdWin.insert(1.0, "\nRelay the message to other peer"+message)
					elif not ((int(temp_msgID) > int(current_sender.getid()))):
						#CmdWin.insert(1.0, "\nError: Received a message that has been seen before: " + str(temp_msgID) + " " + str(current_sender.getid())+" " + message)
					else:
						lock.acquire()
						current_sender.setid(temp_msgID)
						lock.release()
						MsgWin.insert(1.0, "\n["+temp_name+"] "+message)
						send_message(msg, sockfd)
						CmdWin.insert(1.0, "\nRelay the message to other peer"+message)
			else:
				MsgWin.insert(1.0, "\n socket close")
				write_lock.acquire()
				sockfd.close()
				if sockfd in write_sk_list:
					write_sk_list.remove(sockfd)
				write_lock.release()
                update_user_list();
				return

def send_message(msg, sockfd = None):
	global lock, write_sk_list, write_lock
	write_lock.acquire()
	for s in write_sk_list:
		if s != sockfd:
			s.send(msg)
	write_lock.release()

#
# Functions to handle user input
#

def do_User():
	global myself
	# just check and change
	username = userentry.get()
	if username != "":
		if be_in_chatroom:
			CmdWin.insert(1.0, "\nCannot change username in the chatroom")
		else:
			myself.setname(username)
			CmdWin.insert(1.0, "\n[User] username: "+myself.getname())
			userentry.delete(0, END)


def do_List():

	global connected_to_server, chatroom
	# First try to connect
	if connected_to_server == False:
		try:
			client_sk.connect((sys.argv[1],int(sys.argv[2])))
		except socket.error, err:
			print "Connection failed!\nError:", err
		else:
			CmdWin.insert(1.0, "\nConnect to server at " + sys.argv[1] + ":" + sys.argv[2])
			connected_to_server = True

	try:
		client_sk.send("L::\r\n")
	except socket.error, err:
		print "Error:", err
	msg = client_sk.recv(1024)
	# Check message Type
	if msg[0] == 'G':
		if msg == "G::\r\n":
			CmdWin.insert(1.0, "\nNo active chatrooms")
		else :
			CmdWin.insert(1.0, "\nHere are the active chatroooms:")
			chatrooms = msg[2:-4].split(":")
			for room in chatrooms:
				CmdWin.insert(1.0, "\n\t" + room)
	else:
		CmdWin.insert(1.0, "\nError: "+(msg[2:-4] if msg[2:-4] != '' else "Unkown Error"))

def do_Join():
	global connected_to_server, be_in_chatroom, chatroom, myself

	if connected_to_server == False:
		try:
			client_sk.connect((sys.argv[1],int(sys.argv[2])))
		except socket.error, err:
			print "Connection failed!\nError:", err
		else:
			CmdWin.insert(1.0, "\nConnect to server at " + sys.argv[1] + ":" + sys.argv[2])
			connected_to_server = True

	if userentry.get() == "":
		return
	if myself.getname() == "":
		CmdWin.insert(1.0, "\nPlease input a username first")
	else:
		if be_in_chatroom:
			CmdWin.insert(1.0, "\nAlready in chatroom: "+chatroom+". Cannot JOIN again")
		else:
			chatroom = userentry.get()
			userentry.delete(0, END)
			addr, dummy_port = client_sk.getsockname()
			myself.setIP(addr)
			myself.setport(sys.argv[3])
			try:
				client_sk.send("J:"+chatroom+":"+myself.getname()+":"+myself.getIP()+":"+myself.getport()+"::\r\n")
			except socket.error, err:
				print "Error:", err
			msg = client_sk.recv(1024)
			if msg[0] == "M":
				be_in_chatroom = True
				keepalive_thread.start() # Start the keep alive thread
				info = msg[2:-4].split(":")
				while info:
					new_user = user(info.pop(0),info.pop(0),info.pop(0))
					if new_user == myself:
						user_list.append(myself)
					else:
						user_list.append(new_user)
				user_list.sort()
				p2pclient_thread.start()
				p2pserver_thread.start()


def do_Send():
	global myself, chatroom, lock, user_list, user_lock
	message = userentry.get()
	if message == "":
		return
	elif not be_in_chatroom:
		return
	userentry.delete(0, END)
	lock.acquire()
	myself.setid(myself.getid()+1)
	user_lock.acquire()
	user_list[user_list.index(myself)].setid(myself.getid())
	user_lock.release()
	MsgWin.insert(1.0, "\n["+myself.getname()+"] "+message)
	msg = "T:" + chatroom + ":" + str(myself.gethash()) + ":" + myself.getname() + ":" + str(myself.getid()) + ":" + str(len(message)) + ":" +  message + "::\r\n"
	lock.release()
	send_message(msg)

def do_Quit():
	global all_thread_running, lock, thread_List, write_sk_list, p2pclient_sk, p2pserver_sk, client_sk
	all_thread_running = False
	lock.acquire()
	for s in write_sk_list:
		s.close()
	p2pclient_sk.close()
	p2pserver_sk.close()
	client_sk.close()
	lock.release()
	for t in thread_List:
		t.join()
	sys.exit(0)


#
# Initialize the Global variables
#
myself = user()
forward_user = user()
keepalive_thread = threading.Thread (target=keepalive)
p2pclient_thread = threading.Thread (target=p2pclient)
p2pserver_thread = threading.Thread (target=p2pserver)

#
# Set up of Basic UI
#
win = Tk()
win.title("MyP2PChat")

#Top Frame for Message display
topframe = Frame(win, relief=RAISED, borderwidth=1)
topframe.pack(fill=BOTH, expand=True)
topscroll = Scrollbar(topframe)
MsgWin = Text(topframe, height='15', padx=5, pady=5, fg="red", exportselection=0, insertofftime=0)
MsgWin.pack(side=LEFT, fill=BOTH, expand=True)
topscroll.pack(side=RIGHT, fill=Y, expand=True)
MsgWin.config(yscrollcommand=topscroll.set)
topscroll.config(command=MsgWin.yview)

#Top Middle Frame for buttons
topmidframe = Frame(win, relief=RAISED, borderwidth=1)
topmidframe.pack(fill=X, expand=True)
Butt01 = Button(topmidframe, width='8', relief=RAISED, text="User", command=do_User)
Butt01.pack(side=LEFT, padx=8, pady=8);
Butt02 = Button(topmidframe, width='8', relief=RAISED, text="List", command=do_List)
Butt02.pack(side=LEFT, padx=8, pady=8);
Butt03 = Button(topmidframe, width='8', relief=RAISED, text="Join", command=do_Join)
Butt03.pack(side=LEFT, padx=8, pady=8);
Butt04 = Button(topmidframe, width='8', relief=RAISED, text="Send", command=do_Send)
Butt04.pack(side=LEFT, padx=8, pady=8);
Butt05 = Button(topmidframe, width='8', relief=RAISED, text="Quit", command=do_Quit)
Butt05.pack(side=LEFT, padx=8, pady=8);

#Lower Middle Frame for User input
lowmidframe = Frame(win, relief=RAISED, borderwidth=1)
lowmidframe.pack(fill=X, expand=True)
userentry = Entry(lowmidframe, fg="blue")
userentry.pack(fill=X, padx=4, pady=4, expand=True)

#Bottom Frame for displaying action info
bottframe = Frame(win, relief=RAISED, borderwidth=1)
bottframe.pack(fill=BOTH, expand=True)
bottscroll = Scrollbar(bottframe)
CmdWin = Text(bottframe, height='15', padx=5, pady=5, exportselection=0, insertofftime=0)
CmdWin.pack(side=LEFT, fill=BOTH, expand=True)
bottscroll.pack(side=RIGHT, fill=Y, expand=True)
CmdWin.config(yscrollcommand=bottscroll.set)
bottscroll.config(command=CmdWin.yview)

def main():
	if len(sys.argv) != 4:
		print "P2PChat.py <server address> <server port no.> <my port no.>"
		sys.exit(2)
	win.protocol("WM_DELETE_WINDOW", do_Quit)
	win.mainloop()


if __name__ == "__main__":
	main()
