 #-*-coding:utf-8-*-
import socket, threading, os, sys, time, datetime
import hashlib, platform, stat  
from os.path import join, getsize
listen_ip = "0.0.0.0"  
listen_port = 21  
conn_list = []  
root_dir = "C://Autodesk"
if sys.version_info < (3, 0):
		root_dir = root_dir.decode('utf-8').encode('gb2312')#目录 windows目录下使用这个
#root_dir = "/"#Linux utf8系统使用这个
max_connections = 500  
conn_timeout = 120  
	
class FtpConnection(threading.Thread):  
		def __init__(self, fd):  
				threading.Thread.__init__(self)  
				self.fd = fd  
				self.running = True  
				self.setDaemon(True)  
				self.alive_time = time.time()  
				self.option_utf8 = False  
				self.identified = False  
				self.option_pasv = True  
				self.username = ""
				self.file_pos = 0
				self.u_username = "wmfy808"#帐号
				self.u_passwd="123456"#密码
				self.u_limit_size=5*1024*1024*1024#限制目录大小为5G
				self.u_permission = "read,write,modify"#权限
		def process(self, cmd, arg):  
				cmd = cmd.upper();  
				arg2 = []
				if self.option_utf8:
						if sys.version_info < (3, 0):  
								arg = unicode(arg, "utf8").encode(sys.getfilesystemencoding())  
				print ("<<", cmd, arg, self.fd)
				# Ftp Command  
				if cmd == "BYE" or cmd == "QUIT":  
						if os.path.exists(root_dir + "/xxftp.goodbye"):  
								self.message(221, open(root_dir + "/xxftp.goodbye").read())  
						else:  
								self.message(221, "Bye!")  
						self.running = False  
						return  
				elif cmd == "USER":  
						# Set Anonymous User  
						if arg == "": arg = "anonymous"  
						for c in arg:  
								if not c.isalpha() and not c.isdigit() and c!="_":  
										self.message(530, "Incorrect username.")  
										return  
						self.username = arg  
						self.home_dir = root_dir 
						self.curr_dir = "/"  
						self.curr_dir, self.full_path, permission, self.vdir_list, \
								limit_size, is_virtual = self.parse_path("/")  
						if not os.path.isdir(self.home_dir):  
								self.message(530, "path " + self.home_dir + " not exists.")  
								return  
						self.pass_path = self.home_dir + "/.xxftp/password"  
						if os.path.isfile(self.pass_path):  
								self.message(331, "Password required for " + self.username)  
						else:  
								self.message(230, "Identified!")  
								self.identified = True  
						return  
				elif cmd == "PASS":  
						if open(self.pass_path).read() == hashlib.md5(arg).hexdigest():  
								self.message(230, "Identified!")  
								self.identified = True  
						else:  
								self.message(530, "Not identified!")  
								self.identified = False  
						return  
				elif not self.identified:  
						self.message(530, "Please login with USER and PASS.")  
						return  
	
				self.alive_time = time.time()  
				finish = True  
				if cmd == "NOOP":  
						self.message(200, "ok")  
				elif cmd == "TYPE":  
						self.message(200, "Type set to "+arg[0])  
				elif cmd == "SYST":  
						self.message(200, "UNIX")  
				elif cmd == "EPSV" or cmd == "PASV":  
						self.option_pasv = True  
						try:  
								self.data_fd = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  
								self.data_fd.bind((listen_ip, 0))  
								self.data_fd.listen(1)  
								ip, port = self.data_fd.getsockname()  
								if cmd == "EPSV":  
										self.message(229, "Entering Extended Passive Mode (|||" + str(port) + "|)")  
								else:  
										ipnum = socket.inet_aton(ip)  
										self.message(227, "Entering Passive Mode (%s,%u,%u)." %  
												(",".join(ip.split(".")), (port>>8&0xff), (port&0xff)))  
						except:  
								self.message(500, "failed to create data socket.")  
				elif cmd == "EPRT":  
						self.message(500, "implement EPRT later...")  
				elif cmd == "PORT":  
						self.option_pasv = False  
						self.data_fd = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  
						s = arg.split(",")  
						self.data_ip = ".".join(s[:4])  
						self.data_port = int(s[4])*256 + int(s[5])  
						self.message(200, "ok") 
				elif cmd == "MFMT":
						if arg !="":
								print (arg[0])
						self.message(213, "modify="+"; /deprecated.php")
				elif cmd == "PWD" or cmd == "XPWD":  
						if self.curr_dir == "": self.curr_dir = "/"  
						self.message(257, '"''' + self.curr_dir + '"')  
				elif cmd == "LIST" or cmd == "NLST" or cmd == "MLST":  
						if arg != "" and arg[0] == "-": arg = "" # omit parameters  
						remote, local, perm, vdir_list, limit_size, is_virtual = self.parse_path(arg)
						#print local           
						if not os.path.exists(local):  
								self.message(550, "failed.")  
								return  
						if not self.establish(): return  
						self.message(150, "ok")  
						for v in vdir_list:  
								f = v[0]  
								if self.option_utf8:
										if sys.version_info < (3, 0):  
												f = unicode(f, sys.getfilesystemencoding()).encode("utf8")  
								if cmd == "NLST":  
										info = f + "\r\n"  
								else:  
										info = "d%s%s------- %04u %8s %8s %8lu %s %s\r\n" % (  
												"r" if "read" in perm else "-",  
												"w" if "write" in perm else "-",  
												1, "0", "0", 0,  
												time.strftime("%b %d  %Y", time.localtime(time.time())),  
												f) 
								if sys.version_info < (3, 0): 
										self.data_fd.send(info)  
								else:
										self.data_fd.send(info.encode())
						for f in os.listdir(local):  
								if f[0] == ".": continue  
								path = local + "/" + f  
								if self.option_utf8:
										if sys.version_info < (3, 0):  
												f = unicode(f, sys.getfilesystemencoding()).encode("utf8")  
								if cmd == "NLST":  
										info = f + "\r\n"  
								else:  
										st = os.stat(path)  
										filesize = 0
										if os.path.isfile(path):
												filesize = st[stat.ST_SIZE]
										else:
												filesize = self.getdirsize(path)
										info = "%s%s%s------- %04u %8s %8s %8lu %s %s\r\n" % (  
												"-" if os.path.isfile(path) else "d",  
												"r" if "read" in perm else "-",  
												"w" if "write" in perm else "-",  
												1, "0", "0", filesize,  
												time.strftime("%b %d  %Y", time.localtime(st[stat.ST_MTIME])),  
												f)
								if sys.version_info < (3, 0): 
										self.data_fd.send(info)  
								else:
										self.data_fd.send(info.encode())
						self.message(226, "Limit size: " + str(limit_size))  
						self.data_fd.close()  
						self.data_fd = 0  
				elif cmd == "REST":  
						self.file_pos = int(arg)  
						self.message(250, "ok")  
				elif cmd == "FEAT":  
						features = "211-Features:\r\nSITES\r\nEPRT\r\nEPSV\r\nMDTM\r\nPASV\r\n"\
								"REST STREAM\r\nSIZE\r\nUTF8\r\n211 End\r\n" 
						if sys.version_info < (3, 0): 
								self.fd.send(features) 
						else:
								self.fd.send(features.encode()) 
				elif cmd == "OPTS":  
						arg = arg.upper()  
						if arg == "UTF8 ON":  
								self.option_utf8 = True  
								self.message(200, "ok")  
						elif arg == "UTF8 OFF":  
								self.option_utf8 = False  
								self.message(200, "ok")  
						else:  
								self.message(500, "unrecognized option")  
				elif cmd == "CDUP":  
						finish = False  
						arg = ".."
						cmd = "CWD"
				else:  
						finish = False  
				if finish: return  
				# Parse argument ( It's a path )  
				if arg == "":  
						self.message(500, "where's my argument?")  
						return  
				if (cmd == "MDTM"):
						arg2 = arg.split()
						remote, local, permission, vdir_list, limit_size, is_virtual = \
								self.parse_path(arg2[1])
				else:
						remote, local, permission, vdir_list, limit_size, is_virtual = \
								self.parse_path(arg)  
				# can not do anything to virtual directory  
				if is_virtual: permission = "none"  
				can_read, can_write, can_modify = "read" in permission, "write" in permission, "modify" in permission  
				newpath = local  
				try:  
						if cmd == "CWD":  
								#print remote
								print ("kyky",newpath);
								if(os.path.isdir(newpath)):  
										self.curr_dir = remote  
										self.full_path = newpath  
										self.message(250, '"''"' + remote + '"')  
								else:  
										self.message(550, newpath)  
						elif cmd == "MDTM":  
								timeArray = time.strptime(arg2[0], "%Y%m%d%H%M%S")
								timeStamp = int(time.mktime(timeArray))
								#print timeArray.tm_year
								
								if os.path.exists(newpath):  
										os.utime(newpath, (timeStamp,timeStamp))
										self.message(213, time.strftime("%Y%m%d%I%M%S", time.localtime(  
												os.path.getmtime(newpath))))  
								else:  
										self.message(550, "failed")  
						elif cmd == "SIZE":  
								if (os.path.exists(newpath)):
										self.message(231, os.path.getsize(newpath))
								else:
								 		self.message(231, 0)
						elif cmd == "XMKD" or cmd == "MKD":  
								if not can_modify:  
										self.message(550, "permission denied.")  
										return  
								os.mkdir(newpath)  
								self.message(257, "created successfully")  
						elif cmd == "RNFR":  
								if not can_modify:  
										self.message(550, "permission denied.")  
										return  
								self.temp_path = newpath  
								self.message(350, "rename from " + remote)  
						elif cmd == "RNTO":  
								os.rename(self.temp_path, newpath)  
								self.message(250, "RNTO to " + remote)  
						elif cmd == "XRMD" or cmd == "RMD":  
								if not can_modify:  
										self.message(550, "permission denied.")  
										return  
								os.rmdir(newpath)  
								self.message(250, "ok")  
						elif cmd == "DELE":  
								if not can_modify:  
										self.message(550, "permission denied.")  
										return  
								os.remove(newpath)  
								self.message(250, "ok")  
						elif cmd == "RETR":  
								if not os.path.isfile(newpath):  
										self.message(550, "failed")  
										return  
								if not can_read:  
										self.message(550, "permission denied.")  
										return  
								if not self.establish(): return  
								self.message(150, "ok") 
								if self.file_pos >0:
										with open(newpath, 'rb') as f:
												f.seek(self.file_pos)
												while True:
														data = f.read(1024)
														if data:
																
																self.data_fd.send(data)
														else:
																break
												f.close()
								else:                        
										f = open(newpath, "rb") 
																
										while self.running:  
												self.alive_time = time.time()  
												data = f.read(8192)  
												if len(data) == 0: break 
												self.data_fd.send(data)  
										f.close()  
								self.data_fd.close()  
								self.data_fd = 0  
								self.message(226, "ok")  
						elif cmd == "STOR" or cmd == "APPE":  
								if not can_write:  
										self.message(550, "permission denied.")  
										return  
								if os.path.exists(newpath) and not can_modify:  
										self.message(550, "permission denied.")  
										return  
								# Check space size remained!  
								
								used_size = 0  
								if limit_size > 0:  
										used_size = self.get_dir_size(os.path.dirname(newpath))  
								if not self.establish(): return  
								self.message(150, "Opening data channel for file upload to server of\"" + remote + " \"")
								if os.path.exists(newpath) and  self.file_pos > 0:
										print ("kkkkk")
										has_size = self.file_pos
										with open(newpath, 'ab') as f:
												f.seek(has_size)
												while True:
														data = self.data_fd.recv(1024)
														if len(data) == 0: break
														if limit_size > 0:
																 used_size = used_size + len(data) 
																 if used_size > limit_size: break
														f.write(data)
												f.close()       
								else:
										print ("qqqqq",self.file_pos)    
										f = open(newpath, "wb" )  
										while self.running:  
												self.alive_time = time.time()  
												data = self.data_fd.recv(8192)  
												if len(data) == 0: break  
												if limit_size > 0:  
														used_size = used_size + len(data)  
														if used_size > limit_size: break  
												f.write(data)  
										f.close()  
								self.data_fd.close()  
								self.data_fd = 0 
								self.file_pos = 0                
								if limit_size > 0 and used_size > limit_size:  
										self.message(550, "Exceeding user space limit: " + str(limit_size) + " bytes")  
								else:  
										self.message(226, "Successfully transferred \""+remote+"\"")  
						else:  
								self.message(500, cmd + " not implemented")  
				except BaseException as ex: 
						print (ex) 
						self.message(550, "failed.")  
			
		def establish(self):  
				if self.data_fd == 0:  
						self.message(500, "no data connection")  
						return False  
				if self.option_pasv:  
						fd = self.data_fd.accept()[0]  
						self.data_fd.close()  
						self.data_fd = fd  
				else:  
						try:  
								self.data_fd.connect((self.data_ip, self.data_port))  
						except:  
								self.message(500, "failed to establish data connection")  
								return False  
				return True  
		def getdirsize(self, dir):
				size = 0
				for root, dirs, files in os.walk(dir):
						try:
								size += sum([getsize(join(root, name)) for name in files])
						except:
								print ("error file")
				return size

		def read_virtual(self, path):  
				vdir_list = []  
				path = path + "/.xxftp/virtual"  
				if os.path.isfile(path):  
						for v in open(path, "r").readlines():  
								items = v.split()  
								items[1] = items[1].replace("$root", root_dir)  
								vdir_list.append(items)  
				return vdir_list  
	
		def get_dir_size(self, folder):  
				size = 0  
				folder = root_dir
				for path, dirs, files in os.walk(folder):  
						for f in files:  
								size += os.path.getsize(os.path.join(path, f))  
				print (folder)
				return size  
			
		def read_size(self, path):  
				size = 0  
				path = path + "/.xxftp/size"  
				if os.path.isfile(path):  
						size = int(open(path, "r").readline())  
				return size  
	
		def read_permission(self, path):  
				permission = "read,write,modify"  
				path = path + "/.xxftp/permission"  
				if os.path.isfile(path):  
						permission = open(path, "r").readline()  
				return permission  
			
		def parse_path(self, path):  
				path = path.replace("/\"", "")
				if path == "": path = "."  
				if path[0] != "/":  
						path = self.curr_dir + "/" + path  
				s = os.path.normpath(path).replace("\\", "/").split("/")  
				local = self.home_dir  
				#print local
				# reset directory permission  
				vdir_list = self.read_virtual(local)  
				limit_size = self.u_limit_size  
				permission = self.u_permission  
				remote = ""  
				is_virtual = False  
				for name in s:  
						name = name.lstrip(".")  
						if name == "": continue  
						remote = remote + "/" + name  
						is_virtual = False  
						for v in vdir_list:  
								if v[0] == name:  
										permission = v[2]  
										local = v[1]  
										limit_size = self.read_size(local)  
										is_virtual = True  
						if not is_virtual: local = local + "/" + name
						#local = local.replace("/\"", "/")           
						vdir_list = self.read_virtual(local) 
								
				return (remote, local, permission, vdir_list, limit_size, is_virtual)  
	
		def run(self):  
				''''' Connection Process '''  
				#try:  
				if len(conn_list) > max_connections:  
						self.message(500, "too many connections!")  
						self.fd.close()  
						self.running = False  
						return  
				# Welcome Message  
				if os.path.exists(root_dir + "/xxftp.welcome"):  
						self.message(220, open(root_dir + "/xxftp.welcome").read())  
				else:  
						self.message(220, "xxftp(Python) www.xiaoxia.org")  
				# Command Loop  
				line = ""  
				while self.running: 
						data = 0 
						if sys.version_info < (3, 0):
								data = self.fd.recv(4096)
						else:
								data = self.fd.recv(4096).decode()  
						if len(data) == 0: break  
						line += data  
						if line[-2:] != "\r\n": continue  
						line = line[:-2]  
						space = line.find(" ")  
						if space == -1:  
								self.process(line, "")  
						else:  
								self.process(line[:space], line[space+1:])  
						line = ""  
				#except:  
						#print ("error", sys.exc_info())  
				self.running = False  
				self.fd.close()  
				
				print ("connection end", self.fd, "user", self.username) 
				del self.fd        
	
		def message(self, code, s):  
				''''' Send Ftp Message '''  
				s = str(s).replace("\r", "")  
				ss = s.split("\n")  
				#r = ""
				if len(ss) > 1:  
						r = (str(code) + "-") + ("\r\n" + str(code) + "-").join(ss[:-1])  
						r += "\r\n" + str(code) + " " + ss[-1] + "\r\n"  
				else:  
						r = str(code) + " " + ss[0] + "\r\n"  
				if self.option_utf8:  
						if sys.version_info < (3, 0):
								r = unicode(r, sys.getfilesystemencoding()).encode("utf8")  
				if sys.version_info < (3, 0):
						self.fd.send(r)
				else:
						self.fd.send(r.encode())  
	
def server_listen():  
		global conn_list  
		listen_fd = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  
		listen_fd.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)  
		listen_fd.bind((listen_ip, listen_port))  
		listen_fd.listen(1024)  
		conn_lock = threading.Lock()  
		print ("ftpd is listening on ", listen_ip + ":" + str(listen_port))  
	
		while True:  
				conn_fd, remote_addr = listen_fd.accept()  
				print ("connection from ", remote_addr, "conn_list", len(conn_list))  
				conn = FtpConnection(conn_fd)  
				conn.start()  
				
				conn_lock.acquire()  
				conn_list.append(conn)  
				# check timeout  
				try:  
						curr_time = time.time()  
						for conn in conn_list:  
								if int(curr_time - conn.alive_time) > conn_timeout:  
										if conn.running == True:  
												conn.fd.shutdown(socket.SHUT_RDWR)  
										conn.running = False
										del conn 
								if conn.running == False:
										del conn                
						conn_list = [conn for conn in conn_list if conn.running]  
				except:  
						print (sys.exc_info())  
				conn_lock.release()  
	
	
def main():  
		server_listen()  
			
if __name__ == "__main__":  
		main()  