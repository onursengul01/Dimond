import os.path
import os
import json
import sys
from termcolor import colored
import pyfiglet
from pyfiglet import figlet_format
import socket
from time import gmtime, strftime, sleep
import time

#! /usr/bin/python3




if os.getuid() != 0:
	print("Sorry, this script requires sudo privledges")
	sys.exit()


class Dimond:
	def __init__(self):
		pass

	



	def YorN(self):
		try:
			import colorama
			from colorama import Fore, Style
		except:
			print("colorama not found")	

		os.system("clear")
		print('''\x1b[96mI shall not use Dimond to:
(i) upload or otherwise transmit, display or distribute any
content that infringes any trademark, trade secret, copyright
or other proprietary or intellectual property rights of any
person; (ii) upload or otherwise transmit any material that contains
software viruses or any other computer code, files or programs
designed to interrupt, destroy or limit the functionality of any
computer software or hardware or telecommunications equipment. 

Thanks for reading Onur.


''')
	
		while True:
			terms = input("You must agree to terms and conditions first (Y/n) ")
			if terms == "y":
				return s.Menu()
			if terms == "n":
				return s.YorN()
			if terms == "Y":
				return s.Menu()	

			else:
				return s.YorN()		






	def Menu(self):
		os.system("clear")
		while True:
			print((colored(figlet_format("Dimond"), color="cyan")))
			print("""

{1}--Information Gathering
{2}--Password Attacks
{3}--Wireless Testing 
{4}--Exploitation Tools
{5}--Sniffing & Spoofing
{6}--Web Hacking
{7}--Private Web Hacking
{8}--Post Exploitation
\n{e}--Exit\n


				""")

			options = input("dimond ~# ")

			if options == "1":
				return s.Information_Gathering()
			if options == "":
				os.system("clear")
				return s.Menu()
			
			if options == "2":
				return s.PSW_Attacks()	


			if options == "3":
				return s.Wireless_Testing()
				

			if options == "4":
				return s.Exploitation_Tools_Menu()	


			if options == "e":
				print()
				print("Ok bye...")
				exit()
				
			else:
				return s.Menu()	

	def Information_Gathering(self):
		os.system("clear")
		while True:
			print((colored(figlet_format("INFO"), color="cyan")))
			print("""

{1}--Nmap - Network Mapper
{2}--Setoolkit
{3}--Host To Ip
{4}--WPScan
{5}--Nikto
{6}--XXStrike
{7}--Doork
{8}--Crips

{b}--Go back to main menu



				""")

			options2 = input("dimond ~# ")
			if options2 == "1":
				return s.Nmap()
			
			if options2 == "2":
				return s.Setoolkit()
			if options2 == "":
				return s.Information_Gathering()
				

			if options2 == "3":
				return s.HostToIp()


			if options2 == "4":
				return s.WPScan_Check()

			if options2 == "5":
				return s.NiktoIP()			

			if options2 == "6":
				os.system("clear")
				return s.XXStrike_Check()

			if options2 == "7":
				return s.Doork_Check()	

			if options2 == "8":
				return s.Crips_Check()	



			if options2 == "b":
				return s.Menu()



			else:
				return s.Information_Gathering()	

	#Nmap 			
	def Nmap(self):
		os.system("clear")
		print((colored(figlet_format("NMAP"), color="cyan")))
		global target
		target = input("Enter Target IP/Subnet/Range/Host: ")
		return s.NmapScan()
	#Nmap Scan options
	def NmapScan(self):
		os.system("clear")
		scan = True

		while scan:
			print((colored(figlet_format("NMAP"), color="cyan")))
			print(f"Nmap scan for: {target}")
			print("""

	{1}--Simple Scan [-sV]
	{2}--Port Scan [-Pn]
	{3}--Operating System Detection [-An]

	{b}--Return to information gathering menu




				""")

			options3 = input("nmap ~# ")
			

			if options3 == "1":
				os.system("clear")
				os.system(f"sudo nmap -sV {target}")

			if options3 == "2":
				os.system(f"sudo nmap -Pn {target}")
			if options3 == "3":
				os.system(f"sudo nmap -An {target}")


			if options3 == "b":
				return s.Information_Gathering()


			if options3 == "":
				return s.NmapScan()

			else:
				return s.WPScanOptions()	


	def Setoolkit(self):
		path = '/usr/bin/setoolkit'
		if os.path.exists(path):
   			os.system("sudo setoolkit")
   			return s.Information_Gathering()

		else:
			while True:
				gitRepo = "https://github.com/trustedsec/social-engineer-toolkit.git"
				os.system("sudo apt-get --force-yes -y install git apache3 python3-requests libapache3-mod-php python3-pymssql build-essential python3-pexpect python-pefile python3-crypto python3-openssl")
				os.system(f"git clone {gitRepo} {path}" )
				os.system(f"pip3 install -r {path}/requirements.txt")
				os.system(f"sudo python3 {path}/setup.py")
				os.system("clear")
				os.system("sudo setoolkit")
				return s.Menu()




	def HostToIp(self):
		os.system("clear")
		host = input("Enter a Host: ")
		ip = socket.gethostbyname(host)
		print("has the IP of " + host, ip)
		while True:
			enter = input("")
			if enter == "":
				os.system("clear")
				return s.Information_Gathering()
								
	def WPScan_Check(self):
		gitRepo2 = "https://github.com/wpscanteam/wpscan.git"
		path4 = "/usr/bin/wpscan"

		if os.path.exists(path4):
			return s.WPScan()

		else:
			os.system(f"git clone {gitRepo2} {path4}")
			os.system("sudo apt install build-essential libcurl4-openssl-dev libxml2 libxml2-dev libxslt1-dev ruby-dev  libgmp-dev zlib1g-dev")
			os.system("sudo gem install wpscan")
			return s.WPScan()

	def WPScan(self):
		try:
			import validators
			import ipaddress
			from validator_collection import validators, checkers
			from IPy import IP
		except ModuleNotFoundError:
			print(f"import validators not found")
			os.system("import ipaddress not found")
			print("from validator_collection import validators, checkers couldn't import")
			os.system("sudo pip3 install validator-collection")
			os.system("sudo pip3 install IPy")
			os.system("sudo pip3 install validators")
			os.system("sudo pip3 install ipaddress")
			
			return s.WPScan()
		os.system("clear")
		global target2
		print((colored(figlet_format("WPSCAN"), color="cyan")))
		try:
			target2 = input("Enter a target: ")
			
			return s.WPScanOptions()
		except KeyboardInterrupt:
			print(" Ok bye...")
			sys.exit()



			
		
			


	def WPScanOptions(self):
		os.system("clear")
		while True:
			print((colored(figlet_format("WPSCAN"), color="cyan")))
			print(f"   WPScan for: {target2}\n")
			print("   {1}--Username Enumeration [--enumerate u]")
			print("   {2}--Plugin Enumeration [--enumerate p]")
			print("   {3}--Scan Vulnerable timthumb files tt]")
			print("   {4}--Update wpscan")
			
			print("   {b}-Return to information gathering menu \n")

			try:
				options4 = input("wpscan ~# ")
			except KeyboardInterrupt:
				print(" Ok bye...")
				sys.exit()	
			if options4 == "1":
				try:
					os.system(f"wpscan --ignore-main-redirect --url {target2} --enumerate u ")
				except:
					while True:
						enter2 = input("Press enter to go back to information gathering menu")
						if enter2 == "":
							return s.Information_Gathering()
			if options4 == "":
				return s.WPScanOptions()

			if options4 == "2":
				os.system("clear")
				try:
					os.system("clear")
					os.system(f"wpscan --ignore-main-redirect --url {target2} --enumerate p")
					while True:
						enter6 = input("Scan is finished please press enter to go back")
						if enter6 == "":
							return s.WPScanOptions()
				except:
					while True:
						enter4 = input("Press entrer to go back to wpsscan menu")
						if enter4 == "":
							return s.WPScanOptions()
					
			if options4 == "3":
				 os.system(f"wpscan --ignore-main-redirect --url {target2} --enumerate tt")	 


			if options4 == "4":
				try:
					os.system("clear")
					os.system("sudo wpscan --update")
				except:
					while True:
						enter7 = input("Couldn't update wpscan.\nPlease press enter to go back\n")
						if enter7 == "":
							return s.WPScanOptions()	

			if options4 == "":
				return s.WPScanOptions()


				
				
			if options4 == "b":
				return s.Information_Gathering()
			
			else:
				return s.WPScanOptions()

		

	def Nikto_Check(self):
		path14 = '/usr/bin/nikto'
		if os.path.exists(path14):
			return NiktoIP()

		else:
			os.system("clear")
			os.system("sudo apt-get install nikto -y")


	def NiktoIP(self):
		global ip
		os.system("clear")
		while True:
			print((colored(figlet_format("NIKTO"), color="cyan")))
			ip = input("Enter the url or ip address of the website: ")
			return s.Nikto_run()
	def Nikto_run(self):
		os.system("clear")
		try:
			value = os.system(f"sudo nikto -h {ip} -p 80")
			print()
			if value == True:
				while True:
					enter9 = input("[*] Scan is succesfully completed.\nPress enter to return to Information Gathering menu\n")
					if enter9 == "":
						return s.Information_Gathering()

			if value == False:
				while True:
					print("Scan Failed \nPress enter to return to Information Gathering menu\n")
					enter8 = input("")
					if enter8 == "":
						return s.Information_Gathering()	


							
							
		except OSError as e:
			pass
			


	def XXStrike_Check(self):

		global path6
		path6 = '/usr/bin/XSStrike'
		gitRepo4 = 'https://github.com/UltimateHackers/XSStrike.git'
		if os.path.exists(path6):
			return s.XSStrike_target()
		else:
			os.system("clear")
			os.system(f"sudo git clone {gitRepo4} {path6} ")
			os.system("sudo pip3 install -r /usr/bin/XSStrike/requirements.txt")
			return s.XSStrike_target()
	
	def XSStrike_target(self):
		try:
			import colorama
			from colorama import Fore, Style
		except:
			print("colorama not found")
			os.system("pip3 install colorama")


		global target6
		print((colored(figlet_format("XSSTRKE"), color="cyan")))
		target6 = input("Enter the target: ")
		os.system("clear")
		print(f"Target: {target6}")
		try:
			os.system(f"python3 /usr/bin/XSStrike/xsstrike.py -u {target6}/listproducts.php?=1")
			green = "\033[32m"
			enter10 = input("\033[32m[*] Scan has ben completed.\nPress enter to return to Information Gathering\n")
			if enter10 == "":
				os.system("clear")

				return s.Information_Gathering()
					
			
							
						
		except:
			while True:
				enter11 = input("\033[31mScan failed!\nPlease press enter to go back to try again\n")
				if enter11 == "":
					return s.Information_Gathering()
											
			
		



	def Doork_Check(self):
		path7 = "/usr/bin/doork"
		gitRepo5 = "https://github.com/AeonDave/doork.git"
		if os.path.exists(path7):
			return s.doork_Target()
			
		else:
			os.system("clear")
			os.system(f"git clone {gitRepo5} {path7}")
			os.system("pip install beautifulsoup4 requests Django==1.11")
			os.system("pip install requests")

			

			return s.Doork_Check()
			
	
	def doork_Target(self):
		os.system("clear")
		global target5
		print((colored(figlet_format("DOORK"), color="cyan")))
		target5 = input("Enter a target: ")
		return s.run2()

				

	def run2(self):
		os.system("clear")
		try:
			os.system(f"python2.7 /usr/bin/doork/doork.py -t {target5}")

		except:
			print("Scan Failed")	
		



	def Crips_Check(self):
		path8 = "/usr/bin/Crips"
		gitRepo6 = "https://github.com/Manisso/Crips.git"
		if os.path.exists(path8):
			try:
				os.system("python2.7 /usr/bin/Crips/crips.py")
				return s.Information_Gathering()
			except:
				return s.Information_Gathering()	
		else:
			os.system(f"git clone {gitRepo6} {path8}")
			os.system("sudo bash /usr/bin/Crips/install.sh")
			
			

	def PSW_Attacks(self):
		os.system("clear")
		while True:
			print((colored(figlet_format("PASSWD"), color="cyan")))

			print("""

{1}--Cupp - Common User Passwords Profiler
{2}--BruteX - Automatically bruteforces all services running on a target

{b}--Go Back to Main Menu


			""")
			options5 = input("passwd ~# ")
			if options5 == "1":
				return s.Cupp_Check()

			if options5 == "2":
				return s.BruteX()

			if options5 == "":
				return s.PSW_Attacks()

			if options5 == "b":
				return s.Menu()	

			else:
				return s.PSW_Attacks()	

	def Cupp_Check(self):
		path9 = '/usr/bin/cupp/'
		gitRepo7 = "https://github.com/Mebus/cupp.git"

		if os.path.exists(path9):
			os.system("clear")
			os.system("python3 /usr/bin/cupp/cupp.py -i")
			return s.PSW_Attacks()			

		else:
			os.system("clear")
			os.system(f"git clone {gitRepo7} {path9}")
			return s.Cupp_Check()				


			
	def BruteX(self):
		path10 = "/usr/bin/BruteX/"
		gitRepo8 = "https://github.com/1N3/BruteX.git"
		if os.path.exists(path10):
			os.system("clear")
			target = input("Enter Target IP: ")
			os.system(f"sudo bash /usr/bin/BruteX/brutex {target}")
			while True:
				print()
				option3 = input("Press enter to return to menu")
				if option3 == "":
					return s.Menu()
		else:
			os.system("clear")
			os.system(f"git clone {gitRepo8} {path10}")
			os.system("clear")
			os.system(f"sudo chmod +x {path10}install.sh && sudo bash {path10}install.sh")			
			return s.BruteX()


	def Wireless_Testing(self):
		os.system("clear")
		while True:
			print((colored(figlet_format("WIRELESS"), color="cyan")))
			print("""

{1}--Reaver
{2}--Pixiewps
{3}--Bluetooth Honeypot GUI Framework

{b}-Go to the main menu





				""")

			options6 = input("wireless ~# ")
			
			if options6 == "1":
				return s.Reaver_Check()

			

			if options6 == "":
				return s.Wireless_Testing()

			if options6 == 	"3":
				return s.Bluepot_Check()

			if options6 == "b":
				return s.Menu()

			else:
				return s.Wireless_Testing()			


	def Reaver_Check(self):
		path12 = '/usr/bin/reaver/'
		if os.path.exists(path12):
			return s.Reaver_Interface()

		else:
			os.system("sudo apt-get install reaver -y")	
			return s.Reaver_Interface()	

	

	def Reaver_Interface(self):
		global interface		
		os.system("clear")
		interface = input("Enter your wifi card {ex.wlan0}: ")
		return s.Reaver()


	def Reaver(self):
		os.system("clear")
		while True:
			print((colored(figlet_format("REAVER"), color="cyan")))
			print("{1}--Enable monitor mode for " + interface)
			print("{2}--Run Reaver attack\n")

			print("{b}-Go back to main menu\n")


				
			reaver = input("reaver ~# ")
			if reaver == "1":
				os.system("clear")
				try:
					os.system(f"airmong-ng start {wlan0}")
				except:
					print("Couldn't start monitor mode")
					while True:
						options3 = input("Press Enter to go back to reaver menu")
						if options3 == "":
							return s.Reaver()	

			if reaver == "2":
				return s.Run_Reaver_Attack()			


			if reaver == "":
				return s.Reaver()

			
			if reaver == "b":
					return s.Menu()

			else:
				return s.Reaver()
						

	def Run_Reaver_Attack(self):
		import re
		os.system("clear")
		
		bssid = input("Enter the bssid ex.{The mac of address of the access point} ")
		valid = re.match('(?=[a-f0-9]{2}:){5}[a-f0-9]{2}', bssid, re.I)
		if valid:
			mac_as_int = int(bssid.replace(':', ''), 16)
			for address in range(mac_as_int + 1, mac_as_int + 4):
				output = '{:012X}'.format(address)
				print('{}:{}:{}:{}:{}:{}'.format(output[0:2], output[2:4], output[4:6], output[6:8], output[8:10], output[10:12]))
				global option6
				try:
					value = os.system(f"reaver -i {interface} -b {bssid} -vv")
					return s.Reaver()
				except:
					print()
					print("Proccess failed please try again")
					while True:
						option6 = input("Press enter to try again")
						if option6 == "":
							return s.Reaver() 
						

		else:
			print('Invalid MAC address')
			while True:
				print()
				option2 = input("Press enter to do the proccess again")
				if option2 == "":
					return s.Reaver()
	
				




	def Bluepot_Check(self):
		path13 = '/usr/bin/bluepot-0.1.tar.gz/'
		gitRepo14 = 'wget https://github.com/andrewmichaelsmith/bluepot/raw/master/bin/bluepot-0.1.tar.gz'
		if os.path.exists(path13):
			pass

		else:
			os.system("clear")
			os.system("apt-get install libbluetooth-dev")
			os.system(f"wget {gitRepo14} /usr/bin/")
			os.system(f"tar xfz /usr/bin/bluepot-0.1.tar.gz/")
			os.system(f"sudo java -jar /usr/bin/bluepot-0.1.tar.gz/")






	def Exploitation_Tools_Menu(self):
		while True:
			print((colored(figlet_format("EXPL"), color="cyan")))
			print("""

{1}--ATSCAN
{2}--sqlmap
{3}--Shellnoob
{4}--commix
{5}--FTP Auto Bypass
{6}--JBoss-Autopwn
{7}--Blind SQL Automatic Injection And Exploit
{8}--Bruteforce the Android Passcode ggiven the hash and salt
{9}--Joomla SQL injection Scanner

{b}-Go back to main menu



				""")
			options7 = input("exploitation  ~# ")





s = Dimond()

if __name__ == "__main__":
	try:
		Dimond()
		s.YorN()
		s.Menu()

	except KeyboardInterrupt:
		print("\nok bye...\nok")
		time.sleep(1)
		sys.exit()
	


s.Menu()
