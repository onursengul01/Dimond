import os.path
import os
from termcolor import colored
import pyfiglet
from pyfiglet import figlet_format
class Dimond:
	def __init__(self):
		pass

	def Menu(self):
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
{e}--Exit


				""")

			options = input("Choose: ")

			if options == "1":
				return s.Information_Gathering()
			if options == "":
				os.system("clear")
				return s.Menu()

	def Information_Gathering(self):
		os.system("clear")
		while True:
			print("""

{1}--Nmap - Network Mapper
{2}--Setoolkit
{3}-- Host To Ip
{4}--WPScan
{5}--CMSmap
{6}--XXStrike
{7}--Doork
{8}--Crips

{b}--Go back to main menu



				""")

			options2 = input("Chooose: ")
			if options2 == "1":
				return s.Nmap()
			
			if options2 == "2":
				return s.Setoolkit()
			if options2 == "":
				return s.Information_Gathering()
				
	#Nmap 			
	def Nmap(self):
		os.system("clear")
		ascii_banner = pyfiglet.figlet_format("NMAP")
		print(ascii_banner)
		global Target_Ip
		Target_Ip = input("Enter Target IP/Subnet/Range/Host: ")
		return s.NmapScan()
	#Nmap Scan options
	def NmapScan(self):
		os.system("clear")
		scan = True
		while scan:
			print(f"Nmap scan for: {Target_Ip}")
			print("""

	{1}--Simple Scan [-sV]
	{2}--Port Scan [-Pn]
	{3}--Operating System Detection [-An]

	{b}--Return to information gathering menu




				""")

			options3 = input("Coose:")
			if options3 == "1":
				os.system("clear")
				os.system(f"nmap -sV {Target_Ip}")

			if options3 == "2":
				os.system(f"nmap -Pn {Target_Ip}")

			if options3 == "3":
				os.system(f"nmap -An {Target_Ip}")


			if options3 == "b":
				return s.Information_Gathering()


			if options3 == "":
				return s.NmapScan()

	def Setoolkit(self):
				

s = Dimond()
s.Menu()
