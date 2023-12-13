import socket
import sys
import time
import SecureEncryption

s = socket.socket()
Host = ' 192.168.1.179'
port = 12341

s.connect(('127.0.0.1', port))

se = SecureEncryption.SecureEncryption()
ty = ''

while 1:

    print("1.Do you want to send files 2.Receive Files")
    ty = input()

    if ty == '1':
        print("Enter mode of encryption 1.ChaCha20Poly1305 2.AESGCM 3.AESOCB3 4.AESSIV 5.AESCCM")
        m = input()
        se.select_mode(m)
        k = se.create_key()
        se.convert_key(k)
        f = open("test_file_1.txt", 'rb')
        ct = se.encrypt_msg(f.read())
        f2 = open('r2.txt', 'wb')
        f2.write(k)
        f2.write(ct)
        f2.close()
        with open("r2.txt", 'rb') as file:
            s.sendfile(file)
        f.close()

    if ty == '2':
        with open('r.txt', 'wb') as file:
            while True:
                data = s.recv(1024)
                if not data:
                    break
                file.write(data)
        f = open('r.txt', 'rb')
        k = f.read(32)
        se.mode = '1'
        se.convert_key(k)
        ct = f.read()
        f = open("received.txt", 'wb')
        msg = se.decrypt_msg(se.pr_key, ct)
        f.write(msg)
        f.close()