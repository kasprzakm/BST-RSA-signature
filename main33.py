import tkinter as tk
from tkinter import *
from tkinter import ttk
from tkinter import filedialog as fd
from Crypto import Random
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA

import Crypto.Cipher.PKCS1_OAEP
import ast
from hashlib import sha512


# main window
class MainWindow(tk.Tk):
    def __init__(self):
        super().__init__()

        # configure the root window
        self.eval('tk::PlaceWindow . center')
        self.geometry('500x250')
        self.resizable(False, False)
        self.configure(background='#FFFFFF')
        self.title('Digital Signature Wizard')
        self.iconbitmap('icon.ico')

        # labels
        label1 = Label(text='Import file to sign or check', bg='#FFFFFF')
        label1.place(x=40, y=20)

        label2 = Label(text='Input your message to sign', bg='#FFFFFF')
        label2.place(x=40, y=60)

        # input box
        ws = Entry(self)
        ws.place(x=200, y=60)

        # import file block
        button1 = tk.Button(text='Choose file', bg='#FFFFFF', command=lambda: self.import_file())
        button1.place(x=200, y=20)
        label3 = Label(text='No file chosen', bg='#FFFFFF')
        label3.place(x=275, y=20)

        # action buttons block
        Button(self, text='Generate keys', width=12, command=lambda: self.generate_keys()).place(x=100, y=150)
        Button(self, text='Sign file', width=12, command=lambda: self.sign_file).place(x=210, y=150)
        Button(self, text='Check signature', width=12, command=lambda: self.check_signature).place(x=320, y=150)

    def import_file(self):
        filetypes = (
            ('Pliki tekstowe', '*.txt'),
            ('Wszystkie pliki', '*.*'))

        self.filename = fd.askopenfilename(
            title='Open a file',
            initialdir='/',
            filetypes=filetypes)

        self.data = open(self.filename, 'r').readlines()

        disp_name = self.filename.split('/')[len(self.filename.split('/')) - 1]
        if self.filename != "":
            print('[File selected]', disp_name)
            self.label3['text'] = disp_name


    def generate_keys(self):
        # generate public and private key
        random_generator = Random.new().read
        key_pair = RSA.generate(2048, random_generator)

        # print(key_pair)
        # print(key_pair.publickey())
        #
        # print(key_pair.exportKey())
        # print(key_pair.publickey().exportKey())

        private_key = key_pair.exportKey('PEM')  # private key for hashing
        public_key = key_pair.publickey().exportKey('PEM')  # public key for exchange

        # print(f"Public key:  (n={hex(keyPair.n)}, e={hex(keyPair.e)})")
        # print(f"Private key: (n={hex(keyPair.n)}, d={hex(keyPair.d)})")

        try:
            with open('master_private.pem', 'wb') as keyfile:
                keyfile.write(private_key)
                keyfile.close()
            print("[Successfully created your RSA PRIVATE key]")
        except Exception as e:
            print("[Error creating your key]", e)

        try:
            with open("master_public.pem", "wb") as keyfile:
                keyfile.write(public_key)
                keyfile.close()
            print("[Successfully created your RSA PUBLIC key]")
        except Exception as e:
            print("[Error creating your key]", e)

    def sign_file(self):
        # RSA sign the message
        msg = b'A message for signing'
        private_key = RSA.import_key(open('master_private.pem').read())
        hash = SHA256.new(msg)
        signature = pkcs1_15.new(private_key).sign(hash)
        # print("Signature:", signature)

        try:
            with open("signed_file", "wb") as signed_file:
                signed_file.write(signature)
                signed_file.close()
            print("[Successfully signed your message!]")
        except Exception as e:
            print("[Error signing your message]", e)

    def check_signature(signature, public_key):
        print(_key_pair)
        # # RSA verify signature
        # msg = b'A message for signing'
        # hash = int.from_bytes(sha512(msg).digest(), byteorder='big')
        # hashFromSignature = pow(signature, public_key.e, public_key.n)
        # print("Signature valid:", hash == hashFromSignature)
        # print("x")

    def user_signature(self):
        user_input = ws.get()
        return user_input


if __name__ == "__main__":
    win1 = MainWindow()
    win1.mainloop()
