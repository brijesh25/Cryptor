#!/usr/bin/env python3

from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import base64
import codecs
import threading
maxBytes = 159

class crypter:
    def cleanUp(self):
        self.data = []
        self.datablocks = []
        self.decrypteddatablocks = {}
        self.base64blocks = {}
        self.cb64blocks = {}
        self.cipherdata = []
        self.encrypteddatablocks = {}
        self.totalBytes = int(0)
        self.datablocksPerThread = int(0)
        self.offsets = []
        self.processes = []
        self.threadsDone = 0
        self.shiftedlines = {}
        self.odata = {}

    def __init__(self, keypath=None, threads=4):
        if keypath is None:
            print("/\/\/\/Generating Keys/\/\/\/")
            self.key = RSA.generate(2048)
            self.cipher = PKCS1_OAEP.new(self.key)
            self.threads = int(threads)
            self.hexifyr = codecs.getencoder('hex')
            self.data = []
            self.odata = {}
            self.datablocks = []
            self.decrypteddatablocks = {}
            self.base64blocks = {}
            self.cb64blocks = {}
            self.cipherdata = []
            self.encrypteddatablocks = {}
            self.totalBytes = int(0)
            self.datablocksPerThread = int(0)
            self.offsets = []
            self.processes = []
            self.threadsDone = 0
            self.shiftedlines = {}
        else:
            try:
                keyfile = open(keypath, 'rb')
                password = str(input("Enter the password for the key: "))
                print("/\/\/\/Loading Keys/\/\/\/")
                self.key = RSA.import_key(keyfile.read(), password)
                keyfile.close()
            except Exception as e:
                print("Error! Failed to import key. Please check your password/path!" + str(e))
                exit(1)
            self.threads = int(threads)
            self.cipher = PKCS1_OAEP.new(self.key)
            self.odata = {}
            self.decrypteddatablocks = {}
            self.base64blocks = {}
            self.cb64blocks = {}
            self.dehexifyr = codecs.getdecoder('hex')
            self.cipherdata = []
            self.encrypteddatablocks = {}
            self.numberOfBlocks = int(0)
            self.datablocksPerThread = int(0)
            self.offsets = []
            self.processes = []
            self.threadsDone = 0
            self.datablocks = []
            self.shiftedlines = {}

    def initBlocks(self):  # Initialising Different Data Blocks
        print("----------Initialising Data Blocks for MultiThreaded Operations----------\n")
        for i in range(0, int(self.threads)):
            self.odata.update({str(i+1): []})
            self.decrypteddatablocks.update({str(i + 1): []})
            self.base64blocks.update({str(i + 1): []})
            self.cb64blocks.update({str(i + 1): []})
            self.encrypteddatablocks.update({str(i + 1): []})
            if ((i + 1) * int(self.datablocksPerThread)) > self.numberOfBlocks:
                self.offsets.append((i * (self.datablocksPerThread), self.numberOfBlocks))
            else:
                self.offsets.append((i * (self.datablocksPerThread), (i + 1) * self.datablocksPerThread))

    def getData(self, filepath, mode):  # Reading data from file
        if mode == 'encrypt':
            print("----------Reading Data from Original File----------\n")
            inputfile = open(filepath, 'rb')
            while(inputfile):
                inputline = inputfile.read(maxBytes)
                if inputline != b'': self.data.append(inputline)
                else: break
            inputfile.close()
            self.numberOfBlocks = len(self.data)
            #print(self.numberOfBlocks)
            self.datablocksPerThread = int(self.numberOfBlocks) // int(self.threads) + 1
            #print(self.datablocksPerThread)
            self.initBlocks()
            #print(self.offsets)
            print("----------DONE----------\n")
        elif mode == 'decrypt':
            print("----------Reading Data from Encrypted File----------\n")
            inputfile = open(filepath, 'rb')
            self.cipherdata = []
            while (inputfile):
                inputline = inputfile.readline().strip()
                if inputline != b'':
                    self.cipherdata.append(self.dehexifyr(inputline)[0])
                    self.numberOfBlocks += 1
                else:
                    break
            inputfile.close()
            self.datablocksPerThread = int(self.numberOfBlocks) // int(self.threads) + 1
            self.initBlocks()
            print("----------DONE----------\n")

    def base64it(self, data, mode, part):
        if mode == 'encrypt':
            x, y = self.offsets[part - 1]
            for i in range(x, y):
                self.base64blocks[str(part)].append(base64.b64encode(data[i]))
        elif mode == 'decrypt':
            for i in range(0, len(data[str(part)])):
                self.odata[str(part)].append(base64.b64decode(data[str(part)][i]))

    def cbase64it(self, data, mode, part, shift):
        if mode == 'encrypt':
            for i in range(0, len(data[str(part)])):
                self.shiftedlines[str(part)] = b''
                for char in data[str(part)][i]:
                    self.shiftedlines[str(part)] += chr(char + shift).encode()
                self.cb64blocks[str(part)].append(self.shiftedlines[str(part)])
            self.shiftedlines[str(part)] = b''
        elif mode == 'decrypt':
            for i in range(0, len(data[str(part)])):
                self.shiftedlines[str(part)] = b''
                for char in data[str(part)][i]:
                    self.shiftedlines[str(part)] += chr(char - shift).encode()
                self.base64blocks[str(part)].append(self.shiftedlines[str(part)])
            self.shiftedlines[str(part)] = b''

    def rsaProcess(self, data, mode, part):
        if mode == 'encrypt':
            for i in range(0, len(data[str(part)])):
                self.encrypteddatablocks[str(part)].append(self.cipher.encrypt(data[str(part)][i]))
        elif mode == 'decrypt':
            x, y = self.offsets[part - 1]
            for i in range(x, y):
                self.decrypteddatablocks[str(part)].append(self.cipher.decrypt(data[i]))

    def encrypt(self):
        noOfFiles = int(input("One or Many? (1 or No. of Files):"))
        if (noOfFiles > 0):
            x = 0
            efile = ""
            filepath = ""
            self.cipherdata = []
            magicNum = int(input("Enter the magic number you wish to encrypt files with ;) : "))
            mNum = magicNum % 26
            while (x < noOfFiles):
                self.cipherdata = []
                filepath = str(input("Enter the full path to the file to encrypt: "))
                filename = filepath[filepath.rindex("/"):len(filepath)]
                efile = "./Encrypted_" + filename.lstrip("/")
                self.getData(filepath, 'encrypt')
                #print("Number of lines: {}".format(self.numberOfBlocks))
                print("----------Applying Base64----------\n")
                for i in range(0, self.threads):
                    # print("DEBUG: Running Base64 Thread {}".format(str(i+1)))
                    self.processes.append(threading.Thread(None, self.base64it, None, (self.data, 'encrypt', i + 1)))
                    self.processes[i].start()
                for i in range(0, self.threads):
                    self.processes[i].join()
                print("----------Base64 Done----------\n")
                self.processes = []
                self.threadsDone = 0
                for i in range(0, self.threads):
                    print(len(self.base64blocks[str(i+1)]))
                # print("DEBUG: Base64 Done")
                print("----------Applying CBase64----------\n")
                for i in range(0, self.threads):
                    # print("DEBUG: Running CBase64 Thread {}".format(str(i+1)))
                    self.processes.append(
                        threading.Thread(None, self.cbase64it, None, (self.base64blocks, 'encrypt', i + 1, mNum)))
                    self.processes[i].start()
                for i in range(0, self.threads):
                    self.processes[i].join()
                print("----------CBase64 Done----------\n")
                self.processes = []
                self.threadsDone = 0
                # print("DEBUG: CBase64 Done")
                print("----------Applying RSA----------\n")
                for i in range(0, self.threads):
                    # print("DEBUG: Running RSA Thread {}".format(str(i+1)))
                    self.processes.append(
                        threading.Thread(None, self.rsaProcess, None, (self.cb64blocks, 'encrypt', i + 1)))
                    self.processes[i].start()
                for i in range(0, self.threads):
                    self.processes[i].join()
                print("----------RSA Done----------\n")
                self.processes = []
                self.threadsDone = 0
                # print("DEBUG: RSA Done")
                for i in range(0, self.threads):
                    for j in range(0, len(self.encrypteddatablocks[str(i + 1)])):
                        self.cipherdata.append(self.encrypteddatablocks[str(i + 1)][j])
                self.base64blocks = {}
                self.cb64blocks = {}
                self.encrypteddatablocks = {}
                outfile = open(efile, 'wb')
                for line in self.cipherdata:
                    outfile.write(self.hexifyr(line)[0] + b'\n')
                outfile.close()
                self.cleanUp()
                print("Encrypted File No. " + str(x + 1))
                x += 1
            keys = "n: " + str(self.key.n) + "\n" + "e: " + str(self.key.e) + "\n" + "d: " + str(
                self.key.d) + "\n"  "Magic Number: " + str(magicNum) + "(!THIS IS IMPORTANT!)" + "\n"
            print("Well. That was it!! Here is your Key data to retreive files back: \n" + keys)
            keyname = str(input("Enter the name of KEY FILE to store key in: "))
            keypath = ".//" + keyname + ".key"
            password = str(input("Enter password for key file: "))
            keyfile = open(keypath, 'wb')
            keyfile.write(self.key.export_key('PEM', password, 8, None, None))
            keyfile.close()
            print("KEY STORED! KEEP IT SAFE OR ELSE YOUR FILES WON'T BE BACK!")

    def decrypt(self):
        noOfFiles = int(input("One or Many? (1 or No. of Files):"))
        if (noOfFiles > 0):
            x = 0
            dfile = ""
            filepath = ""
            self.data = []
            magicNum = int(input("Enter the magic number used to encrypt files with: "))
            mNum = magicNum % 26
            while (x < noOfFiles):
                self.data = []
                filepath = str(input("Enter the full path to the file to decrypt: "))
                filename = filepath[filepath.rindex("/"):len(filepath)]
                dfile = "./Decrypted_" + filename.lstrip("/")
                self.getData(filepath, 'decrypt')
                print("Number of lines: {}".format(self.numberOfBlocks))
                print("----------Applying RSA----------\n")
                for i in range(0, self.threads):
                    # print("DEBUG: Running RSA Thread {}".format(str(i+1)))
                    self.processes.append(
                        threading.Thread(None, self.rsaProcess, None, (self.cipherdata, 'decrypt', i + 1)))
                    self.processes[i].start()
                for i in range(0, self.threads):
                    self.processes[i].join()
                print("----------RSA Done----------\n")
                # print("DEBUG: RSA Done")
                self.processes = []
                self.threadsDone = 0
                print("----------Applying CBase64----------\n")
                for i in range(0, self.threads):
                    # print("DEBUG: Running CBase64 Thread {}".format(str(i+1)))
                    self.processes.append(threading.Thread(None, self.cbase64it, None,
                                                           (self.decrypteddatablocks, 'decrypt', i + 1, mNum)))
                    self.processes[i].start()
                for i in range(0, self.threads):
                    self.processes[i].join()
                # print("DEBUG: CBase64 Done")
                print("----------CBase64 Done----------\n")
                self.processes = []
                self.threadsDone = 0
                print("----------Applying Base64----------\n")
                for i in range(0, self.threads):
                    # print("DEBUG: Running Base64 Thread {}".format(str(i+1)))
                    self.processes.append(
                        threading.Thread(None, self.base64it, None, (self.base64blocks, 'decrypt', i + 1)))
                    self.processes[i].start()
                for i in range(0, self.threads):
                    self.processes[i].join()
                print("----------Base64 Done----------\n")
                self.threadsDone = 0
                # print("DEBUG: Base64 Done")
                outfile = open(dfile, 'wb')
                for i in range(0, self.threads):
                    for j in range(0, len(self.odata[str(i + 1)])):
                        outfile.write(self.odata[str(i+1)][j])
                outfile.close()
                self.cleanUp()
                print("Decrypted File No. " + str(x + 1))
                x += 1


print("""\n
         ##########################################\n
         #                                        #\n
         #         Welcome to Crypter	          #\n
         #                                        #\n
         ##########################################\n

         (1) Encrypt File(s)
         (2) Decrypt File(s)
         (0) EXIT
         What to do?(1,2 or 0):""")
choice = int(input())
threads = 4
if (choice == 1):
    cryptor = crypter(None, threads)
    cryptor.encrypt()
elif (choice == 2):
    keypath = str(input("Enter the full path to the key: "))
    cryptor = crypter(keypath, threads)
    cryptor.decrypt()
else:
    exit(0)
print("Bye! See ya later :)\n")