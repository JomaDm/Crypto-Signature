from tkinter import *
from tkinter import filedialog

from Crypto import Signature
from Keys import *
from rsa_file import *
from sha1 import *
from tkinter import messagebox
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA

# TODO: Cambiar interfaz a firma digital


class GUI():

    HEIGHT = 300
    WIDTH = 350
    background_color = "#23262E"
    white = "#fff"
    select_color = "#7A5FEE"
    show_inputs = False
    last_option = 0
    window = None
    frame = None

    pathMessageFile = None
    pathKeyPub = None
    pathKeyPriv = None
    choose_filePMF = False
    choose_filePKPB = False
    choose_filePKPR = False

    dynamic_widgets = []

    def __init__(self):
        self.window = Tk()
        self.window.title("Digital signature")
        self.window.geometry(str(self.HEIGHT)+'x'+str(self.WIDTH))
        self.window.resizable(0, 0)

        self.frame = Frame(self.window,
                           background=self.background_color
                           )
        self.frame.pack(fill="both",
                        expand=True
                        )

        self.label_opt = Label(self.frame,
                               text="Choose your option:",
                               fg=self.white,
                               bg=self.background_color,
                               font=("Arial", 14)
                               )
        self.label_opt.pack()

        option = IntVar()

        self.radioButton1 = Radiobutton(self.frame,
                                        text="Generate Keys",
                                        variable=option,
                                        value=1,
                                        bg=self.background_color,
                                        selectcolor=self.select_color,
                                        fg=self.white,
                                        font=("Arial", 12)
                                        )
        self.radioButton1.pack()

        self.radioButton2 = Radiobutton(self.frame,
                                        text="Generate signature",
                                        variable=option,
                                        value=2,
                                        bg=self.background_color,
                                        selectcolor=self.select_color,
                                        fg=self.white,
                                        font=("Arial", 12)
                                        )
        self.radioButton2.pack()

        self.radioButton2 = Radiobutton(self.frame,
                                        text="Check Signature",
                                        variable=option,
                                        value=3,
                                        bg=self.background_color,
                                        selectcolor=self.select_color,
                                        fg=self.white,
                                        font=("Arial", 12)
                                        )
        self.radioButton2.pack()

        self.selectButton = Button(self.frame,
                                   text="SELECT",
                                   bd=0,
                                   fg=self.white,
                                   bg=self.select_color,
                                   font=("Arial", 12),
                                   command=lambda: self.selectButton_function(option.get())
                                   )
        self.selectButton.pack()

    def run(self):
        self.window.mainloop()

    def selectButton_function(self, option):
        if(option == 1):
            # Generar llaves
            self.generateKeyWidgets()

        elif(option == 2):
            # Generar Firma
            self.generateSignatureWidgets()

        elif(option == 3):
            # Verificar firma
            self.generateCheckSignatureWidgets()

    def setInputText(self, input_entry, text):
        input_entry.delete(0, END)
        input_entry.insert(0, text)

    def destroyDynamicWidgets(self):
        choose_filePMF = False
        choose_filePKPB = False
        choose_filePKPR = False
        for i in self.dynamic_widgets:
            i.destroy()

    def pathFile(self):
        ruta = filedialog.askopenfilename()
        if ruta != None:
            print("Archivo seleccionado")
            print(ruta)
            return ruta
        else:
            print("Archivo no seleccionado")
            return None

    def generateKeyWidgets(self):
        self.destroyDynamicWidgets()
        self.addSpaceWidget()

        labelIdentifier = Label(
            self.frame,
            text="Identifier for Keys (Optional)",
            fg=self.white,
            bg=self.background_color,
            font=("Arial", 14)
        )
        labelIdentifier.pack()
        self.dynamic_widgets.append(labelIdentifier)

        inputIdentifier = Entry(self.frame)
        inputIdentifier.pack()
        self.dynamic_widgets.append(inputIdentifier)

        self.addSpaceWidget()

        generateKeysBtn = Button(self.frame,
                                 text="Generate Keys",
                                 bd=0,
                                 fg=self.white,
                                 bg=self.select_color,
                                 font=("Arial", 12),
                                 command=lambda: self.generateKeysFunction(identifier=inputIdentifier.get())
                                 )
        generateKeysBtn.pack()
        self.dynamic_widgets.append(generateKeysBtn)

    def generateKeysFunction(self, identifier: str):
        try:
            key_Generator(identifier=identifier)
        except Exception:
            messagebox.showerror(message="An error has ocurred trying to generate keys")

        messagebox.showinfo(message="Keys generated successfully", title="Success")

    def generateSignatureWidgets(self):
        self.destroyDynamicWidgets()
        self.addSpaceWidget()
        messageFileBtn = Button(self.frame,
                                text="Message File",
                                bd=0,
                                fg=self.white,
                                bg=self.select_color,
                                font=("Arial", 12),
                                command=lambda: self.pathToMessageFile())
        messageFileBtn.pack()
        self.dynamic_widgets.append(messageFileBtn)

        self.addSpaceWidget()
        privateKeyBtn = Button(self.frame,
                               text="Private Key File",
                               bd=0,
                               fg=self.white,
                               bg=self.select_color,
                               font=("Arial", 12),
                               command=lambda: self.pathToPrivateKey())
        privateKeyBtn.pack()
        self.dynamic_widgets.append(privateKeyBtn)

        self.addSpaceWidget()
        generateBtn = Button(self.frame,
                             text="Generate",
                             bd=0,
                             fg=self.white,
                             bg=self.select_color,
                             font=("Arial", 12),
                             command=lambda: self.generateSignature())
        generateBtn.pack()
        self.dynamic_widgets.append(generateBtn)

    def pathToMessageFile(self):
        self.pathMessageFile = self.pathFile()
        self.choose_filePMF = self.pathMessageFile != None

    def pathToPrivateKey(self):
        self.pathKeyPriv = self.pathFile()
        self.choose_filePKPR = self.pathKeyPriv != None

    def generateSignature(self):
        if(self.choose_filePKPR and self.choose_filePMF):
            nameOfFile = (self.pathMessageFile.split("/")[-1]).split(".")[0]
            fileWithSignature = open("{name}_DS.txt".format(name=nameOfFile), "wb")
            textMessage = open_read_file(self.pathMessageFile)
            # sha = SHA1_()
            # digest = sha.makeDigest(textMessage)
            # encrypted = encrypt_message(message=digest, path_key=self.pathKeyPriv)
            # fileWithSignature.write(encrypted)
            # fileWithSignature.close()

            # fileWithSignature = open("message_DS.txt", "a")
            # result = "~DigitalSignature~"+textMessage

            # fileWithSignature.write(result)
            # fileWithSignature.close()

            key = RSA.import_key(open(self.pathKeyPriv).read())
            h = SHA256.new(bytes(textMessage, encoding="utf-8"))
            signature = pkcs1_15.new(key).sign(h)
            fileWithSignature.write(signature)
            fileWithSignature.close()

            fileWithSignature = open("{name}_DS.txt".format(name=nameOfFile), "a")
            fileWithSignature.write("~DigitalSignature123~"+textMessage)
            fileWithSignature.close()

            messagebox.showinfo(message="Digital signature generated successfully", title="Success")
            pass
        else:
            messagebox.showerror(message="Error files not selected", title="Error")

    def generateCheckSignatureWidgets(self):
        self.destroyDynamicWidgets()
        self.addSpaceWidget()
        messageFileBtn = Button(self.frame,
                                text="Message File",
                                bd=0,
                                fg=self.white,
                                bg=self.select_color,
                                font=("Arial", 12),
                                command=lambda: self.pathToMessageFile())
        messageFileBtn.pack()
        self.dynamic_widgets.append(messageFileBtn)

        self.addSpaceWidget()
        publicKeyBtn = Button(self.frame,
                              text="Public Key File",
                              bd=0,
                              fg=self.white,
                              bg=self.select_color,
                              font=("Arial", 12),
                              command=lambda: self.pathToPublicKey())
        publicKeyBtn.pack()
        self.dynamic_widgets.append(publicKeyBtn)

        self.addSpaceWidget()
        generateBtn = Button(self.frame,
                             text="Check",
                             bd=0,
                             fg=self.white,
                             bg=self.select_color,
                             font=("Arial", 12),
                             command=lambda: self.checkSignature())
        generateBtn.pack()
        self.dynamic_widgets.append(generateBtn)

    def pathToPublicKey(self):
        self.pathKeyPub = self.pathFile()
        self.choose_filePKPB = self.pathKeyPub != None

    def checkSignature(self):
        if(self.choose_filePKPB and self.choose_filePMF):
            # File = open(self.pathMessageFile, "rb")
            # encrypted = File.read()[0:128]
            # textMessage = File.read()[128:-1].decode("utf-8")
            # File.close()

            # # SHA1 digest
            # sha = SHA1_()
            # digest = sha.makeDigest(textMessage)
            # decrypted = decrypt_message(message=encrypted, path_key=self.pathKeyPub)

            # if(digest == decrypted):
            #     messagebox.showinfo(message="Digital signature checked successfully", title="😀")
            # else:
            #     messagebox.showerror(message="Oh no!!! Digital signature error ", title="🙁")

            key = RSA.import_key(open(self.pathKeyPub).read())
            textFile = open_read_file("message.txt").split("~DigitalSignature123~")
            h = SHA256.new(bytes(textFile[0], encoding="utf-8"))
            signature = open(self.pathMessageFile, "rb").read()[0:128]
            try:
                pkcs1_15.new(key).verify(h, signature)
                messagebox.showinfo(message="Digital signature checked successfully", title="😀")
            except (ValueError, TypeError):
                messagebox.showerror(message="Oh no!!! Digital signature error ", title="🙁")
            pass
        else:
            messagebox.showerror(message="Error files not selected", title="Error")

    def addSpaceWidget(self):
        label_space = Label(self.frame,
                            text="",
                            bg=self.background_color
                            )
        label_space.pack()
        self.dynamic_widgets.append(label_space)


if __name__ == "__main__":
    gui = GUI()
    gui.run()
