import base64
import tkinter
from tkinter import  messagebox
from PIL import ImageTk, Image


window = tkinter.Tk()
window.minsize(width=375, height=650)
window.title("Secret Note")

FONT = ("Helvetica", "14")

#Enter title
my_label_tittle = tkinter.Label(text="Enter your title", font=FONT)
my_label_tittle.place(x=98, y=250)

my_entry_title = tkinter.Entry(width=34)
my_entry_title.place(x=98, y=280)


#Enter Secret
my_label_secret = tkinter.Label(text="Enter your Secret", font=FONT)
my_label_secret.place(x=98, y=310)

my_Text_secret = tkinter.Text(width=25, height=7)
my_Text_secret.place(x=98, y=340)


#Enter Masterkey
my_label_key = tkinter.Label(text="Enter your Master Key" , font=FONT)
my_label_key.place(x=98, y=500)

my_entry_key = tkinter.Entry(window,show="*",width=34)
my_entry_key.place(x=98, y=530)


# Image
image = ImageTk.PhotoImage(Image.open("C:logo-header.png"))

image_label = tkinter.Label(width=300, height=250, image=image)
image_label.pack()






def Entry():
    entry_Title = my_entry_title.get()
    entry_SecretNote = my_Text_secret.get("1.0", tkinter.END)
    entry_masterKey = my_entry_key.get()

    if len(entry_Title) == 0 or len(entry_SecretNote) == 0 or len(entry_masterKey)== 0:
        messagebox.showinfo(title="Error!", message="Please enter all options")

    else:
        message_encrypted = encode(entry_masterKey,entry_SecretNote)
        try:

            with open("C:SecretText.txt", "a") as file:

                file.write(f'\n{entry_Title}\n{message_encrypted}')
        except FileNotFoundError:
            with open("C:", "w") as file:
                file.write(f'\n{entry_Title}\n{message_encrypted}')

        finally:
            my_entry_key.delete(0, tkinter.END)
            my_entry_title.delete(0, tkinter.END)
            my_Text_secret.delete("1.0", tkinter.END)



def encode(key, clear):
    enc = []
    for i in range(len(clear)):
        key_c = key[i % len(key)]
        enc_c = chr((ord(clear[i]) + ord(key_c)) % 256)
        enc.append(enc_c)
    return base64.urlsafe_b64encode("".join(enc).encode()).decode()

def decode(key, enc):
    dec = []
    enc = base64.urlsafe_b64decode(enc).decode()
    for i in range(len(enc)):
        key_c = key[i % len(key)]
        dec_c = chr((256 + ord(enc[i]) - ord(key_c)) % 256)
        dec.append(dec_c)
    return "".join(dec)

def decrypt():
    encrypted_message = my_Text_secret.get("1.0", tkinter.END)
    secret_key =my_entry_key.get()
    if len(encrypted_message) == 0 or len(secret_key) == 0:
        messagebox.showinfo(title="ERROR!", message="Please enter all options")
    else:
        try:
            decrypted_message = decode(secret_key, encrypted_message )
            my_Text_secret.delete("1.0", tkinter.END)
            my_Text_secret.insert("1.0", decrypted_message)
        except:
            messagebox.showerror(title="ERROR!", message="Please enter encryted text")

#Button
my_saveEncrypt_Button = tkinter.Button(text="Save & Encrypt", command= Entry)
my_saveEncrypt_Button.place(x=150, y=560)

my_decryptButton = tkinter.Button(text="Decrypt", command=decrypt)
my_decryptButton.place(x=170, y=590 )








tkinter.mainloop()