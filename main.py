import base64
from tkinter import *
from tkinter import messagebox

#Function to encode
def encode(key, clear):
    enc = []
    for i in range(len(clear)):
        key_c = key[i % len(key)]
        enc_c = chr((ord(clear[i]) +
                     ord(key_c)) % 256)
        enc.append(enc_c)
    return base64.urlsafe_b64encode("".join(enc).encode()).decode()

# Function to decode
def decode(key, enc):
    dec = []

    enc = base64.urlsafe_b64decode(enc).decode()
    for i in range(len(enc)):
        key_c = key[i % len(key)]
        dec_c = chr((256 + ord(enc[i]) -
                     ord(key_c)) % 256)
        dec.append(dec_c)
    return "".join(dec)

#GUI
window = Tk()
window.title("Secret notes")
window.minsize(350,700)

photo=PhotoImage(file="topSecret.png")
photo_label =Label(image=photo)
photo_label.pack()

title_label = Label(text="Enter note title")
title_label.config(pady=10)
title_label.pack()

title_entry = Entry(width=40)
title_entry.pack()

secret_text_label = Label(text="Enter your note")
secret_text_label.config(pady=10)
secret_text_label.pack()

secret_note = Text(width=30,height=15)
secret_note.pack()

master_key_title=Label(text="Enter master key")
master_key_title.config(pady=10)
master_key_title.pack()

masterKey_entry=Entry(width=40)
masterKey_entry.pack()

def save_encrypt():
    Filename = str("secretNotes.txt")
    Textfile = open(Filename, 'r+')
    Textfile.read()

    if len(title_entry.get())==0 or len(secret_note.get(1.0,END))==0 or len(masterKey_entry.get())==0:
        messagebox.showinfo(title="ERROR!",message="Please enter all info")
    else:
        #encrypte
        encrypted_message = encode(masterKey_entry.get(),secret_note.get(1.0,END))

        #file processe
        Textfile.write(title_entry.get() + '\n' + encrypted_message + '\n')
        title_entry.delete(0, END)
        secret_note.delete(1.0, END)
        masterKey_entry.delete(0, END)
        Textfile.close()


save_encrypt_btn = Button(text="Save & encrypt",command=save_encrypt)
save_encrypt_btn.config(pady=7)
save_encrypt_btn.pack()

def decrypt():

   if len(secret_note.get(1.0,END))==0 or len(masterKey_entry.get())==0:
       messagebox.showinfo(title="ERROR!",message="Please enter all info")
   else:
      try:
        decrypt_message = decode(masterKey_entry.get(),secret_note.get(1.0,END))
        secret_note.delete(1.0, END)
        secret_note.insert(1.0,decrypt_message)
      except:
          messagebox.showerror(title="ERROR!",message="Please enter encrypted message")



decrypt_btn = Button(text="Decrypt",command=decrypt)
decrypt_btn.config(pady=7)
decrypt_btn.pack()



window.mainloop()