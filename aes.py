import customtkinter as ctk
from tkinter import Tk, messagebox, simpledialog
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import base64

# Mengatur tema
ctk.set_appearance_mode("System")
ctk.set_default_color_theme("blue")

def adjust_key_size(key):
    # Menyesuaikan kunci menjadi 16/24/32 dengan menambahkan spasi
    sizes = [16, 24, 32]
    for size in sizes:
        if len(key) <= size:
            return key.ljust(size, ' ')
    return key[:32]  # Jika kunci lebih dari 32 bytes, maka akan dipotong

class AESApp(ctk.CTk):
    def __init__(self):
        super().__init__()

        self.title('AES Encryption/Decryption')
        self.geometry('800x600')

        # Label untuk input text
        self.label_input_text = ctk.CTkLabel(self, text="Input Text:",  font=('Helvetica', 14, 'normal'))
        self.label_input_text.pack(pady=0)

        # Input untuk plaintext/ciphertext
        self.input_text = ctk.CTkEntry(self, placeholder_text="Masukkan input text", width=400, height=40, corner_radius=10)
        self.input_text.pack(pady=20)

        # Label untuk kunci
        self.label_key = ctk.CTkLabel(self, text="Encryption Key (16/24/32 bytes):", font=('Helvetica', 14, 'normal'))
        self.label_key.pack(pady=0)

        # Input untuk kunci
        self.key_text = ctk.CTkEntry(self, placeholder_text="Masukkan encryption key (16/24/32 bytes)", width=400, height=40, corner_radius=10)
        self.key_text.pack(pady=20)

        # tombol enkripsi
        self.encrypt_button = ctk.CTkButton(self, text="Encrypt", command=self.encrypt, width=200, height=50, corner_radius=10, fg_color="#008000")
        self.encrypt_button.pack(pady=20)

        # tombol dekripsi
        self.decrypt_button = ctk.CTkButton(self, text="Decrypt", command=self.decrypt, width=200, height=50, corner_radius=10, fg_color="#990000")
        self.decrypt_button.pack(pady=20)

        # Hasil
        self.output_label = ctk.CTkLabel(self, text="", width=400, height=100, corner_radius=10,  font=('Helvetica', 18, 'bold'))
        self.output_label.pack(pady=0)

        # Tombol Copy to Clipboard
        self.copy_button = ctk.CTkButton(self, text="Copy to Clipboard", command=self.copy_text, width=200, height=50, corner_radius=10)
        self.copy_button.pack(pady=20)
        self.copy_button.pack_forget()
    # method untuk enkripsi
    def encrypt(self):
        plain_text = self.input_text.get()
        key = adjust_key_size(self.key_text.get())

        try:
            aes = AES.new(key.encode('utf-8'), AES.MODE_CBC)
            cipher_text = aes.encrypt(pad(plain_text.encode('utf-8'), AES.block_size))
            encoded_cipher_text = base64.b64encode(aes.iv + cipher_text).decode('utf-8')
            self.output_label.configure(text=encoded_cipher_text)
            self.show_copy_button()
        except Exception as e:
            messagebox.showerror("Error", str(e))
    # method untuk enkripsi
    def decrypt(self):
        encoded_cipher_text = self.input_text.get()
        key = adjust_key_size(self.key_text.get())

        try:
            decoded_cipher_text = base64.b64decode(encoded_cipher_text)
            iv = decoded_cipher_text[:AES.block_size]
            cipher_text = decoded_cipher_text[AES.block_size:]
            aes = AES.new(key.encode('utf-8'), AES.MODE_CBC, iv)
            plain_text = unpad(aes.decrypt(cipher_text), AES.block_size).decode('utf-8')
            self.output_label.configure(text=plain_text)
        except Exception as e:
            messagebox.showerror("Error", str(e))
    def show_copy_button(self):
        # Menampilkan Tombol Copy
        self.copy_button.pack(pady=10)
    def copy_text(self):
        text = self.output_label.cget("text")
        self.copy_to_clipboard(text)
        messagebox.showinfo("Copied", "Text successfully copied!")
    @staticmethod
    def copy_to_clipboard(text):
        root = Tk()
        root.withdraw()  # Menyembunyikan jendela Tkinter
        root.clipboard_clear()  # Menghapus isi clipboard saat ini
        root.clipboard_append(text)  # Menambahkan teks ke clipboard
        root.update()  # Sekarang teks tersimpan di clipboard dan bisa dipaste
        root.destroy()  # Menghancurkan jendela Tkinter

if __name__ == "__main__":
    app = AESApp()
    app.mainloop()
