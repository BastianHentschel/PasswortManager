import pathlib
import random
import re
import string
import tkinter as tk
from functools import partial
from tkinter import filedialog, messagebox, simpledialog

import msgpack
import pyperclip
from Crypto.Cipher import AES
from Crypto.Hash import SHA512


class PasswordData:
    RANDOM = object()

    def __init__(self, password, fn=None):
        if fn is None:
            self.path = pathlib.Path.home().joinpath(".glad.pass")
        else:
            self.path = pathlib.Path(fn)
        hash_data = SHA512.new(bytes(password, encoding="UTF-8")).digest()
        self.key = bytes(a ^ b for a, b in zip(hash_data[:32], hash_data[32:]))
        self.__password_dict = {}

    def __enter__(self):

        if self.path.exists():
            with self.path.open("rb") as f:
                self.__password_dict = self.decrypt(f)
        else:
            self.__password_dict = {}
        self._opened = True
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        if not self._opened:
            return
        self._opened = False
        with self.path.open("wb") as f:
            f.write(self.encrypt())

    def decrypt(self, fp):
        enc_data = fp.read()
        cipher = AES.new(self.key, AES.MODE_EAX, nonce=enc_data[:16])
        data = cipher.decrypt_and_verify(enc_data[32:], enc_data[16:32])
        return msgpack.loads(data)

    def encrypt(self):
        cipher = AES.new(self.key, AES.MODE_EAX)
        enc_data = b"".join([cipher.nonce, *cipher.encrypt_and_digest(msgpack.dumps(self.__password_dict))[::-1]])
        return enc_data

    def copy_password(self, key):
        if self._opened:
            pyperclip.copy(self.__password_dict.get(key, None))

    def add_password(self, key, password: str = RANDOM, length=64):
        if self._opened:
            if password is self.RANDOM:
                password = "".join(
                    random.choices(string.ascii_letters + string.digits + string.punctuation, k=length)
                )
            if key in self.__password_dict:
                raise KeyError(f"Key {key} already exists")
            self.__password_dict[key] = password

        self.copy_password(key)

    def remove_password(self, key):
        if self._opened:
            self.__password_dict.pop(key, None)

    def keys(self):
        if self._opened:
            return [key for key in self.__password_dict]

    def set_all(self, passwords: dict):
        if self._opened:
            self.__password_dict = passwords


class PasswordManagerWindow(tk.Toplevel):
    def __init__(self, master, password_data, quit_callback):
        super().__init__(master)
        self.quit_callback = quit_callback
        self.master = master
        self.password_data: PasswordData = password_data
        self.title("Password Manager")
        self.init_menus()

        self.search_text = tk.StringVar()
        tk.Entry(self, textvariable=self.search_text).grid(row=0, column=0)
        tk.Button(self, text="Add", command=self.add_password).grid(row=0, column=1)
        self.listbox = tk.Listbox(self)
        self.listbox.grid(row=1, column=0, columnspan=2)

        self.listbox.bind("<Double-Button-1>", self.copy_password)
        self.listbox.bind("<Return>", self.copy_password)
        self.listbox.bind("<Delete>", self.delete_password)

        self.search_text.trace("w", self.update_view)
        self.update_view()

    def update_view(self, *_):
        self.listbox.delete(0, tk.END)
        try:
            for key in self.password_data.keys():
                if re.search(self.search_text.get(), key):
                    self.listbox.insert(tk.END, key)
        except re.error:
            pass

    def init_menus(self):
        # menustructure:
        # file
        #   - backup
        #   - restore
        #   - quit
        # edit
        #   - add
        #   - copy
        #   - delete
        # help
        #   - about
        self.menu = tk.Menu(self)
        self.config(menu=self.menu)

        self.file_menu = tk.Menu(self.menu, tearoff=0)
        self.menu.add_cascade(label="File", menu=self.file_menu)
        self.file_menu.add_command(label="Backup", command=self.backup)
        self.file_menu.add_command(label="Restore", command=self.restore)
        self.file_menu.add_separator()
        self.file_menu.add_command(label="Quit", command=self.quit)

        self.edit_menu = tk.Menu(self.menu, tearoff=0)
        self.menu.add_cascade(label="Edit", menu=self.edit_menu)
        self.edit_menu.add_command(label="Add", command=self.add_password)
        self.edit_menu.add_command(label="Copy", command=self.copy_password)
        self.edit_menu.add_command(label="Delete", command=self.delete_password)

        self.help_menu = tk.Menu(self.menu, tearoff=0)
        self.menu.add_cascade(label="Help", menu=self.help_menu)
        self.help_menu.add_command(label="About", command=self.about)

    def add_password(self, *_):
        key = simpledialog.askstring("Add Password", "Enter Name:")
        if key:
            self.password_data.add_password(key)
            self.update_view()

    def copy_password(self, *_):
        self.password_data.copy_password(self.listbox.get(tk.ACTIVE))

    def delete_password(self, *_):
        if messagebox.askokcancel(f"Delete Entry", f"Do you want to delete '{self.listbox.get(tk.ACTIVE)}'"):
            self.password_data.remove_password(self.listbox.get(tk.ACTIVE))
            self.update_view()

    def backup(self, *_):
        # get a new file selection
        file_path = filedialog.asksaveasfilename(defaultextension=".pass.bak",
                                                 filetypes=[("Password Files", "*.pass.bak"), ("All Files", "*.*")])
        if file_path:
            with open(file_path, "wb") as file:
                file.write(self.password_data.encrypt())

    def restore(self, *_):
        # get a backup file selection
        file_path = filedialog.askopenfilename(defaultextension=".pass.bak",
                                               filetypes=[("Password Files", "*.pass.bak"), ("All Files", "*.*")])

        if file_path:
            with open(file_path, "rb") as file:
                self.password_data.set_all(self.password_data.decrypt(file))
                self.update_view()

    def about(self, *_):
        text = """
This is a simple password manager.
Developed by Bastian Hentschel

Github: https://github.com/bastianhentschel/password-manager
"""

        messagebox.showinfo("About", text)

    def quit(self, *_):
        if messagebox.askokcancel("Quit", "Do you really wish to quit?"):
            self.quit_callback()


class Application:
    def __init__(self):
        self.login_win = tk.Tk()

        self.mode = "login"

        self.init_login()
        self.login_win.protocol("WM_DELETE_WINDOW", self.close)

    def init_login(self):
        self.mode = "login"
        self.login_win.title("Login")

        password_field = tk.Entry(master=self.login_win, show="*")
        password_field.pack()
        password_field.focus_set()
        login_button = tk.Button(master=self.login_win, text="Login",
                                 command=lambda: self.init_main(password_field.get()))
        login_button.pack()

        password_field.bind("<Return>", lambda event: self.init_main(password_field.get()))

    def init_main(self, password):
        try:
            self.data = PasswordData(password)
            self.data.__enter__()
        except ValueError:
            self.mode = "login"
            return

        self.data = PasswordData(password).__enter__()

        self.main_win = PasswordManagerWindow(self.login_win, self.data, self.close)

        self.mode = "main"
        self.login_win.withdraw()
        self.main_win.deiconify()
        self.main_win.protocol("WM_DELETE_WINDOW", self.close)

    def close(self):
        try:
            self.data.__exit__(None, None, None)
        except AttributeError:
            pass
        self.data = None
        self.login_win.destroy()
        self.mode = None

    def run(self):
        self.login_win.mainloop()


x = Application()
x.run()
