import json
import pathlib
import re

import tkinter as tk
from functools import partial
from tkinter import filedialog, messagebox, simpledialog

from password_model import PasswordData


CONFIG_FILE = pathlib.Path.cwd() / "data/config.json"


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

        self.protocol("WM_DELETE_WINDOW", self.quit_callback)

        # show self
        self.deiconify()

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
                self.password_data.set_all(self.password_data.decrypt(file.read()))
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


class LoginWindow(tk.Toplevel):
    def __init__(self, master, login_callback, quit_callback):
        super().__init__(master)
        self.login_callback = login_callback
        self.wm_protocol("WM_DELETE_WINDOW", quit_callback)
        self.title("Login")
        self.geometry("300x100")
        self.resizable(False, False)
        if CONFIG_FILE.exists():
            with open(CONFIG_FILE, "r") as file:
                recent = json.loads(file.read())["recent"]
            if recent:
                self.filepath = pathlib.Path(recent[0])

        else:
            self.filepath: pathlib.Path = None
        self.file_var = tk.StringVar(value=str(self.filepath) if self.filepath else "")
        self.file_label = tk.Label(self, textvariable=self.file_var)
        self.file_label.pack()
        self.password_field = tk.Entry(master=self, show="*")
        self.password_field.pack()
        self.password_field.focus_set()
        login_button = tk.Button(master=self, text="Login",
                                 command=self.login)
        login_button.pack()

        self.password_field.bind("<Return>", self.login)

        self.init_menus()

    def init_menus(self):
        self.menu = tk.Menu(self)
        self.config(menu=self.menu)
        # menu structure:
        # file
        #   - new
        #   - open
        #   - open recent
        #       - file1
        #       - file2
        #       - ...
        #   - quit

        self.file_menu = tk.Menu(self.menu, tearoff=0)
        self.menu.add_cascade(label="File", menu=self.file_menu)
        self.file_menu.add_command(label="New", command=self.add_file)
        self.file_menu.add_command(label="Open", command=self.open_file)
        self.recent = tk.Menu(self.file_menu, tearoff=0)
        self.file_menu.add_cascade(label="Open Recent", menu=self.recent)

        self.file_menu.add_separator()
        self.file_menu.add_command(label="Quit", command=self.quit)

        self.load_recent()

    def add_file(self, *_):
        self.filepath = filedialog.asksaveasfilename(defaultextension=".pass",
                                                     filetypes=[("Password Files", "*.pass"), ("All Files", "*.*")])
        self.filepath = pathlib.Path(self.filepath)
        if self.filepath:
            with open(self.filepath, "wb") as file:
                file.write(b"")
            password = simpledialog.askstring("Password", "Enter Password for new file:", show="*")
            self.login(password)

            self.append_recent(self.filepath)

    def open_file(self, *_, filepath=None):
        if filepath is None:
            self.filepath = filedialog.askopenfilename(defaultextension=".pass",
                                                       filetypes=[("Password Files", "*.pass"), ("All Files", "*.*")])
            self.filepath = pathlib.Path(self.filepath)
        else:
            self.filepath = filepath
        self.file_var.set(str(self.filepath))
        self.append_recent(self.filepath)

    def login(self, *_, password=None):
        if self.filepath and self.filepath.exists():
            if self.login_callback(self.filepath, self.password_field.get() if password is None else password):
                self.withdraw()

    def load_recent(self):
        self.recent.delete(0, tk.END)
        config = json.loads(open(pathlib.Path.cwd() / "data/config.json", "r").read())
        for file in config["recent"]:
            self.recent.add_command(label=file, command=partial(self.open_file, filepath=pathlib.Path(file)))

    def append_recent(self, filepath):

        if not CONFIG_FILE.is_file() or not CONFIG_FILE.exists():
            config = {"recent": []}
            with open(CONFIG_FILE, "w") as file:
                file.write(json.dumps(config))

        else:
            config = json.loads(open(CONFIG_FILE, "r").read())

        while str(filepath) in config["recent"]:
            config["recent"].remove(str(filepath))
        config["recent"].insert(0, str(filepath))
        with open(CONFIG_FILE, "w") as file:
            file.write(json.dumps(config))
        self.load_recent()


class Application:
    def __init__(self):
        self.root = tk.Tk()
        self.root.withdraw()

        self.login_window = LoginWindow(self.root, self.init_main_window, self.close)
        self.data: PasswordData = None
        self.main_win: PasswordManagerWindow = None

    def init_main_window(self, path: pathlib.Path, password: str):
        try:
            self.data = PasswordData(path, password)
        except ValueError:
            return False

        self.main_win = PasswordManagerWindow(self.root, self.data, self.close)

        return True

    def close(self):
        self.data.save()
        self.root.destroy()

    def run(self):
        self.root.mainloop()


x = Application()
x.run()
