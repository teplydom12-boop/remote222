"""Visible Windows app: one button starts the agent and its bundled tunnel."""

import os
import queue
import tkinter as tk
from tkinter import messagebox, ttk

from . import __version__
from .agent import default_state_dir
from .session import Session


class DesktopApp:
    def __init__(self, root):
        self.root = root
        self.session = None
        self.events = queue.Queue()
        self.closing = False
        self.copied_key = None
        self.url = tk.StringVar()
        self.status = tk.StringVar(value="Управление отключено")
        root.title(f"Remote222 {__version__}")
        root.geometry("680x465")
        root.minsize(600, 440)
        root.protocol("WM_DELETE_WINDOW", self.close)
        style = ttk.Style(root)
        if "vista" in style.theme_names():
            style.theme_use("vista")
        style.configure("TButton", padding=(12, 8))
        body = ttk.Frame(root, padding=22)
        body.pack(fill="both", expand=True)
        ttk.Label(body, text="Управление вашим компьютером", font=("Segoe UI", 17, "bold")).pack(anchor="w")
        ttk.Label(body, text="Windows · программы · файлы · клавиатура и мышь", padding=(0, 7)).pack(anchor="w")
        self.state_label = ttk.Label(body, textvariable=self.status, font=("Segoe UI", 11, "bold"), foreground="#5e6672", padding=(0, 14))
        self.state_label.pack(anchor="w")
        controls = ttk.Frame(body)
        controls.pack(fill="x", pady=(0, 16))
        self.start_button = ttk.Button(controls, text="Включить управление", command=self.start)
        self.start_button.pack(side="left")
        self.stop_button = ttk.Button(controls, text="Отключить", command=self.stop, state="disabled")
        self.stop_button.pack(side="left", padx=10)
        ttk.Label(body, text="Адрес для подключения").pack(anchor="w")
        ttk.Entry(body, textvariable=self.url, state="readonly").pack(fill="x", pady=6)
        copy = ttk.Frame(body)
        copy.pack(fill="x", pady=(0, 15))
        self.copy_url_button = ttk.Button(copy, text="Скопировать адрес", command=self.copy_url, state="disabled")
        self.copy_url_button.pack(side="left")
        self.copy_key_button = ttk.Button(copy, text="Скопировать ключ", command=self.copy_key, state="disabled")
        self.copy_key_button.pack(side="left", padx=10)
        ttk.Label(body, text="Отправьте адрес в чат. Ключ вставьте в секрет REMOTE222_TOKEN\nв настройках облачной среды; в чат ключ отправлять не нужно.", justify="left").pack(anchor="w")
        ttk.Separator(body).pack(fill="x", pady=15)
        ttk.Label(body, text="При включении доступны действия с правами вашей учётной записи.\nЗакрытие этого окна отключает управление. Автозапуска нет.", justify="left").pack(anchor="w")
        ttk.Button(body, text="Открыть папку журналов", command=self.open_logs).pack(anchor="w", pady=(12, 0))
        self.root.after(100, self.poll)

    def start(self):
        if self.session:
            return
        self.start_button.configure(state="disabled")
        self.stop_button.configure(state="normal")
        self.status.set("Запуск…")
        self.state_label.configure(foreground="#5e6672")
        self.session = Session(default_state_dir(), lambda kind, data: self.events.put((kind, data)))
        self.session.start()

    def stop(self):
        if self.session:
            self.status.set("Отключение…")
            self.stop_button.configure(state="disabled")
            self.copy_url_button.configure(state="disabled")
            self.copy_key_button.configure(state="disabled")
            self.url.set("")
            self.session.stop()

    def copy_url(self):
        if self.url.get():
            self.root.clipboard_clear()
            self.root.clipboard_append(self.url.get())

    def copy_key(self):
        if self.session and self.session.token:
            self.root.clipboard_clear()
            self.root.clipboard_append(self.session.token)
            self.copied_key = self.session.token
            self.root.after(60000, self.clear_key)
            messagebox.showinfo("Ключ скопирован", "Вставьте ключ в секрет REMOTE222_TOKEN в настройках облачной среды.\n\nРазрешённый домен — имя хоста из адреса подключения. Буфер будет очищен через минуту, если ключ всё ещё в нём.", parent=self.root)

    def clear_key(self):
        try:
            if self.copied_key and self.root.clipboard_get() == self.copied_key:
                self.root.clipboard_clear()
        except tk.TclError:
            pass
        self.copied_key = None

    def open_logs(self):
        path = default_state_dir()
        if path.is_dir():
            os.startfile(path)
        else:
            messagebox.showinfo("Журналы", "Папка журналов появится после первого запуска.", parent=self.root)

    def close(self):
        self.closing = True
        self.clear_key()
        if self.session:
            self.stop()
        else:
            self.root.destroy()

    def poll(self):
        try:
            while True:
                kind, data = self.events.get_nowait()
                if kind == "status" and not self.closing:
                    self.status.set(data)
                elif kind == "ready" and not self.closing and self.session and not self.session.stop_event.is_set():
                    self.url.set(data)
                    self.status.set("Управление включено")
                    self.state_label.configure(foreground="#187448")
                    self.copy_url_button.configure(state="normal")
                    self.copy_key_button.configure(state="normal")
                elif kind == "error" and not self.closing:
                    self.state_label.configure(foreground="#a32626")
                    messagebox.showerror("Не удалось подключиться", data, parent=self.root)
                elif kind == "stopped":
                    self.session = None
                    self.url.set("")
                    self.status.set("Управление отключено")
                    self.state_label.configure(foreground="#5e6672")
                    self.start_button.configure(state="normal")
                    for button in (self.stop_button, self.copy_url_button, self.copy_key_button):
                        button.configure(state="disabled")
                    if self.closing:
                        self.root.destroy()
                        return
        except queue.Empty:
            pass
        self.root.after(100, self.poll)


def main():
    if os.name != "nt":
        raise SystemExit("The desktop app requires Windows 11. Use remote222.client on Linux.")
    root = tk.Tk()
    DesktopApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()
