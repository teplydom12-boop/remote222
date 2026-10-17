"""Visible Windows app with a polling queue or bundled direct tunnel."""

import os
from pathlib import Path
import queue
import tkinter as tk
from tkinter import messagebox, ttk

from . import __version__
from .agent import default_state_dir
from .client import ClientError
from .session import AccountLogout, RelaySession, Session, read_relay_settings


class DesktopApp:
    def __init__(self, root, state_dir=None):
        self.root = root
        self.state_dir = Path(state_dir) if state_dir is not None else default_state_dir()
        self.session = None
        self.events = queue.Queue()
        self.closing = False
        self.copied_key = None
        self.url = tk.StringVar()
        self.mode = tk.StringVar(value="relay")
        saved_account = read_relay_settings(self.state_dir)
        self.relay_url = tk.StringVar(value=saved_account.get("url", ""))
        self.username = tk.StringVar(value=saved_account.get("username", ""))
        self.password = tk.StringVar()
        self.logged_out = False
        self.connection_hint = tk.StringVar()
        self.status = tk.StringVar(value="Управление отключено")
        root.title(f"Remote222 {__version__}")
        root.geometry("740x780")
        root.minsize(700, 740)
        root.protocol("WM_DELETE_WINDOW", self.close)
        style = ttk.Style(root)
        if "vista" in style.theme_names():
            style.theme_use("vista")
        style.configure("TButton", padding=(12, 8))
        body = ttk.Frame(root, padding=22)
        body.pack(fill="both", expand=True)
        ttk.Label(body, text="Управление вашим компьютером", font=("Segoe UI", 17, "bold")).pack(anchor="w")
        ttk.Label(body, text="Windows · программы · файлы · клавиатура и мышь", padding=(0, 7)).pack(anchor="w")
        choice = ttk.Frame(body)
        choice.pack(fill="x", pady=5)
        self.mode_buttons = [
            ttk.Radiobutton(choice, text="Через сервер очереди", value="relay", variable=self.mode, command=self.update_mode),
            ttk.Radiobutton(choice, text="Прямой туннель Cloudflare", value="direct", variable=self.mode, command=self.update_mode),
        ]
        for button in self.mode_buttons:
            button.pack(side="left", padx=(0, 15))
        self.relay_settings = ttk.Frame(body)
        self.relay_settings.pack(fill="x", pady=5)
        ttk.Label(self.relay_settings, text="HTTPS-адрес вашего сервера очереди").pack(anchor="w")
        self.relay_url_entry = ttk.Entry(self.relay_settings, textvariable=self.relay_url)
        self.relay_url_entry.pack(fill="x", pady=(3, 7))
        ttk.Label(self.relay_settings, text="Логин").pack(anchor="w")
        self.username_entry = ttk.Entry(self.relay_settings, textvariable=self.username)
        self.username_entry.pack(fill="x", pady=(3, 7))
        ttk.Label(self.relay_settings, text="Пароль — не нужен, пока сохранённый вход действует").pack(anchor="w")
        self.password_entry = ttk.Entry(self.relay_settings, textvariable=self.password, show="•")
        self.password_entry.pack(fill="x", pady=3)
        ttk.Label(self.relay_settings, text="Вход запоминается на этом ПК. Пароль не сохраняется.", wraplength=650).pack(anchor="w")
        self.state_label = ttk.Label(body, textvariable=self.status, font=("Segoe UI", 11, "bold"), foreground="#5e6672", padding=(0, 14))
        self.state_label.pack(anchor="w")
        controls = ttk.Frame(body)
        controls.pack(fill="x", pady=(0, 16))
        self.start_button = ttk.Button(controls, text="Включить управление", command=self.start)
        self.start_button.pack(side="left")
        self.stop_button = ttk.Button(controls, text="Отключить", command=self.stop, state="disabled")
        self.stop_button.pack(side="left", padx=10)
        self.logout_button = ttk.Button(controls, text="Выйти из аккаунта", command=self.logout)
        self.logout_button.pack(side="left")
        ttk.Label(body, text="Адрес для подключения").pack(anchor="w")
        ttk.Entry(body, textvariable=self.url, state="readonly").pack(fill="x", pady=6)
        copy = ttk.Frame(body)
        copy.pack(fill="x", pady=(0, 15))
        self.copy_url_button = ttk.Button(copy, text="Скопировать адрес", command=self.copy_url, state="disabled")
        self.copy_url_button.pack(side="left")
        self.copy_key_button = ttk.Button(copy, text="Скопировать ключ", command=self.copy_key, state="disabled")
        self.copy_key_button.pack(side="left", padx=10)
        ttk.Label(body, textvariable=self.connection_hint, justify="left", wraplength=650).pack(anchor="w")
        ttk.Separator(body).pack(fill="x", pady=15)
        ttk.Label(body, text="При включении доступны действия с правами вашей учётной записи.\nЗакрытие этого окна отключает управление. Автозапуска нет.", justify="left").pack(anchor="w")
        ttk.Button(body, text="Открыть папку журналов", command=self.open_logs).pack(anchor="w", pady=(12, 0))
        self.update_mode()
        self.root.after(100, self.poll)

    def update_mode(self):
        relay = self.mode.get() == "relay"
        for entry in (self.relay_url_entry, self.username_entry, self.password_entry):
            entry.configure(state="normal" if relay and not self.session else "disabled")
        for button in self.mode_buttons:
            button.configure(state="disabled" if self.session else "normal")
        self.connection_hint.set(
            "Отправьте адрес сервера в чат. Подключение чата подтвердите один раз на странице сервера. Команды, результаты и снимки экрана будут передаваться через очередь. «Отключить» сохраняет вход; «Выйти из аккаунта» завершает его."
            if relay else
            "Отправьте адрес в чат. Кнопка «Скопировать ключ» копирует ключ прямого подключения: вставьте его в секрет REMOTE222_TOKEN облачной среды.")
        if relay:
            self.copy_key_button.pack_forget()
            self.logout_button.pack(side="left")
        else:
            self.copy_key_button.pack(side="left", padx=10)
            self.logout_button.pack_forget()
        self.logout_button.configure(state="disabled" if isinstance(self.session, AccountLogout) else "normal")

    def start(self):
        if self.session:
            return
        emit = lambda kind, data: self.events.put((kind, data))
        try:
            if self.mode.get() == "relay":
                self.session = RelaySession(self.state_dir, emit,
                                            self.relay_url.get().strip(),
                                            username=self.username.get().strip(), password=self.password.get())
                self.password.set("")
            else:
                self.session = Session(self.state_dir, emit)
        except (ClientError, ValueError, RuntimeError) as exc:
            messagebox.showerror("Проверьте настройки", str(exc), parent=self.root)
            return
        self.start_button.configure(state="disabled")
        self.stop_button.configure(state="normal")
        self.logged_out = False
        self.status.set("Запуск…")
        self.state_label.configure(foreground="#5e6672")
        self.update_mode()
        self.session.start()

    def stop(self):
        if self.session:
            self.status.set("Отключение; начатая команда может завершаться…")
            self.stop_button.configure(state="disabled")
            self.copy_url_button.configure(state="disabled")
            self.copy_key_button.configure(state="disabled")
            self.url.set("")
            self.session.stop()

    def logout(self):
        if self.mode.get() != "relay" or isinstance(self.session, AccountLogout):
            return
        self.password.set("")
        self.status.set("Выход из аккаунта; начатая команда может завершаться…")
        if self.session:
            self.stop()
            self.session.logout()
        else:
            emit = lambda kind, data: self.events.put((kind, data))
            self.session = AccountLogout(self.state_dir, emit)
            self.start_button.configure(state="disabled")
            self.update_mode()
            self.session.start()
        self.logout_button.configure(state="disabled")

    def copy_url(self):
        if self.url.get():
            self.root.clipboard_clear()
            self.root.clipboard_append(self.url.get())

    def copy_key(self):
        if self.mode.get() == "direct" and self.session and self.session.token:
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
        path = self.state_dir
        if path.is_dir():
            os.startfile(path)
        else:
            messagebox.showinfo("Журналы", "Папка журналов появится после первого запуска.", parent=self.root)

    def close(self):
        self.closing = True
        self.password.set("")
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
                elif kind == "account_ready":
                    self.password.set("")
                elif kind == "logged_out":
                    self.logged_out = True
                elif kind == "ready" and not self.closing and self.session and not self.session.stop_event.is_set():
                    self.url.set(data)
                    self.status.set("Управление включено")
                    self.state_label.configure(foreground="#187448")
                    self.copy_url_button.configure(state="normal")
                    self.copy_key_button.configure(state="normal" if self.mode.get() == "direct" else "disabled")
                elif kind == "error" and not self.closing:
                    self.state_label.configure(foreground="#a32626")
                    messagebox.showerror("Remote222", data, parent=self.root)
                elif kind == "stopped":
                    self.session = None
                    self.url.set("")
                    self.status.set("Вход удалён. Управление отключено" if self.logged_out else "Управление отключено")
                    self.state_label.configure(foreground="#5e6672")
                    self.start_button.configure(state="normal")
                    self.update_mode()
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
