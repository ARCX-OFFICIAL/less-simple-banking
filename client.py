import os
import tkinter as tk
from tkinter import ttk, messagebox
import requests
import random
import time
import threading
from cryptography.hazmat.primitives.asymmetric import dsa
from cryptography.hazmat.primitives import hashes, serialization
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import matplotlib.pyplot as plt
import imageio
from PIL import Image, ImageTk

# === Constants ===
FONT = ("Segoe UI", 11)
TITLE_FONT = ("Segoe UI", 13, "bold")
PADX, PADY = 8, 6
WINDOW_WIDTH, WINDOW_HEIGHT = 1000, 700

server_url = "http://localhost:5000"
KEY_FILE = "client_private_key.pem"

if os.path.exists(KEY_FILE):
    with open(KEY_FILE, "rb") as key_file:
        client_private_key = serialization.load_pem_private_key(
            key_file.read(), password=None)
else:
    client_private_key = dsa.generate_private_key(key_size=2048)
    with open(KEY_FILE, "wb") as key_file:
        key_file.write(client_private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()))
client_public_key = client_private_key.public_key()

root = tk.Tk()
root.title("Less Simple Banking")
root.geometry(f"{WINDOW_WIDTH}x{WINDOW_HEIGHT}")
root.minsize(800, 600)

def play_intro_video(path, on_done):
    try:
        reader = imageio.get_reader(path)
    except Exception as e:
        print(f"Error reading video: {e}")
        on_done()
        return

    label = tk.Label(root, bg="black")
    label.place(relx=0, rely=0, relwidth=1, relheight=1)

    frames = []
    for frame in reader:
        frames.append(ImageTk.PhotoImage(Image.fromarray(frame)))
    reader.close()

    def update(i=0):
        if i < len(frames):
            label.config(image=frames[i])
            root.after(33, lambda: update(i + 1))
        else:
            label.destroy()
            on_done()

    update()
def show_login_ui():
    screen_width = root.winfo_screenwidth()
    screen_height = root.winfo_screenheight()
    x = (screen_width // 2) - (WINDOW_WIDTH // 2)
    y = (screen_height // 2) - (WINDOW_HEIGHT // 2)
    root.geometry(f"{WINDOW_WIDTH}x{WINDOW_HEIGHT}+{x}+{y}")

    register_frame = ttk.LabelFrame(root, text="Register", padding=PADY)
    register_frame.pack(pady=10, fill="x")

    ttk.Label(register_frame, text="New Username:", font=FONT).grid(row=0, column=0, padx=PADX, pady=PADY, sticky="e")
    new_username_entry = ttk.Entry(register_frame, font=FONT)
    new_username_entry.grid(row=0, column=1, padx=PADX, pady=PADY)

    ttk.Label(register_frame, text="New Password:", font=FONT).grid(row=1, column=0, padx=PADX, pady=PADY, sticky="e")
    new_password_entry = ttk.Entry(register_frame, font=FONT, show="*")
    new_password_entry.grid(row=1, column=1, padx=PADX, pady=PADY)

    def register():
        new_username = new_username_entry.get()
        new_password = new_password_entry.get()
        if len(new_username) < 3 or len(new_password) < 6:
            messagebox.showerror("Error", "Username must be at least 3 characters and password at least 6.")
            return
        public_key_pem = client_public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo).decode()
        response = requests.post(f"{server_url}/register", json={
            "username": new_username,
            "password": new_password,
            "public_key": public_key_pem})
        result = response.json()
        if result["status"] == "Success":
            messagebox.showinfo("Success", "Registration Successful!")
            register_frame.pack_forget()
        else:
            messagebox.showerror("Failed", "Registration Failed.")

    ttk.Button(register_frame, text="Register", command=register).grid(row=3, columnspan=2, pady=PADY)

    login_frame = ttk.LabelFrame(root, text="Login", padding=PADY)
    login_frame.pack(pady=10, fill="x")

    ttk.Label(login_frame, text="Username:", font=FONT).grid(row=0, column=0, padx=PADX, pady=PADY, sticky="e")
    username_entry = ttk.Entry(login_frame, font=FONT)
    username_entry.grid(row=0, column=1, padx=PADX, pady=PADY)

    ttk.Label(login_frame, text="Password:", font=FONT).grid(row=1, column=0, padx=PADX, pady=PADY, sticky="e")
    password_entry = ttk.Entry(login_frame, font=FONT, show="*")
    password_entry.grid(row=1, column=1, padx=PADX, pady=PADY)

    def login():
        username = username_entry.get()
        password = password_entry.get()
        response = requests.post(f"{server_url}/login", json={"username": username, "password": password})
        result = response.json()
        if result["status"] == "Success":
            messagebox.showinfo("Success", "Login Successful!")
            login_frame.pack_forget()
            register_frame.pack_forget()
            open_dashboard(username)
        else:
            messagebox.showerror("Failed", "Login Failed.")

    ttk.Button(login_frame, text="Login", command=login).grid(row=3, columnspan=2, pady=PADY)

    def open_dashboard(username):
        dashboard_frame = ttk.Frame(root)
        dashboard_frame.pack(fill="both", expand=True)

        general_frame = ttk.Frame(dashboard_frame)
        transaction_frame = ttk.Frame(dashboard_frame)
        stocks_frame = ttk.Frame(dashboard_frame)
        share_price_frame = ttk.Frame(dashboard_frame)

        # --- Variables used across functions ---
        company_var = tk.StringVar()
        investment_var = tk.StringVar()
        balance_var = tk.StringVar()
        stocks_var = tk.StringVar()

        price_history = []
        time_history = []
        update_thread = None
        stop_update = threading.Event()
        chart_canvas = None
        fig = None
        ax = None

        # --- Helper functions defined first ---

        def fetch_balance():
            try:
                response = requests.post(f"{server_url}/balance", json={"username": username})
                result = response.json()
                if result["status"] == "Success":
                    balance_var.set(f"Current Balance: {result['balance']}")
                    if "investment_balance" in result:
                        investment_var.set(f"Investment Money: {result['investment_balance']}")
                    else:
                        investment_var.set("")
                else:
                    balance_var.set("Balance: Error")
                    investment_var.set("")
            except Exception as e:
                balance_var.set("Balance: Error")
                investment_var.set("")

        def fetch_company_status():
            try:
                resp = requests.post(f"{server_url}/is_company", json={"username": username})
                result = resp.json()
                if result["status"] == "Success":
                    if result["is_company"]:
                        company_var.set("This account is a COMPANY")
                    else:
                        company_var.set("This account is a PERSONAL account")
                else:
                    company_var.set("Error loading company status")
            except Exception as e:
                company_var.set("Error loading company status")

        def toggle_company():
            try:
                requests.post(f"{server_url}/toggle_company", json={"username": username})
            except Exception:
                pass
            fetch_company_status()
            fetch_balance()

        def fetch_stocks():
            try:
                resp = requests.post(f"{server_url}/my_stocks", json={"investor": username})
                info = resp.json()
                if info["status"] == "Success":
                    holdings = [f"{shares} shares in {account}" for account, shares in info["holdings"].items()]
                    stocks_var.set("Your Stocks: " + (", ".join(holdings) if holdings else "None"))
                else:
                    stocks_var.set("Your Stocks: Error")
                fetch_pending()
            except Exception:
                stocks_var.set("Your Stocks: Error")

        def fetch_pending():
            try:
                resp = requests.post(f"{server_url}/pending_stock_sales", json={"account": username})
                info = resp.json()
                pending_listbox.delete(0, tk.END)
                if info["status"] == "Success":
                    for req in info["pending"]:
                        txt = f"From: {req['investor']} | Shares: {req['shares']} | Cost: {req['total_cost']} | ID: {req['request_id']}"
                        pending_listbox.insert(tk.END, txt)
                else:
                    pending_listbox.insert(tk.END, "Error loading pending requests")
            except Exception:
                pending_listbox.insert(tk.END, "Error loading pending requests")

        def fetch_share_price(company):
            try:
                resp = requests.post(f"{server_url}/share_price", json={"company": company})
                data = resp.json()
                if data["status"] == "Success":
                    return float(data["price"])
                else:
                    return None
            except Exception:
                return None

        def update_chart():
            nonlocal chart_canvas, fig, ax
            company = company_entry.get()
            if not company:
                return
            price = fetch_share_price(company)
            if price is not None:
                price_history.append(price)
                time_history.append(time.strftime("%H:%M:%S"))
                if len(price_history) > 30:
                    price_history.pop(0)
                    time_history.pop(0)
            if fig is None or ax is None:
                fig, ax = plt.subplots(figsize=(5, 2.5), dpi=100)
                fig.tight_layout()
            ax.clear()
            ax.plot(time_history, price_history, marker='o', color='blue')
            ax.set_title(f"Share Price: {company}")
            ax.set_xlabel("Time")
            ax.set_ylabel("Price")
            ax.tick_params(axis='x', rotation=45)
            ax.set_ylim(0, 200)
            ax.set_xlim(0, max(10, len(time_history)))
            if chart_canvas is None or chart_canvas.figure != fig:
                if chart_canvas:
                    chart_canvas.get_tk_widget().destroy()
                chart_canvas = FigureCanvasTkAgg(fig, master=share_price_frame)
                chart_canvas.get_tk_widget().pack(pady=10)
            chart_canvas.draw()

        def periodic_update():
            while not stop_update.is_set():
                root.after(0, update_chart)
                for _ in range(60):
                    if stop_update.is_set():
                        break
                    time.sleep(1)

        def start_share_price():
            nonlocal update_thread, price_history, time_history, fig, ax, chart_canvas
            stop_share_price()
            price_history.clear()
            time_history.clear()
            fig = None
            ax = None
            if chart_canvas:
                chart_canvas.get_tk_widget().destroy()
            chart_canvas = None
            update_chart()
            stop_update.clear()
            if update_thread and update_thread.is_alive():
                return
            update_thread = threading.Thread(target=periodic_update, daemon=True)
            update_thread.start()

        def stop_share_price():
            stop_update.set()

        def show_frame(frame):
            for f in (general_frame, transaction_frame, stocks_frame, share_price_frame):
                f.pack_forget()
            frame.pack(fill="both", expand=True)

        def on_section_change(frame):
            if frame != share_price_frame:
                stop_share_price()
            show_frame(frame)

        # --- General Frame widgets ---
        ttk.Label(general_frame, text=f"Welcome, {username}", font=TITLE_FONT).pack(pady=10)
        ttk.Label(general_frame, textvariable=company_var, foreground="blue").pack()
        ttk.Button(general_frame, text="Toggle Company Status", command=toggle_company).pack(pady=5)
        ttk.Label(general_frame, textvariable=balance_var).pack()
        ttk.Label(general_frame, textvariable=investment_var, foreground="purple").pack()
        ttk.Button(general_frame, text="Reload Balance", command=fetch_balance).pack(pady=5)

        # --- Transaction Frame widgets ---
        ttk.Label(transaction_frame, text="Transfer Currency", font=TITLE_FONT).pack(pady=10)
        ttk.Label(transaction_frame, text="Transfer To:").pack()
        receiver_entry = ttk.Entry(transaction_frame)
        receiver_entry.pack()
        ttk.Label(transaction_frame, text="Amount:").pack()
        amount_entry = ttk.Entry(transaction_frame)
        amount_entry.pack()
        transfer_result = ttk.Label(transaction_frame, text="")
        transfer_result.pack()

        def transfer():
            receiver = receiver_entry.get()
            amount = amount_entry.get()
            transaction_id = random.randint(100000, 999999)
            transaction_data = f"{username}-{receiver}-{float(amount)}-{transaction_id}"
            signature = client_private_key.sign(transaction_data.encode(), hashes.SHA256())
            try:
                response = requests.post(f"{server_url}/transfer_currency", json={
                    "sender": username,
                    "receiver": receiver,
                    "amount": amount,
                    "transaction_id": transaction_id,
                    "signature": signature.hex()
                })
                message = response.json()["message"]
                if message == "Transaction successful!":
                    transfer_result.config(text=message, foreground="green")
                else:
                    transfer_result.config(text=message, foreground="red")
                fetch_balance()
            except Exception as e:
                transfer_result.config(text="Transfer Failed", foreground="red")

        ttk.Button(transaction_frame, text="Transfer", command=transfer).pack(pady=5)
        ttk.Button(transaction_frame, text="Reload Balance", command=fetch_balance).pack()

        # --- Stocks Frame widgets ---
        ttk.Label(stocks_frame, textvariable=stocks_var).pack()
        ttk.Button(stocks_frame, text="Reload Stocks", command=fetch_stocks).pack(pady=5)

        ttk.Label(stocks_frame, text="Buy Stock in Account:").pack()
        buy_account_entry = ttk.Entry(stocks_frame)
        buy_account_entry.pack()
        ttk.Label(stocks_frame, text="Shares:").pack()
        buy_shares_entry = ttk.Entry(stocks_frame)
        buy_shares_entry.pack()
        buy_result = ttk.Label(stocks_frame, text="")
        buy_result.pack()

        def buy_stock():
            account = buy_account_entry.get()
            shares = buy_shares_entry.get()
            try:
                shares = int(shares)
            except:
                buy_result.config(text="Invalid share number", foreground="red")
                return
            try:
                resp = requests.post(f"{server_url}/buy_stock", json={
                    "investor": username,
                    "account": account,
                    "shares": shares
                })
                result = resp.json()
                if result["status"] == "Success":
                    buy_result.config(text=result["message"], foreground="green")
                elif result["status"] == "Pending":
                    buy_result.config(text=result["message"], foreground="orange")
                else:
                    buy_result.config(text=result["message"], foreground="red")
                fetch_balance()
                fetch_stocks()
            except Exception as e:
                buy_result.config(text="Buy stock failed", foreground="red")

        ttk.Button(stocks_frame, text="Buy Stock", command=buy_stock).pack(pady=5)

        ttk.Label(stocks_frame, text="Sell Stock in Account:").pack()
        sell_account_entry = ttk.Entry(stocks_frame)
        sell_account_entry.pack()
        ttk.Label(stocks_frame, text="Shares:").pack()
        sell_shares_entry = ttk.Entry(stocks_frame)
        sell_shares_entry.pack()
        sell_result = ttk.Label(stocks_frame, text="")
        sell_result.pack()

        def sell_stock():
            account = sell_account_entry.get()
            shares = sell_shares_entry.get()
            try:
                shares = int(shares)
            except:
                sell_result.config(text="Invalid share number", foreground="red")
                return
            try:
                resp = requests.post(f"{server_url}/sell_stock", json={
                    "investor": username,
                    "account": account,
                    "shares": shares
                })
                result = resp.json()
                if result["status"] == "Success":
                    sell_result.config(text=result["message"], foreground="green")
                else:
                    sell_result.config(text=result["message"], foreground="red")
                fetch_balance()
                fetch_stocks()
            except Exception as e:
                sell_result.config(text="Sell stock failed", foreground="red")

        ttk.Button(stocks_frame, text="Sell Stock", command=sell_stock).pack(pady=5)

        # Pending Stock Sales Approval Section
        pending_listbox = tk.Listbox(stocks_frame, width=60)
        pending_listbox.pack(pady=5)

        # --- Share Price Frame widgets ---
        ttk.Label(share_price_frame, text="Share Price Chart", font=TITLE_FONT).pack(pady=(10, 5))
        ttk.Label(share_price_frame, text="Company Name:").pack()
        company_entry = ttk.Entry(share_price_frame)
        company_entry.pack()
        ttk.Button(share_price_frame, text="Show Chart", command=start_share_price).pack(pady=5)

        # --- Menu Bar ---
        menu_bar = tk.Menu(root)
        root.config(menu=menu_bar)
        section_menu = tk.Menu(menu_bar, tearoff=0)
        menu_bar.add_cascade(label="Menu", menu=section_menu)

        # Section switching with on_section_change to stop updates properly
        section_menu.add_command(label="General", command=lambda: on_section_change(general_frame))
        section_menu.add_command(label="Transaction", command=lambda: on_section_change(transaction_frame))
        section_menu.add_command(label="Stocks", command=lambda: on_section_change(stocks_frame))
        section_menu.add_command(label="Share Price", command=lambda: on_section_change(share_price_frame))

        # --- Initial load ---
        fetch_company_status()
        fetch_balance()
        fetch_stocks()
        show_frame(general_frame)

        # --- Initial loading ---
        fetch_company_status()
        fetch_balance()
        fetch_stocks()
        show_frame(general_frame)

VIDEO_PATH = "C:\LessSimpleBanking\media//videos//1080p60\LessSimpleBankingIntro.mp4"
play_intro_video(VIDEO_PATH, show_login_ui)

root.mainloop()
