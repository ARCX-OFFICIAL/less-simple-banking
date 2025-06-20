import os
import tkinter as tk
import requests
import random
from cryptography.hazmat.primitives.asymmetric import dsa
from cryptography.hazmat.primitives import hashes, serialization
# Add matplotlib imports
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import matplotlib.pyplot as plt
import threading
import time

server_url = "http://localhost:5000"
KEY_FILE = "client_private_key.pem"
client_private_key = KEY_FILE

# Load or generate Client's DSA Private Key and save/load from file
if os.path.exists(KEY_FILE):
    with open(KEY_FILE, "rb") as key_file:
        client_private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=None,
        )
else:
    client_private_key = dsa.generate_private_key(key_size=2048)
    with open(KEY_FILE, "wb") as key_file:
        key_file.write(
            client_private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )
client_public_key = client_private_key.public_key()

root = tk.Tk()
root.title("Banking System")

# Registration Frame
register_frame = tk.Frame(root)
register_frame.pack()

tk.Label(register_frame, text="New Username:").grid(row=0, column=0)
new_username_entry = tk.Entry(register_frame)
new_username_entry.grid(row=0, column=1)

tk.Label(register_frame, text="New Password:").grid(row=1, column=0)
new_password_entry = tk.Entry(register_frame, show="*")
new_password_entry.grid(row=1, column=1)

def register():
    new_username = new_username_entry.get()
    new_password = new_password_entry.get()
    if len(new_username) < 3 or len(new_password) < 6:
        tk.Label(register_frame, text="Username must be at least 3 characters and password at least 6 characters", fg="red").grid(row=2, columnspan=2)
        return
    # Serialize public key to PEM format
    public_key_pem = client_public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode()
    response = requests.post(
        f"{server_url}/register",
        json={
            "username": new_username,
            "password": new_password,
            "public_key": public_key_pem
        }
    )
    result = response.json()
    if result["status"] == "Success":
        tk.Label(register_frame, text="Registration Successful!", fg="green").grid(row=2, columnspan=2)
        register_frame.pack_forget()
    else:
        tk.Label(register_frame, text="Registration Failed", fg="red").grid(row=2, columnspan=2)

tk.Button(register_frame, text="Register", command=register).grid(row=3, columnspan=2)

# Login Frame
login_frame = tk.Frame(root)
login_frame.pack()

tk.Label(login_frame, text="Username:").grid(row=0, column=0)
username_entry = tk.Entry(login_frame)
username_entry.grid(row=0, column=1)

tk.Label(login_frame, text="Password:").grid(row=1, column=0)
password_entry = tk.Entry(login_frame, show="*")
password_entry.grid(row=1, column=1)

def login():
    username = username_entry.get()
    password = password_entry.get()
    response = requests.post(f"{server_url}/login", json={"username": username, "password": password})
    result = response.json()
    
    if result["status"] == "Success":
        login_frame.pack_forget()
        register_frame.pack_forget()
        tk.Label(root, text="Login Successful!", fg="green").pack()
        open_dashboard(username)
    else:
        tk.Label(login_frame, text="Login Failed", fg="red").grid(row=2, columnspan=2)

tk.Button(login_frame, text="Login", command=login).grid(row=3, columnspan=2)

def open_dashboard(username):
    dashboard_frame = tk.Frame(root)
    dashboard_frame.pack()

    # --- Menu Bar ---
    menu_bar = tk.Menu(root)
    root.config(menu=menu_bar)
    section_menu = tk.Menu(menu_bar, tearoff=0)
    menu_bar.add_cascade(label="Menu", menu=section_menu)

    # --- Frames for each section ---
    general_frame = tk.Frame(dashboard_frame)
    transaction_frame = tk.Frame(dashboard_frame)
    stocks_frame = tk.Frame(dashboard_frame)
    # Add share price frame
    share_price_frame = tk.Frame(dashboard_frame)

    # --- General Section ---
    tk.Label(general_frame, text=f"Welcome, {username}").pack()

    company_var = tk.StringVar()
    investment_var = tk.StringVar()

    def fetch_balance():
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

    def fetch_company_status():
        resp = requests.post(f"{server_url}/is_company", json={"username": username})
        result = resp.json()
        if result["status"] == "Success":
            if result["is_company"]:
                company_var.set("This account is a COMPANY")
            else:
                company_var.set("This account is a PERSONAL account")
        else:
            company_var.set("Error loading company status")

    def toggle_company():
        requests.post(f"{server_url}/toggle_company", json={"username": username})
        fetch_company_status()
        fetch_balance()

    tk.Label(general_frame, textvariable=company_var, fg="blue").pack()
    tk.Button(general_frame, text="Toggle Company Status", command=toggle_company).pack()

    balance_var = tk.StringVar()
    tk.Label(general_frame, textvariable=balance_var).pack()
    tk.Label(general_frame, textvariable=investment_var, fg="purple").pack()
    tk.Button(general_frame, text="Reload Balance", command=fetch_balance).pack()

    # --- Transaction Section ---
    tk.Label(transaction_frame, text="Transfer Currency").pack()
    tk.Label(transaction_frame, text="Transfer To:").pack()
    receiver_entry = tk.Entry(transaction_frame)
    receiver_entry.pack()
    tk.Label(transaction_frame, text="Amount:").pack()
    amount_entry = tk.Entry(transaction_frame)
    amount_entry.pack()
    transfer_result = tk.Label(transaction_frame, text="")
    transfer_result.pack()

    def transfer():
        receiver = receiver_entry.get()
        amount = amount_entry.get()
        transaction_id = random.randint(100000, 999999)
        transaction_data = f"{username}-{receiver}-{float(amount)}-{transaction_id}"
        signature = client_private_key.sign(transaction_data.encode(), hashes.SHA256())

        response = requests.post(f"{server_url}/transfer_currency", json={
            "sender": username,
            "receiver": receiver,
            "amount": amount,
            "transaction_id": transaction_id,
            "signature": signature.hex()
        })
        
        message = response.json()["message"]
        if message == "Transaction successful!":
            transfer_result.config(text=message, fg="green")
        else:
            transfer_result.config(text=message, fg="red")
        fetch_balance()  # Update balance after transfer

    tk.Button(transaction_frame, text="Transfer", command=transfer).pack()
    tk.Button(transaction_frame, text="Reload Balance", command=fetch_balance).pack()

    # --- Stocks Section ---
    stocks_var = tk.StringVar()
    tk.Label(stocks_frame, textvariable=stocks_var).pack()
    tk.Button(stocks_frame, text="Reload Stocks", command=lambda: fetch_stocks()).pack()

    tk.Label(stocks_frame, text="Buy Stock in Account:").pack()
    buy_account_entry = tk.Entry(stocks_frame)
    buy_account_entry.pack()
    tk.Label(stocks_frame, text="Shares:").pack()
    buy_shares_entry = tk.Entry(stocks_frame)
    buy_shares_entry.pack()
    buy_result = tk.Label(stocks_frame, text="")
    buy_result.pack()

    def buy_stock():
        account = buy_account_entry.get()
        shares = buy_shares_entry.get()
        try:
            shares = int(shares)
        except:
            buy_result.config(text="Invalid share number", fg="red")
            return
        resp = requests.post(f"{server_url}/buy_stock", json={
            "investor": username,
            "account": account,
            "shares": shares
        })
        result = resp.json()
        if result["status"] == "Success":
            buy_result.config(text=result["message"], fg="green")
        elif result["status"] == "Pending":
            buy_result.config(text=result["message"], fg="orange")
        else:
            buy_result.config(text=result["message"], fg="red")
        fetch_balance()
        fetch_stocks()

    tk.Button(stocks_frame, text="Buy Stock", command=buy_stock).pack()

    tk.Label(stocks_frame, text="Sell Stock in Account:").pack()
    sell_account_entry = tk.Entry(stocks_frame)
    sell_account_entry.pack()
    tk.Label(stocks_frame, text="Shares:").pack()
    sell_shares_entry = tk.Entry(stocks_frame)
    sell_shares_entry.pack()
    sell_result = tk.Label(stocks_frame, text="")
    sell_result.pack()

    def sell_stock():
        account = sell_account_entry.get()
        shares = sell_shares_entry.get()
        try:
            shares = int(shares)
        except:
            sell_result.config(text="Invalid share number", fg="red")
            return
        resp = requests.post(f"{server_url}/sell_stock", json={
            "investor": username,
            "account": account,
            "shares": shares
        })
        result = resp.json()
        if result["status"] == "Success":
            sell_result.config(text=result["message"], fg="green")
        else:
            sell_result.config(text=result["message"], fg="red")
        fetch_balance()
        fetch_stocks()

    tk.Button(stocks_frame, text="Sell Stock", command=sell_stock).pack()

    # Pending Stock Sales Approval Section
    pending_listbox = tk.Listbox(stocks_frame, width=60)
    pending_listbox.pack()
    def fetch_pending():
        resp = requests.post(f"{server_url}/pending_stock_sales", json={"account": username})
        info = resp.json()
        pending_listbox.delete(0, tk.END)
        if info["status"] == "Success":
            for req in info["pending"]:
                txt = f"From: {req['investor']} | Shares: {req['shares']} | Cost: {req['total_cost']} | ID: {req['request_id']}"
                pending_listbox.insert(tk.END, txt)
        else:
            pending_listbox.insert(tk.END, "Error loading pending requests")

    def fetch_stocks():
        resp = requests.post(f"{server_url}/my_stocks", json={"investor": username})
        info = resp.json()
        if info["status"] == "Success":
            holdings = []
            for account, shares in info["holdings"].items():
                holdings.append(f"{shares} shares in {account}")
            stocks_var.set("Your Stocks: " + (", ".join(holdings) if holdings else "None"))
        else:
            stocks_var.set("Your Stocks: Error")
        fetch_pending()

    # --- Share Price Section ---
    tk.Label(share_price_frame, text="Share Price Chart", font=("Segoe UI", 14, "bold")).pack(pady=(10, 5))
    tk.Label(share_price_frame, text="Company Name:").pack()
    company_entry = tk.Entry(share_price_frame)
    company_entry.pack()
    chart_canvas = None
    fig = None
    ax = None
    price_history = []
    time_history = []
    update_thread = None
    stop_update = threading.Event()

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
        # Create figure and axis only once
        if fig is None or ax is None:
            fig, ax = plt.subplots(figsize=(5, 2.5), dpi=100)
            fig.tight_layout()
        ax.clear()
        ax.plot(time_history, price_history, marker='o', color='blue')
        ax.set_title(f"Share Price: {company}")
        ax.set_xlabel("Time")
        ax.set_ylabel("Price")
        ax.tick_params(axis='x', rotation=45)
        ax.set_ylim(0, 200)  # Set y-axis range
        ax.set_xlim(0, 100)
        # Always ensure chart_canvas uses the current fig
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

    tk.Button(share_price_frame, text="Show Chart", command=start_share_price).pack(pady=5)

    def stop_share_price():
        stop_update.set()

    # --- Section switching logic ---
    def show_frame(frame):
        for f in [general_frame, transaction_frame, stocks_frame, share_price_frame]:
            f.pack_forget()
        frame.pack(fill="both", expand=True)

    section_menu.add_command(label="General", command=lambda: show_frame(general_frame))
    section_menu.add_command(label="Transaction", command=lambda: show_frame(transaction_frame))
    section_menu.add_command(label="Stocks", command=lambda: show_frame(stocks_frame))
    section_menu.add_command(label="Share Price", command=lambda: show_frame(share_price_frame))

    # --- Initial load ---
    fetch_company_status()
    fetch_balance()
    fetch_stocks()
    show_frame(general_frame)

    # Stop share price updates when switching away
    def on_section_change(frame):
        if frame != share_price_frame:
            stop_share_price()
        show_frame(frame)

    # Replace section_menu commands to use on_section_change
    section_menu.entryconfig("General", command=lambda: on_section_change(general_frame))
    section_menu.entryconfig("Transaction", command=lambda: on_section_change(transaction_frame))
    section_menu.entryconfig("Stocks", command=lambda: on_section_change(stocks_frame))
    section_menu.entryconfig("Share Price", command=lambda: on_section_change(share_price_frame))