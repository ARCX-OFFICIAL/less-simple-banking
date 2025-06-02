import os
import tkinter as tk
import requests
import random
from cryptography.hazmat.primitives.asymmetric import dsa
from cryptography.hazmat.primitives import hashes, serialization

server_url = "http://localhost:5000"
KEY_FILE = "client_private_key.pem"

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

# Dashboard
def open_dashboard(username):
    dashboard_frame = tk.Frame(root)
    dashboard_frame.pack()
    
    tk.Label(dashboard_frame, text=f"Welcome, {username}").pack()

    # --- Company Toggle Section ---
    company_var = tk.StringVar()
    investment_var = tk.StringVar()  # New: for displaying investment balance

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
        resp = requests.post(f"{server_url}/toggle_company", json={"username": username})
        fetch_company_status()
        fetch_balance()  # Also update investment balance

    tk.Label(dashboard_frame, textvariable=company_var, fg="blue").pack()
    tk.Button(dashboard_frame, text="Toggle Company Status", command=toggle_company).pack()
    fetch_company_status()

    balance_var = tk.StringVar()
    balance_label = tk.Label(dashboard_frame, textvariable=balance_var)
    balance_label.pack()

    # New: Investment balance label
    investment_label = tk.Label(dashboard_frame, textvariable=investment_var, fg="purple")
    investment_label.pack()

    def fetch_balance():
        response = requests.post(f"{server_url}/balance", json={"username": username})
        result = response.json()
        if result["status"] == "Success":
            balance_var.set(f"Current Balance: {result['balance']}")
            # Show investment balance if company
            if "investment_balance" in result:
                investment_var.set(f"Investment Money: {result['investment_balance']}")
            else:
                investment_var.set("")
        else:
            balance_var.set("Balance: Error")
            investment_var.set("")

    # --- STOCKS SECTION ---
    stocks_var = tk.StringVar()
    def fetch_stocks():
        # Use /my_stocks endpoint to get all your holdings
        resp = requests.post(f"{server_url}/my_stocks", json={"investor": username})
        info = resp.json()
        if info["status"] == "Success":
            holdings = []
            for account, shares in info["holdings"].items():
                holdings.append(f"{shares} shares in {account}")
            stocks_var.set("Your Stocks: " + (", ".join(holdings) if holdings else "None"))
        else:
            stocks_var.set("Your Stocks: Error")

    tk.Label(dashboard_frame, textvariable=stocks_var).pack()
    tk.Button(dashboard_frame, text="Reload Stocks", command=fetch_stocks).pack()

    # Buy Stock
    tk.Label(dashboard_frame, text="Buy Stock in Account:").pack()
    buy_account_entry = tk.Entry(dashboard_frame)
    buy_account_entry.pack()
    tk.Label(dashboard_frame, text="Shares:").pack()
    buy_shares_entry = tk.Entry(dashboard_frame)
    buy_shares_entry.pack()
    buy_result = tk.Label(dashboard_frame, text="")
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
    tk.Button(dashboard_frame, text="Buy Stock", command=buy_stock).pack()

    # Sell Stock
    tk.Label(dashboard_frame, text="Sell Stock in Account:").pack()
    sell_account_entry = tk.Entry(dashboard_frame)
    sell_account_entry.pack()
    tk.Label(dashboard_frame, text="Shares:").pack()
    sell_shares_entry = tk.Entry(dashboard_frame)
    sell_shares_entry.pack()
    sell_result = tk.Label(dashboard_frame, text="")
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
    tk.Button(dashboard_frame, text="Sell Stock", command=sell_stock).pack()

    # --- Transfer Section ---
    tk.Label(dashboard_frame, text="Transfer Currency").pack()
    tk.Label(dashboard_frame, text="Transfer To:").pack()
    receiver_entry = tk.Entry(dashboard_frame)
    receiver_entry.pack()

    tk.Label(dashboard_frame, text="Amount:").pack()
    amount_entry = tk.Entry(dashboard_frame)
    amount_entry.pack()

    transfer_result = tk.Label(dashboard_frame, text="")
    transfer_result.pack()

    def transfer():
        receiver = receiver_entry.get()
        amount = amount_entry.get()
        transaction_id = random.randint(100000, 999999)
        transaction_data = f"{username}-{receiver}-{amount}-{transaction_id}"
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

    tk.Button(dashboard_frame, text="Transfer", command=transfer).pack()
    tk.Button(dashboard_frame, text="Reload", command=fetch_balance).pack()
    

    # --- Pending Stock Sales Approval Section ---
    pending_var = tk.StringVar()
    pending_listbox = tk.Listbox(dashboard_frame, width=60)
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

    fetch_balance()  # Show balance on dashboard open
    fetch_stocks()   # Show stocks on dashboard open
    fetch_pending()  # Show pending requests on dashboard open

root.mainloop()