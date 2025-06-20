from flask import Flask, request, jsonify
from cryptography.hazmat.primitives.asymmetric import dsa
from cryptography.hazmat.primitives import hashes, serialization
import hashlib

app = Flask(__name__)

import json

DATA_FILE = "server_data.json"

# Simulated Database
users = {}  # {"username": {"password": ..., "public_key": ..., "is_company": False}}
transactions = []  # Stores transactions
INITIAL_BALANCE = 50  # New accounts start with 50

# Stocks: {investor: {account: shares}}
stocks = {}  # e.g., {"alice": {"bob": 3, "charlie": 2}}

pending_stock_sales = []  # Each item: {"investor": ..., "account": ..., "shares": ..., "request_id": ...}


def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

@app.route("/register", methods=["POST"])
def register():
    data = request.json
    username = data["username"]
    password = hash_password(data["password"])
    public_key_pem = data.get("public_key")
    
    if username in users:
        return jsonify({"status": "Failure", "message": "Username already exists"})
    
    # Load public key from PEM
    try:
        public_key = serialization.load_pem_public_key(public_key_pem.encode())
    except Exception as e:
        return jsonify({"status": "Failure", "message": "Invalid public key"})
    
    users[username] = {"password": password, "public_key": public_key, "is_company": False}
    # Give initial balance by creating a "system" transaction
    transactions.append({"sender": "SYSTEM", "receiver": username, "amount": INITIAL_BALANCE, "transaction_id": f"init_{username}"})

    return jsonify({"status": "Success", "message": "Account created!"})

@app.route("/toggle_company", methods=["POST"])
def toggle_company():
    data = request.json
    username = data["username"]
    if username not in users:
        return jsonify({"status": "Failure", "message": "Invalid username"})
    users[username]["is_company"] = not users[username].get("is_company", False)
    # If toggling ON, initialize company shares to 100 if not already set
    if users[username]["is_company"]:
        if username not in stocks:
            stocks[username] = {}
        # Only set if not already set
        if stocks[username].get(username, None) is None:
            stocks[username][username] = 100
    return jsonify({"status": "Success", "is_company": users[username]["is_company"]})

@app.route("/is_company", methods=["POST"])
def is_company():
    data = request.json
    username = data["username"]
    if username not in users:
        return jsonify({"status": "Failure", "message": "Invalid username"})
    return jsonify({"status": "Success", "is_company": users[username].get("is_company", False)})

@app.route("/login", methods=["POST"])
def login():
    data = request.json
    username = data["username"]
    password = hash_password(data["password"])
    
    if username not in users or users[username]["password"] != password:
        return jsonify({"status": "Failure", "message": "Invalid username or password"})
    
    return jsonify({"status": "Success", "message": "Login successful!"})

@app.route("/transfer_currency", methods=["POST"])
def transfer_currency():
    data = request.json
    sender = data["sender"]
    receiver = data["receiver"]
    amount = float(data["amount"])
    transaction_id = data["transaction_id"]
    signature = bytes.fromhex(data["signature"])  # Convert back to bytes

    if sender not in users or receiver not in users:
        return jsonify({"status": "Failure", "message": "Invalid sender or receiver"})

    # Ensure identical encoding before verification
    transaction_data = f"{sender}-{receiver}-{amount}-{transaction_id}".encode()

    sender_public_key = users[sender]["public_key"]
    try:
        sender_public_key.verify(signature, transaction_data, hashes.SHA256())
    except Exception as e:
        return jsonify({"status": "Failure", "message": "Invalid signature"})

    # Calculate sender's balance
    balance = 0
    for tx in transactions:
        if tx["receiver"] == sender:
            balance += float(tx["amount"])
        if tx["sender"] == sender:
            balance -= float(tx["amount"])

    if balance < amount:
        return jsonify({"status": "Failure", "message": "Insufficient funds"})

    transactions.append({
        "sender": sender,
        "receiver": receiver,
        "amount": amount,
        "transaction_id": transaction_id
    })

    return jsonify({"status": "Success", "message": "Transaction successful!"})
@app.route("/balance", methods=["POST"])
def balance():
    data = request.json
    username = data["username"]
    if username not in users:
        return jsonify({"status": "Failure", "message": "Invalid username"})
    # Calculate balance: +amount for received, -amount for sent
    balance = 0
    for tx in transactions:
        if tx["receiver"] == username:
            balance += float(tx["amount"])
        if tx["sender"] == username:
            balance -= float(tx["amount"])
    return jsonify({"status": "Success", "balance": balance})

@app.route("/buy_stock", methods=["POST"])
def buy_stock():
    data = request.json
    investor = data["investor"]
    account = data["account"]
    shares = float(data["shares"])
    if investor not in users or account not in users:
        return jsonify({"status": "Failure", "message": "Invalid investor or account"})
    if shares <= 0 or int(shares) != shares:
        return jsonify({"status": "Failure", "message": "Shares must be a positive integer"})
    shares = int(shares)
    # Only allow buying stock in companies
    if not users[account].get("is_company", False):
        return jsonify({"status": "Failure", "message": "You can only invest in companies"})
    # Calculate investor balance
    balance = 0
    for tx in transactions:
        if tx["receiver"] == investor:
            balance += float(tx["amount"])
        if tx["sender"] == investor:
            balance -= float(tx["amount"])
    # Company must have enough shares to sell (max 100, decremented on sale)
    owned = stocks.get(account, {}).get(account, 0)
    if owned < shares:
        return jsonify({"status": "Failure", "message": "Company does not have enough shares to sell"})
    total_cost = 0
    for i in range(shares):
        # Calculate company regular balance for price
        company_balance = 0
        for tx in transactions:
            if tx["receiver"] == account:
                company_balance += float(tx["amount"])
            if tx["sender"] == account:
                company_balance -= float(tx["amount"])
        price_per_share = company_balance / 100 * (0.5 + (100 - stocks.get(account, {}).get(account, 0)) / 100) if company_balance > 0 else 0
        if price_per_share <= 0:
            return jsonify({"status": "Failure", "message": "Company has no value, cannot buy shares"})
        if balance < price_per_share:
            return jsonify({"status": "Failure", "message": "Insufficient funds"})
        # Deduct one share
        stocks[account][account] -= 1
        if stocks[account][account] == 0:
            del stocks[account][account]
        # Payment goes to company
        transactions.append({"sender": investor, "receiver": account, "amount": price_per_share, "transaction_id": f"buy_{investor}_{account}_{len(transactions)}"})
        if investor not in stocks:
            stocks[investor] = {}
        stocks[investor][account] = stocks[investor].get(account, 0) + 1
        balance -= price_per_share
        total_cost += price_per_share
    return jsonify({"status": "Success", "message": f"Stock purchase successful. {investor} bought {shares} shares in {account} for a total of {total_cost}."})

@app.route("/sell_stock", methods=["POST"])
def sell_stock():
    data = request.json
    investor = data["investor"]
    account = data["account"]
    shares = float(data["shares"])
    if investor not in users or account not in users:
        return jsonify({"status": "Failure", "message": "Invalid investor or account"})
    if shares <= 0 or int(shares) != shares:
        return jsonify({"status": "Failure", "message": "Shares must be a positive integer"})
    shares = int(shares)
    owned = stocks.get(investor, {}).get(account, 0)
    if owned < shares:
        return jsonify({"status": "Failure", "message": "Not enough shares to sell"})
    # Only allow selling to companies
    if not users[account].get("is_company", False):
        return jsonify({"status": "Failure", "message": "You can only sell shares of companies"})
    total_payout = 0
    for i in range(shares):
        # Calculate company regular balance for price
        company_balance = 0
        for tx in transactions:
            if tx["receiver"] == account:
                company_balance += float(tx["amount"])
            if tx["sender"] == account:
                company_balance -= float(tx["amount"])
        price_per_share = company_balance / 100 * (0.5 + (100 - stocks.get(account, {}).get(account, 0)) / 100) if company_balance > 0 else 0
        if price_per_share <= 0:
            return jsonify({"status": "Failure", "message": "Company has no value, cannot sell shares"})
        if company_balance < price_per_share:
            return jsonify({"status": "Failure", "message": "Company does not have enough regular funds to buy back shares"})
        # Remove one share from investor
        stocks[investor][account] -= 1
        if stocks[investor][account] == 0:
            del stocks[investor][account]
        # Return one share to company
        if account not in stocks:
            stocks[account] = {}
        stocks[account][account] = stocks[account].get(account, 0) + 1
        # Pay investor from company's regular balance (record transaction)
        transactions.append({"sender": account, "receiver": investor, "amount": price_per_share, "transaction_id": f"sell_{investor}_{account}_{len(transactions)}"})
        total_payout += price_per_share
    return jsonify({"status": "Success", "message": f"Sold {shares} shares of {account} for a total of {total_payout}."})

@app.route("/stock_info", methods=["POST"])
def stock_info():
    data = request.json
    account = data["account"]
    if account not in users:
        return jsonify({"status": "Failure", "message": "Invalid account"})
    # Gather all investors and their shares in this account
    info = {}
    for investor, holdings in stocks.items():
        if account in holdings:
            info[investor] = holdings[account]
    return jsonify({"status": "Success", "account": account, "investors": info})

@app.route("/my_stocks", methods=["POST"])
def my_stocks():
    data = request.json
    investor = data["investor"]
    if investor not in users:
        return jsonify({"status": "Failure", "message": "Invalid investor"})
    holdings = stocks.get(investor, {})
    return jsonify({"status": "Success", "holdings": holdings})

@app.route("/share_price", methods=["POST"])
def share_price():
    data = request.json
    company = data["company"]
    if company not in users or not users[company].get("is_company", False):
        return jsonify({"status": "Failure", "message": "Invalid company"})
    # Calculate company regular balance for price
    company_balance = 0
    for tx in transactions:
        if tx["receiver"] == company:
            company_balance += float(tx["amount"])
        if tx["sender"] == company:
            company_balance -= float(tx["amount"])
    shares_left = stocks.get(company, {}).get(company, 0)
    price = company_balance / 100 * (0.5 + (100 - shares_left) / 100) if company_balance > 0 else 0
    return jsonify({"status": "Success", "price": price})

if __name__ == "__main__":
    app.run(port=5000, debug=True)