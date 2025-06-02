from flask import Flask, request, jsonify
from cryptography.hazmat.primitives.asymmetric import dsa
from cryptography.hazmat.primitives import hashes, serialization
import hashlib

app = Flask(__name__)

# Simulated Database
users = {}  # {"username": {"password": ..., "public_key": ..., "is_company": False, "investment_balance": 0}}
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
    
    users[username] = {"password": password, "public_key": public_key, "is_company": False, "investment_balance": 0}
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
    amount = int(data["amount"])
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

    # Calculate sender's regular balance (not investment)
    regular_balance = 0
    for tx in transactions:
        if tx["receiver"] == sender:
            regular_balance += int(tx["amount"])
        if tx["sender"] == sender:
            regular_balance -= int(tx["amount"])
    investment_balance = users[sender].get("investment_balance", 0)
    total_balance = regular_balance + investment_balance

    if total_balance < amount:
        return jsonify({"status": "Failure", "message": "Insufficient funds"})

    # Deduct from investment_balance first, then from regular balance
    deduct_investment = min(investment_balance, amount)
    users[sender]["investment_balance"] -= deduct_investment
    deduct_regular = amount - deduct_investment
    if deduct_regular > 0:
        transactions.append({"sender": sender, "receiver": receiver, "amount": deduct_regular, "transaction_id": transaction_id})
    else:
        transactions.append({"sender": sender, "receiver": receiver, "amount": amount, "transaction_id": transaction_id})

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
            balance += int(tx["amount"])
        if tx["sender"] == username:
            balance -= int(tx["amount"])
    investment_balance = users[username].get("investment_balance", 0)
    return jsonify({"status": "Success", "balance": balance + investment_balance, "investment_balance": investment_balance})

@app.route("/buy_stock", methods=["POST"])
def buy_stock():
    data = request.json
    investor = data["investor"]
    account = data["account"]
    shares = int(data["shares"])
    if investor not in users or account not in users:
        return jsonify({"status": "Failure", "message": "Invalid investor or account"})
    if shares <= 0:
        return jsonify({"status": "Failure", "message": "Shares must be positive"})
    # Only allow buying stock in companies
    if not users[account].get("is_company", False):
        return jsonify({"status": "Failure", "message": "You can only invest in companies"})
    # Calculate investor balance (main + investment)
    balance = 0
    for tx in transactions:
        if tx["receiver"] == investor:
            balance += int(tx["amount"])
        if tx["sender"] == investor:
            balance -= int(tx["amount"])
    balance += users[investor].get("investment_balance", 0)
    # Calculate company regular balance for price
    company_balance = 0
    for tx in transactions:
        if tx["receiver"] == account:
            company_balance += int(tx["amount"])
        if tx["sender"] == account:
            company_balance -= int(tx["amount"])
    price_per_share = company_balance / 100 if company_balance > 0 else 0
    if price_per_share <= 0:
        return jsonify({"status": "Failure", "message": "Company has no value, cannot buy shares"})
    total_cost = shares * price_per_share
    if balance < total_cost:
        return jsonify({"status": "Failure", "message": "Insufficient funds"})
    # Company must have enough shares to sell (max 100, decremented on sale)
    owned = stocks.get(account, {}).get(account, 0)
    if owned < shares:
        return jsonify({"status": "Failure", "message": "Company does not have enough shares to sell"})
    stocks[account][account] -= shares
    if stocks[account][account] == 0:
        del stocks[account][account]
    # Deduct from investor's investment_balance first, then main balance
    deduct = min(users[investor].get("investment_balance", 0), total_cost)
    users[investor]["investment_balance"] -= deduct
    remaining = total_cost - deduct
    # If remaining amount is greater than 0, record a transaction
    if remaining > 0:
        transactions.append({"sender": investor, "receiver": account, "amount": remaining, "transaction_id": f"buy_{investor}_{account}_{len(transactions)}"})
    # Do NOT add to company's main balance, only to investment_balance
    # Do NOT record a transaction for this investment (so main balance doesn't increase)
    users[account]["investment_balance"] += total_cost
    if investor not in stocks:
        stocks[investor] = {}
    stocks[investor][account] = stocks[investor].get(account, 0) + shares
    return jsonify({"status": "Success", "message": f"Stock purchase successful. {investor} now owns {shares} shares in {account} at {price_per_share} per share."})

@app.route("/pending_stock_sales", methods=["POST"])
def pending_stock_sales_view():
    data = request.json
    account = data["account"]
    # Only show pending requests for non-companies (companies have no pending sales)
    if users.get(account, {}).get("is_company", False):
        return jsonify({"status": "Success", "pending": []})
    requests = [req for req in pending_stock_sales if req["account"] == account]
    return jsonify({"status": "Success", "pending": requests})

@app.route("/approve_stock_sale", methods=["POST"])
def approve_stock_sale():
    data = request.json
    account = data["account"]
    request_id = data["request_id"]
    approve = data["approve"]  # True/False
    balance = 0
    for tx in transactions:
        if tx["receiver"] == investor:
            balance += int(tx["amount"])
        if tx["sender"] == investor:
            balance -= int(tx["amount"])
    # If account is a company, do not allow approval (should not happen)
    if users.get(account, {}).get("is_company", False):
        return jsonify({"status": "Failure", "message": "Company accounts do not require approval"})
    # Find the pending request
    req = next((r for r in pending_stock_sales if r["request_id"] == request_id and r["account"] == account), None)
    if not req:
        return jsonify({"status": "Failure", "message": "Request not found"})
    if not approve:
        pending_stock_sales.remove(req)
        return jsonify({"status": "Rejected", "message": "Stock sale rejected"})
    investor = req["investor"]
    shares = req["shares"]
    total_cost = req["total_cost"]
    if investor not in users or account not in users:
        pending_stock_sales.remove(req)
        return jsonify({"status": "Failure", "message": "Invalid investor or account"})

    balance += users[investor].get("investment_balance", 0)
    if balance < total_cost:
        pending_stock_sales.remove(req)
        return jsonify({"status": "Failure", "message": "Investor has insufficient funds"})
    # Account must have enough shares to sell (if not SYSTEM)
    if account != "SYSTEM":
        owned = stocks.get(account, {}).get(account, 0)
        if owned < shares:
            pending_stock_sales.remove(req)
            return jsonify({"status": "Failure", "message": "Account does not have enough shares to sell"})
        stocks[account][account] -= shares
        if stocks[account][account] == 0:
            del stocks[account][account]
    transactions.append({"sender": investor, "receiver": account, "amount": total_cost, "transaction_id": f"buy_{investor}_{account}_{len(transactions)}"})
    if investor not in stocks:
        stocks[investor] = {}
    stocks[investor][account] = stocks[investor].get(account, 0) + shares
    pending_stock_sales.remove(req)
    return jsonify({"status": "Success", "message": f"Stock sale approved. {investor} now owns {shares} shares in {account}."})

@app.route("/sell_stock", methods=["POST"])
def sell_stock():
    data = request.json
    investor = data["investor"]
    account = data["account"]
    shares = int(data["shares"])
    # Calculate company regular balance for price
    company_balance = 0
    for tx in transactions:
        if tx["receiver"] == account:
            company_balance += int(tx["amount"])
        if tx["sender"] == account:
            company_balance -= int(tx["amount"])
    if investor not in users or account not in users:
        return jsonify({"status": "Failure", "message": "Invalid investor or account"})
    if shares <= 0:
        return jsonify({"status": "Failure", "message": "Shares must be positive"})
    owned = stocks.get(investor, {}).get(account, 0)
    if owned < shares:
        return jsonify({"status": "Failure", "message": "Not enough shares to sell"})
    # Only allow selling to companies
    if not users[account].get("is_company", False):
        return jsonify({"status": "Failure", "message": "You can only sell shares of companies"})
    price_per_share = company_balance / 100 if company_balance > 0 else 0
    if price_per_share <= 0:
        return jsonify({"status": "Failure", "message": "Company has no value, cannot sell shares"})
    total_payout = shares * price_per_share
    print(f"Total payout for {shares} shares at {price_per_share} per share: {total_payout}")
    # Check if company has enough regular balance
    if company_balance < total_payout:
        return jsonify({"status": "Failure", "message": "Company does not have enough regular funds to buy back shares"})

    # Remove shares from investor
    stocks[investor][account] -= shares
    if stocks[investor][account] == 0:
        del stocks[investor][account]
    # Return shares to company
    if account not in stocks:
        stocks[account] = {}
    stocks[account][account] = stocks[account].get(account, 0) + shares
    # Pay investor from company's regular balance (record transaction)
    transactions.append({"sender": account, "receiver": investor, "amount": total_payout, "transaction_id": f"sell_{investor}_{account}_{len(transactions)}"})
    return jsonify({"status": "Success", "message": f"Sold {shares} shares of {account} at {price_per_share} per share."})

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

if __name__ == "__main__":
    app.run(port=5000, debug=True)
