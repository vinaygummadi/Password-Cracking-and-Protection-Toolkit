# Password-Cracking-and-Protection-Toolkit

## **Project Overview**
This project demonstrates the process of cracking weak passwords and educates users on securing passwords using modern practices. It includes examples of hashing, brute force attacks, dictionary attacks, strong password enforcement, and secure password storage using encryption. Additionally, the project includes RSA and AES encryption modules for enhanced password security.

---

## **Features**
1. **Password Hashing**
   - Demonstrates secure hashing using `hashlib` (SHA-256) and `bcrypt` with salting.
   - Allows password verification after hashing.

2. **Password Cracking**
   - Implements brute force attacks using Python and `itertools`.
   - Implements dictionary attacks using custom wordlists.

3. **Password Policy Enforcement**
   - Generates strong passwords using random combinations of letters, numbers, and symbols.
   - Enforces strong password policies.

4. **Secure Password Storage**
   - AES encryption for securely storing passwords using `cryptography.Fernet`.
   - RSA encryption and decryption for secure password handling.

5. **Interactive Tools**
   - Includes a CLI-based interactive menu for easy usage and testing of features.

---

## **Technologies Used**
- **Programming Language**: Python
- **Libraries**:
   - Hashing: `hashlib`, `bcrypt`
   - Password Policies: `random`, `string`
   - Encryption: `cryptography` (AES and RSA encryption)
- **Tools**:
   - Brute Force: `itertools`
   - Dictionary Attack: Reads from user-provided wordlists

---

## **Setup Instructions**

### **1. Clone the Repository**
```bash
git clone https://github.com/vinaygummadi/Password Cracking and Protection Toolkit.git
cd password-cracking-toolkit
```

### **2. Install Dependencies**
Ensure Python 3.7+ is installed. Install the required libraries:
```bash
pip install -r requirements.txt
```

### **3. Usage**

#### **a) Run the Interactive Toolkit**
The main menu provides access to all features:
```bash
python3 main.py
```
