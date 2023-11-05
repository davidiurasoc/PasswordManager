import logging
from cryptography.fernet import Fernet
from datetime import datetime
import os
import base64

# Set up logging
logging.basicConfig(filename='password_manager.log', level=logging.INFO)

# Define a custom logger
logger = logging.getLogger('password_manager')


class ManagePassword:
    def __init__(self):
        self.passwords_saved = []
        self.mpass = None
        self.key = None
        self.master_pwd = None
        self.fer = None
        self.initialize()

    def initialize(self):
        # Initialize the password manager by loading the master password and encryption key
        self.load_key()
        self.load_master_password()
        self.fer = Fernet(self.key)
        self.load_saved_passwords()

    def load_saved_passwords(self):
        try:
            # Load saved passwords from the 'passwords.txt' file
            with open("passwords.txt", "r") as f:
                for line in f.readlines():
                    # Split the line into components
                    data = line.strip().split(" | ")
                    if len(data) == 4:
                        user, passw, date_created, last_modified = data
                        # Store the encrypted password in the list
                        self.passwords_saved.append((user, passw))
        except Exception as e:
            logger.error(f"Error loading saved passwords: {e}")

    def load_master_password(self):
        # Check if 'master_pass.txt' exists and load the master password if it does
        if os.path.exists("master_pass.txt"):
            with open("master_pass.txt", "rb") as pass_file:
                contents = pass_file.read()
                if contents:
                    # The file exists and contains data, so use the existing password
                    self.mpass = base64.b64decode(contents)
                else:
                    # The file exists but is empty, so create a new password
                    self.create_mpass()
                    # After creating a new master password, update the key
                    self.key = Fernet.generate_key()
                    with open("key.key", "wb") as key_file:
                        key_file.write(self.key)
        else:
            # The file doesn't exist, so create it and set a new password
            self.create_mpass()
            # After creating a new master password, update the key
            self.key = Fernet.generate_key()
            with open("key.key", "wb") as key_file:
                key_file.write(self.key)

    def create_mpass(self):
        # Create a new master password and save it to 'master_pass.txt'
        mpass = input("Please enter the master password for creation: ")
        with open("master_pass.txt", "wb") as pass_file:
            pass_file.write(base64.b64encode(mpass.encode()))
        logger.info("Created a new master password in master_pass.txt")
        self.master_pwd = mpass.encode()

    def enter_mpass(self):
        max_attempts = 3  # Set the maximum number of attempts
        for _ in range(max_attempts):
            mpass = input("Please enter the master password to log in: ")
            with open("master_pass.txt", "rb") as pass_file:
                stored_mpass = pass_file.read()
                if mpass.encode() == base64.b64decode(stored_mpass):
                    print("Login was successful")
                    logger.info("Login was successfull")
                    self.mpass = mpass
                    break
                else:
                    print("Invalid master password! Please try again...")
        else:
            print(f"Maximum number of attempts ({max_attempts}) reached. Exiting.")
            logger.error("Login was unsuccessfull! Entered wrong password for 3 times.")
            exit(1)

    def load_key(self):
        # Check if 'key.key' exists and load the encryption key if it does
        if os.path.exists("key.key") and os.path.getsize("key.key") > 0:
            with open("key.key", "rb") as file:
                key = file.read()
                logger.info("Loaded key from key.key")
                self.key = key
        else:
            # The file doesn't exist or is empty, so create a new encryption key
            self.create_key()

    def create_key(self):
        # Generate a new encryption key and save it to 'key.key'
        key = Fernet.generate_key()
        with open("key.key", "wb") as key_file:
            key_file.write(key)
        logger.info("Created a new key in key.key")
        self.key = key

    def add(self):
        name = input("Account Name: ")
        pwd = input("Password: ")
        current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        with open("passwords.txt", "a") as f:
            encrypted_pwd = self.fer.encrypt(pwd.encode()).decode()  # Encrypt and decode the password
            f.write(f"{name} | {encrypted_pwd} | {current_time} | {current_time}\n")
        logger.info(f"Added password for Account Name: {name}")
        print(f"Password for Account Name '{name}' added.")
        self.passwords_saved.append((name, encrypted_pwd))  # Append to the list

    def view(self):
        if not self.passwords_saved:
            print("No passwords have been saved.")
            return

        print("Stored Passwords:")
        for name, encrypted_pwd in self.passwords_saved:
            decrypted_passw = self.fer.decrypt(encrypted_pwd.encode()).decode()
            print("User:", name, "| Password:", decrypted_passw)

        print(f"There are: {len(self.passwords_saved)} password(s) saved.")

    def run(self):
        self.enter_mpass()  # Prompt for the master password

        while True:
            mode = input(
                "Would you like to add a new password or view existing ones ('view', 'add')? - press 'q' to quit: ").lower()
            if mode == "q":
                break
            if mode == "view":
                self.view()
            elif mode == "add":
                self.add()
            else:
                print("Invalid mode.")
                continue


if __name__ == "__main__":
    os.system('cls' if os.name == 'nt' else 'clear')
    password_manager = ManagePassword()
    password_manager.run()
