from cryptography.fernet import Fernet


class PasswordManager:
    """Manager for encrypted password storage."""

    def __init__(self):
        self.key: bytes | None = None
        self.password_file: str | None = None
        self.password_dict: dict[str, str] = {}


    def create_key(self, path: str):
        """Create a key and save it into a file.

        Arguments:
            path -- The path to the file where the key will be saved.

        Raises:
            ValueError -- If path is not provided.
        """
        if path == "":
            raise ValueError(
                "Path not set. "
                "Provide a valid path to save the key."
            )
        
        self.key = Fernet.generate_key()
        with open(path, 'wb') as f:
            f.write(self.key)


    def load_key(self, path: str):
        """Load existing key from a file.

        Arguments:
            path -- The path to the file where the key is stored.
        Raises:
            ValueError -- If path is not provided or file not found.
        """
        try:
            with open(path, 'rb') as f:
                self.key = f.read()
        except FileNotFoundError:
            raise ValueError(
                f"Key file not found at {path}. "
                "Provide a valid path to load the key."
            )


    def create_password_file(
        self,
        path: str,
        initial_values: dict[str, str] | None = None
    ):
        """Create a new password file and optionally fill it with initial values.

        Arguments:
            path -- Path to the password file.
            initial_values -- Initial passwords and sites to add.
        Raises:
            ValueError -- If encryption key is not set or path is not provided.
        """
        if self.key is None:
            raise ValueError(
                "Encryption key not set. "
                "Call create_key() or load_key() first."
            )
        if path == "":
            raise ValueError(
                "Path not set. "
                "Provide a valid path to save the password file."
            )
        
        self.password_file = path

        if initial_values is not None:
            for key, value in initial_values.items():
                self.add_password(key, value)


    def load_password_file(self, path: str):
        """Load existing password file.

        Arguments:
            path -- Path to the existing password file.

        Raises:
            ValueError -- If encryption key is not set or path is not provided.
        """
        if self.key is None:
            raise ValueError(
                "Encryption key not set. "
                "Call create_key() or load_key() first."
            )
        if path == "":
            raise ValueError(
                "Path not set. "
                "Provide a valid path to load the password file."
            )

        self.password_file = path

        with open(path, 'r') as f:
            for line in f:
                site, encrypted = line.split(':')
                decrypted = Fernet(self.key).decrypt(encrypted.encode())
                self.password_dict[site] = decrypted.decode()


    def add_password(self, site: str, password: str):
        """Add a new password and site to the password file.

        Arguments:
            site -- The site for which the password is being added.
            password -- The password to add.

        Raises:
            ValueError -- If encryption key or password file is not set,
            or if password is too short, or site is not provided.
        """
        if self.key is None:
            raise ValueError(
                "Encryption key not set. "
                "Call create_key() or load_key() first."
            )
        if self.password_file is None or self.password_file == "":
            raise ValueError(
                "Password file not set. "
                "Call create_password_file() or load_password_file() first."
            )
        if len(password) < 4:
            raise ValueError("Password too short. Must be at least 4 characters.")
        if site == "":
            raise ValueError("Site not set. Provide a valid site name.")
        
        self.password_dict[site] = password

        with open(self.password_file, 'a+') as f:
            encrypted = Fernet(self.key).encrypt(password.encode())
            f.write(site + ":" + encrypted.decode() + "\n") 


    def get_password(self, site: str) -> str:
        """Get password for a given site.

        Arguments:
            site -- Site for which to return the password.

        Returns:
            The password for the given site.

        Raises:
            ValueError -- If no password found for the given site.
        """
        if site not in self.password_dict:
            raise ValueError(f"No password found for site: {site}")
        
        return self.password_dict[site]



def main():
    """Main function to run the password manager CLI."""
    my_password = {
        "email": "1234567",
        "facebook": "myfbpassword",
        "youtube": "helloworld123",
        "something": "myfavoritepassword_123"
    }

    pm = PasswordManager()
    print(
        "What do you want to do?\n"
        "1. Create new key\n"
        "2. Load existing key\n"
        "3. Create new password file\n"
        "4. Load existing password file\n"
        "5. Add new password\n"
        "6. Get password\n"
        "q. Quit"
    )

    done = False

    while not done:

        match input("Enter your choise: "):
            case "1":
                path = input("Enter path: ")
                pm.create_key(path)
            case "2":
                path = input("Enter path: ")
                pm.load_key(path)
            case "3":
                path = input("Enter path: ")
                pm.create_password_file(path, my_password)
            case "4":
                path = input("Enter path: ")
                pm.load_password_file(path)
            case "5":
                site = input("Enter the site: ")
                password = input("Enter the password: ")
                pm.add_password(site, password)
            case "6":
                site = input("What site do you want: ")
                print(f"Password for {site} is {pm.get_password(site)}")
            case "q":
                done = True
                print("Exiting...")
            case _:
                print("Invalid choice. Try again.")


# if __name__ == "__main__":
#     main()
man = PasswordManager()
man.load_key('a')
man.create_password_file('b.pass')
man.add_password('', '')
 