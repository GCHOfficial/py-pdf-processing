import random
import array
import string


class PasswordGenerator:
    def __init__(self):
        self.numbers = array.array("u", string.digits)
        self.letters_lower = array.array("u", string.ascii_lowercase)
        self.letters_upper = array.array("u", string.ascii_uppercase)
        self.symbols = array.array("u", string.punctuation)
        self.combined = (
            self.numbers + self.letters_lower + self.letters_upper + self.symbols
        )

    def generate_password(self):
        random_number = random.choice(self.numbers)
        random_lower = random.choice(self.letters_lower)
        random_upper = random.choice(self.letters_upper)
        random_symbol = random.choice(self.symbols)
        temp = random_number + random_lower + random_upper + random_symbol
        password = ""
        for num in range(8):
            temp = temp + random.choice(self.combined)
            temp_list = array.array("u", temp)
            random.shuffle(temp_list)
        for char in temp_list:
            password = password + char
        return password
