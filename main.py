import rsa
from Crypto.PublicKey import ECC
from Crypto import PublicKey

CHATROOM_ITERATOR = 0
USER_ITERATOR = 0

encryption_dictionary = {
    "RSA": rsa.encrypt,
    "ECC": ""
}

decryption_dictionary = {
    "RSA": rsa.decrypt,
    "ECC": ""
}



user_dictionary = dict()


class Message:

    def __init__(self, encoded_message, sender, encoding):
        self.encoded_message = encoded_message
        self.sender = sender
        self.encoding = encoding


def encode_message(message: str, encoding: str, receiver_public_key: PublicKey) -> bytes:
    utf8_message = message.encode('utf8')
    encoded_message = encryption_dictionary[encoding](utf8_message, receiver_public_key)
    return encoded_message


class User:
    def __init__(self):
        global USER_ITERATOR
        self.public_key_RSA, self.private_key_RSA = rsa.newkeys(512)
        self.private_key_ECC = ECC.generate(curve='P-256')
        self.public_key_ECC = self.private_key_ECC.public_key()
        self.id = USER_ITERATOR
        self.messages_received = list()
        USER_ITERATOR += 1

    def decode_message(self, message: bytes):
        decoded_message = rsa.decrypt(message, self.private_key_RSA)
        return decoded_message.decode('utf8')

    def receive_message(self, encoded_message: Message):
        self.messages_received.append(encoded_message)

    def show_messages(self):
        for message in self.messages_received:
            print(f"'{self.decode_message(message.encoded_message)}':message from {message.sender}")


def send_message(message: str, receiver: User, sender: User, encoding: str):
    encoded_message = Message(encode_message(message, encoding, receiver.public_key_RSA), sender, encoding)
    receiver.receive_message(encoded_message)


while True:
    user = int(input("select user: "))
    if user not in user_dictionary:
        user_dictionary[user] = User()
    user_dictionary.get(user).show_messages()
    action = input("select action, 1-> send message 2-> logout, 3-> exit")
    if action == '1':
        message = input("what is the message")
        receiver = int(input("who is the receiver, id()int"))
        send_message(message, user_dictionary.get(receiver), user_dictionary.get(user), "RSA")
    elif action == '3':
        quit()
    else:
        pass




