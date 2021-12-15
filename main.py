import rsa
from Crypto.PublicKey import ECC
from Crypto import PublicKey

CHATROOM_ITERATOR = 0

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
    '''
    encoded addressed message class
    '''
    def __init__(self, encoded_message, sender, encoding):
        self.encoded_message = encoded_message
        self.sender = sender
        self.encoding = encoding


def encode_message(message: str, encoding: str, receiver_public_key: PublicKey) -> bytes:
    '''
    encodes messages
    Inputs:
    message - plain text
    encoding - encoding type
    receiver_public_key - key to encode with
    Returns:
    encoded message
    '''
    utf8_message = message.encode('utf8')
    encoded_message = encryption_dictionary[encoding](utf8_message, receiver_public_key)
    return encoded_message


class User:
    '''
    user class
    '''
    def __init__(self, name):
        if name in user_dictionary:
            print(f"such user already exists")
            raise Exception("user already  exists")
        public_key_RSA, private_key_RSA = rsa.newkeys(512)
        self.private_key_dictionary = {
            "RSA": private_key_RSA,
            "ECC": ECC.generate(curve='P-256'),
        }
        self.public_key_dictionary = {
            "RSA": public_key_RSA
        }

        self.name = name
        self.messages_received = list()

    def decode_message(self, message: Message):
        '''
        decodes message with user's private key
        Inputs:
        message - encoded message
        Returns:
        decoded plain text message
        '''
        decoded_message = decryption_dictionary[message.encoding](message.encoded_message, self.private_key_dictionary[message.encoding])
        return decoded_message.decode('utf8')

    def receive_message(self, encoded_message: Message):
        '''
        appends a message to user's received list
        Inputs:
        encoded_message - message object
        Returns:
        None
        '''
        self.messages_received.append(encoded_message)

    def show_messages(self):
        '''
        displays receied messages
        Inputs:
        None
        Returns:
        None
        '''
        for message in self.messages_received:
            print(f"'{self.decode_message(message)}' :message from {message.sender.name}")


def send_message(message: str, receiver: User, sender: User, encoding: str):
    '''
    sends a message to the receiver
    Inputs:
    message - plain text message
    receiver - receiving user
    sender - sending user
    encoding - encoding type
    Returns:
    None
    '''
    user_dictionary[receiver.name] = receiver
    encoded_message = Message(encode_message(message, encoding, receiver.public_key_dictionary[encoding]), sender,
                              encoding)

    receiver.receive_message(encoded_message)


while True:
    user = input("select user: ")
    if user not in user_dictionary:
        user_dictionary[user] = User(user)
    user_dictionary.get(user).show_messages()
    action = input("1-> send message 2-> logout, 3-> exit")
    if action == '1':
        message = input("what is the message: ")
        receiver = input("who is the receiver: ")
        while 1:
            encoding = input("RSA or ECC")
            if encoding == "RSA" or encoding == "ECC":
                break

        if receiver not in user_dictionary:
            user_dictionary[receiver] = User(receiver)
        send_message(message, user_dictionary.get(receiver), user_dictionary.get(user), encoding)
    elif action == '3':
        quit()
    else:
        pass
