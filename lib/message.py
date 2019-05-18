
class Message:
    def __init__(self, payload):
        self.payload = payload
        self.read = False
        self.sent = False