import base64

def encode(x):
    return base64.urlsafe_b64encode(x).decode()

def decode(x):
    return base64.urlsafe_b64decode(x)
    # return base64.urlsafe_b64decode(x).decode()
