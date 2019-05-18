from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import dh

from lib.serial import encode, decode

DH_G = 2
DH_P = 11173079624332270584779013141183007699620771330975947079342182095878615993690126529835397203702022596679699701823502388945326714661378027038552480022150507


class DH_Wrapper:
    def __init__(self):
        self.pn = dh.DHParameterNumbers(DH_P, DH_G)
        parameters = self.pn.parameters(default_backend())
        self.private_key = parameters.generate_private_key()
        public_key = self.private_key.public_key()
        self.y = public_key.public_numbers().y

    def calc_shared_key(self, y):
        peer_public_number = dh.DHPublicNumbers(y, self.pn)
        peer_public_key = peer_public_number.public_key(default_backend())
        return self.private_key.exchange(peer_public_key)
