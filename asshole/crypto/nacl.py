import nacl.utils
from nacl.public import PrivateKey, Box
import logging

def _gen_keypair_by_seed(seed):
    key = PrivateKey(seed)
    return key.public_key, key


local_public_key, local_private_key = _gen_keypair_by_seed(
    bytes.fromhex("82001573a003fd3b7fd72ffb0eaf63aac62f12deb629dca72785a66268ec758a")
)
remote_public_key, remote_private_key = _gen_keypair_by_seed(
    bytes.fromhex("82001573a003fd3b7fd72ffb0eaf63aac62f12deb629dca72785a66268ec758c")
)


class NaclCrypto(object):
    def __init__(self, is_client):
        self.is_client = is_client

    def get_encode_box(self):
        if self.is_client:
            return Box(local_private_key, remote_public_key)
        else:
            return Box(remote_private_key, local_public_key)

    def get_decode_box(self):
        if self.is_client:
            return Box(local_private_key, remote_public_key)
        else:
            return Box(remote_private_key, local_public_key)

class NaclEncoder(NaclCrypto):
    def encode(self, data: bytes):
        if len(data) == 0:
            return b''
        ret = self.get_encode_box().encrypt(data)
        # print(ret)
        return len(ret).to_bytes(2, byteorder="little", signed=False) + ret


class NaclDecoder(NaclCrypto):
    def __init__(self, is_client, encryptor):
        self.is_client = is_client
        self.encryptor = encryptor

    def decode(self, data: bytes):
        if len(data) == 0:
            return b''
        buffer = self.encryptor._decrypt_buf + data
        ret = bytearray()

        while len(buffer) > 0:
            size = int.from_bytes(buffer[:2], byteorder='little', signed=False)
            logging.debug("NaclDecoder size: %d, buffer: %d, data: %d", size, len(buffer), len(data))
            if size > len(buffer) - 2:
                self.encryptor._decrypt_buf = buffer
                return bytes(ret)

            try:
                dstr = self.get_decode_box().decrypt(buffer[2:size+2])
            except Exception:
                logging.error("NaclDecoderERROR: %d, %d, %d, %d", size, len(buffer), len(data), len(self.encryptor._decrypt_buf))
                self.encryptor._decrypt_buf = b''
                return bytes(ret)

            ret.extend(dstr)
            buffer = buffer[size+2:]
        return bytes(ret)

