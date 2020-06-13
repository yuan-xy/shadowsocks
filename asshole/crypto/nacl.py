import nacl.utils
from nacl.public import PrivateKey, Box
import logging
from asshole import shell


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

HEAD_LEN = 3
MAX_SIZE = int.from_bytes(b'\xff'*HEAD_LEN, byteorder='little', signed=False)
is_decoding = False

class NaclEncoder(NaclCrypto):
    def encode(self, data: bytes):
        if len(data) == 0:
            return b''
        ret = self.get_encode_box().encrypt(data)
        size = len(ret)
        if size > MAX_SIZE:
            raise ValueError(f"data length {size} is too large.")
        return size.to_bytes(HEAD_LEN, byteorder="little", signed=False) + ret


class NaclDecoder(NaclCrypto):
    def __init__(self, is_client, encryptor):
        self.is_client = is_client
        self.encryptor = encryptor

    def decode(self, data: bytes):
        global is_decoding
        if is_decoding:
            print("last decode not finished yet.")
            raise IOError("last decode not finished yet.")
        is_decoding = True
        ret = self.decode0(data)
        is_decoding = False
        if not self.is_client:
            logging.debug("Server got req: %s", ret)
        return ret

    def decode0(self, data: bytes):
        if len(data) == 0:
            return b''
        buffer = self.encryptor._decrypt_buf + data
        ret = bytearray()

        while len(buffer) > 0:
            size = int.from_bytes(buffer[:HEAD_LEN], byteorder='little', signed=False)
            if size > len(buffer) - HEAD_LEN:
                self.encryptor._decrypt_buf = buffer
                return bytes(ret)

            logging.log(shell.VERBOSE_LEVEL, "NaclDecoder size: %d, buffer: %d, data: %d, %s",
                size, len(buffer), len(data), self.encryptor.handler)

            try:
                dstr = self.get_decode_box().decrypt(buffer[HEAD_LEN:size+HEAD_LEN])
            except Exception:
                logging.error("NaclDecoderERROR: %d, %d, %d, %d", size, len(buffer), len(data), len(self.encryptor._decrypt_buf))
                self.encryptor._decrypt_buf = b''
                return bytes(ret)

            ret.extend(dstr)
            buffer = buffer[size+HEAD_LEN:]

        assert len(buffer) == 0
        self.encryptor._decrypt_buf = b''
        return bytes(ret)

