import uuid
from cryptography.hazmat.primitives.cmac import CMAC
from cryptography.hazmat.primitives.ciphers import algorithms
import binascii
import sys


def uuid_to_btaddress(uuid_str):
    # UUID文字列からUUIDオブジェクトを生成
    key = uuid.UUID(uuid_str).bytes

    # 2. AES-CMACで文字列 "candy" の認証コードを算出
    cmac = CMAC(algorithms.AES(key))
    cmac.update(b"candy")
    auth_code = cmac.finalize()  # 16バイトのMAC

    # 3. 先頭6バイトを取得
    first_6_bytes = auth_code[:6]

    # 4. バイト順を反転
    reversed_bytes = first_6_bytes[::-1]

    # 5. 反転後の先頭バイトに 0xc0 を OR演算
    modified_first_byte = bytes([reversed_bytes[0] | 0xC0])

    # 6. 最終結果を16進数文字列で出力
    return modified_first_byte + reversed_bytes[1:]


if __name__ == "__main__":
    if len(sys.argv) <= 1:
        print("Usage: python uuid_to_btaddress.py <128bit UUID>...")
        sys.exit(1)
    for id in sys.argv[1:]:
        print(f"{id} -> {binascii.hexlify(uuid_to_btaddress(id), ':').decode('utf-8')}")
