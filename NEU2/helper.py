from Crypto.Hash import HMAC, SHA256

def hmac_sha256(message: bytearray, key: bytearray) -> bytearray:
    try:
        h = HMAC.new(key, digestmod=SHA256)
        h.update(message)
        return bytearray(h.digest())
    except ValueError as e:
        print(f"HMAC error: {e}")
        return None
    except TypeError as e:
        print(f"Type error: {e}")
        return None
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
        return None


def derive_keys(secrets) -> (bytearray, bytearray, bytearray, bytearray, bytearray, bytearray):
    array = bytearray(ord(char) for char in secrets)

    kve = hmac_sha256(array, array[0:32])
    kse = hmac_sha256(array, array[5:37])
    kfe = hmac_sha256(array, array[10:42])

    kva = hmac_sha256(array, array[15:47])
    ksa = hmac_sha256(array, array[20:52])
    kfa = hmac_sha256(array, array[25:57])

    return (kve, kse, kfe, kva, ksa, kfa)

if __name__ == "__main__":
    secret = "415a4ae674bdf4d45b44e81ffdb60cb71bf4753cc3d5c60534671c3fd58547f2c17c0b89a0021f1821930e15509fb99e"
    kve, kse, kfe, kva, ksa, kfa = derive_keys(secret)

    print("kve:", kve.hex())
    print("kse:", kse.hex())
    print("kfe:", kfe.hex())
    print("kva:", kva.hex())
    print("ksa:", ksa.hex())
    print("kfa:", kfa.hex())
