def xor_bytes(a, b):
    """Perform byte-wise XOR between two byte strings."""
    return bytes(x ^ y for x, y in zip(a, b))

def recover_key_stream(plaintext, ciphertext):
    """Recover the key stream from plaintext and ciphertext (excluding the authentication tag)."""
    encrypted_part = ciphertext[:-16]  # AES-GCM 认证标签是 16 字节
    return xor_bytes(plaintext, encrypted_part)

def decrypt_with_key_stream(ciphertext, key_stream):
    """Decrypt ciphertext using the recovered key stream (excluding the authentication tag)."""
    encrypted_part = ciphertext[:-16]  # 只取加密明文部分
    return xor_bytes(encrypted_part, key_stream)

def main():
    # 假设完整的 plaintext_ch1 是 76 字节（需要你提供正确的数据）
    # 这里只是示例，实际需要通道号和时间戳
    plaintext_ch1 = b"\x00" * 12+ b"noflagonthischan^ flag ^000745b0e8392b5a^ time ^a5af3b967a269d23"   # 补齐到 76 字节
    ciphertext_ch1 = b'\xf2\xf3\x8aqG\x87g\x96\xcc%<i\x92\xe3\xfei-p\x93T\xc0\xb7\xc8*\x9f\x1b\xe4\x0c\x89\x96\x97\xd4\xb6\xe1\xb61\t,\xa3\x1fj\xd7\xa0\x12\x02\xfd\xf0\xad\x81\xc9\xd4_#$\xa4\x02\xee<\x1e\x85.M\xden\xb9\x08\x83\xe8\x02W\xb9\xeb\x94J\xc5\xf3D\xad\xf6\xaa\xf6\xc7j\x19?K\xd8\x1c\x93\xb5\xea\xbf'
    ciphertext_ch4 = b'\xf7\xf3\x8aqp\xb0\xe6\x95\xcc%<i\x9e\xb8\xa02- \x98\x0b\x80\xef\x94?\x9a@\xb1\x01\x89\x96\x97\xd4\xb6\xe1\xb61\t,\xa3\x1fj\xd7\xa0\x12\x02\xa7\xa1\xac\x82\xc8\xd7Z#$\xa4\x02\xee<\x1e\x85+L\xdcj\xbf\x08\x83\xbcQR\xea\xe5\x9b\x1c\xc1\xa3\xaa\xba\xae<\x84U\xcc0\xff\x17\xe6#L\xf9\xb8@'

    # 检查长度
    if len(plaintext_ch1) != len(ciphertext_ch1) - 16:
        print("Error: Lengths do not match.")
        print(f"plaintext_ch1 length: {len(plaintext_ch1)}")
        print(f"ciphertext_ch1 length: {len(ciphertext_ch1)}")
        return

    key_stream = recover_key_stream(plaintext_ch1, ciphertext_ch1)
    plaintext_ch4 = decrypt_with_key_stream(ciphertext_ch4, key_stream)
    print("Decrypted channel 4 data:")
    print(plaintext_ch4.decode(errors='ignore'))

if __name__ == "__main__":
    main()