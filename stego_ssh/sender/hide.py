import sys
import base64
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding

def load_public_key(path="public_key.txt"):
    """Tải khóa công khai từ file PEM"""
    with open(path, "rb") as f:
        return serialization.load_pem_public_key(f.read())
def hide_bits(text, bitstring):
    """Giấu chuỗi bit vào văn bản bằng cách thay thế ' và ' bằng ', và ' hoặc ngược lại"""
    lines = text.split('\n')
    result = []
    bit_index = 0
    bits_hidden = 0  # Đếm số lượng bit đã giấu

    for line in lines:
        if bit_index >= len(bitstring):
            result.append(line)
            continue

        if " và " in line or ", và " in line:
            bit = bitstring[bit_index]
            bit_index += 1
            bits_hidden += 1  # Tăng đếm mỗi khi một bit được giấu

            if bit == '1':
                line = line.replace(" và ", ", và ", 1)
            elif bit == '0':
                line = line.replace(", và ", " và ", 1)

        result.append(line)

    print(f"[+] Đã giấu {bits_hidden} bit vào văn bản.")  # In ra số lượng bit đã giấu
    return '\n'.join(result)


def encrypt_text(text, public_key):
    """Mã hóa văn bản dài bằng RSA với OAEP padding"""
    # Lấy độ dài khóa
    hash_len = hashes.SHA256().digest_size
    key_len = public_key.key_size // 8
    chunk_size = key_len - 2 * hash_len - 2  # Công thức cho OAEP padding

    encrypted_chunks = []
    text_bytes = text.encode("utf-8")

    for i in range(0, len(text_bytes), chunk_size):
        chunk = text_bytes[i:i + chunk_size]
        encrypted = public_key.encrypt(
            chunk,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        encrypted_chunks.append(base64.b64encode(encrypted).decode())

    return '\n'.join(encrypted_chunks)

def main():
    """Chạy chương trình chính"""
    if len(sys.argv) != 4:
        print("Cách dùng: python hide.py <text.txt> <binary.txt> <public_key.pem>")
        return

    # Đọc đầu vào từ các file
    text_file = sys.argv[1]
    binary_file = sys.argv[2]
    public_key_file = sys.argv[3]

    with open(text_file, "r", encoding="utf-8") as f:
        text = f.read()

    with open(binary_file, "r", encoding="utf-8") as f:
        bitstring = f.read().strip()

    # Tải khóa công khai từ file
    public_key = load_public_key(public_key_file)

    # Giấu chuỗi bit vào văn bản
    hidden_text = hide_bits(text, bitstring)

    # Mã hóa văn bản đã giấu bằng khóa công khai
    encrypted_hidden_text = encrypt_text(hidden_text, public_key)

    # Lưu kết quả mã hóa vào file
    with open("encrypted_hidden_text.txt", "w", encoding="utf-8") as f:
        f.write(encrypted_hidden_text)

    print("[+] Đã tạo file 'encrypted_hidden_text.txt' chứa văn bản đã giấu và mã hóa.")

if __name__ == "__main__":
    main()