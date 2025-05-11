import sys
import base64
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization, hashes

def load_private_key(path="private_key.txt"):
    """Tải khóa private từ file PEM."""
    with open(path, "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=None)

def decrypt_text(encrypted_base64, private_key):
    """Giải mã văn bản đã mã hóa bằng khóa private RSA với OAEP padding."""
    encrypted = base64.b64decode(encrypted_base64)  # Giải mã base64
    decrypted = private_key.decrypt(
        encrypted,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),  # MGF1 với SHA256
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return decrypted.decode("utf-8")  # Giải mã và trả lại dưới dạng văn bản

def extract_bits_from_commas(text):
    """Trích xuất chuỗi bit từ văn bản đã được giấu."""
    lines = text.split('\n')
    bits = []

    for line in lines:
        if ", và " in line:
            bits.append('1')
        elif " và " in line:
            bits.append('0')

    return ''.join(bits)  # Kết hợp các bit thành chuỗi

def main():
    if len(sys.argv) != 3:
        print("Usage: python3 extract.py [encrypted_hidden_text.txt] [private_key.txt]")
        return

    encrypted_file = sys.argv[1]  # File chứa dữ liệu đã mã hóa
    private_key_file = sys.argv[2]  # File chứa khóa private

    # Tải private key
    try:
        private_key = load_private_key(private_key_file)
    except Exception as e:
        print("Không thể tải khóa bí mật:", str(e))
        return

    # Đọc nội dung đã mã hóa từ file
    with open(encrypted_file, "r", encoding="utf-8") as f:
        encrypted_data = f.read()

    # Giải mã dữ liệu đã mã hóa
    try:
        decrypted_text = decrypt_text(encrypted_data, private_key)
    except Exception as e:
        print("Lỗi khi giải mã:", str(e))
        return

    # Trích xuất chuỗi bit từ văn bản đã giải mã
    bitstring = extract_bits_from_commas(decrypted_text)

    # Ghi chuỗi bit vào file
    with open("extracted_binary.txt", "w") as f:
        f.write(bitstring)

    print(f"Đã giải mã và trích xuất {len(bitstring)} bit vào extracted_binary.txt")

if __name__ == "__main__":
    main()
