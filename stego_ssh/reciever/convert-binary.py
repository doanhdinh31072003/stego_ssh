import sys

def text_to_binary(text):
    return ''.join(format(ord(c), '08b') for c in text)

def binary_to_text(binary):
    chars = [binary[i:i+8] for i in range(0, len(binary), 8)]
    return ''.join([chr(int(b, 2)) for b in chars])

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python3 convert-binary.py [input_file] encode|decode")
        sys.exit(1)

    file = sys.argv[1]
    option = sys.argv[2]

    with open(file, 'r', encoding='utf-8') as f:
        content = f.read().strip()

    if option == 'encode':
        binary = text_to_binary(content)
        with open('binary.txt', 'w') as out:
            out.write(binary)
        print("Đã tạo binary.txt")
    elif option == 'decode':
        text = binary_to_text(content)
        print("Giải mã decode:", text)
    else:
        print("Tùy chọn không hợp lệ!")
