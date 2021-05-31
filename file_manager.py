def open_read_file(path):
    file_for_encrypt = open(path)
    return file_for_encrypt.read()


def write_file(message_encrypt):
    file_for_decrypt = open("message_C.txt", "w")
    file_for_decrypt.write(message_encrypt)
