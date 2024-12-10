from random import randint

chars = "abcdefghijklmnopqrstuvwxyz0123456789-*/+@=(){}[]#&"

secret_key = ""

for _ in range(0, 128):
    secret_key += chars[randint(0, len(chars) - 1)]

print(secret_key)
