from pwn import *
import sys

if len(sys.argv) != 3:
    print("Invalid arguments.")
    print(">> {} <passwords_lst> <hash>".format(sys.argv[0]))
    exit()

hash = sys.argv[2]
passwords_lst = sys.argv[1]
attempts = 0

with log.progress("Attemping to crack: {}\n".format(hash)) as p:
    with open(passwords_lst, "r", encoding='latin-1') as passwords:
        for password in passwords:
            password = password.strip("\n").encode('latin-1')
            password_hash= sha256sumhex(password)
            p.status("[{}] { == {}}".format(attempts, password.decode('latin-1'), password_hash))
            if password_hash == hash:
                p.success("Password hash found afetr {} attempts >> {} hashes to {}".format(attempts, password.decode('latin-1'), password_hash))
                exit()
            attempts += 1
        p.failure("Password hash not found")