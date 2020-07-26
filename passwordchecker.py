import requests
import hashlib
import sys

def request(head_hash, tail_hash):
    url = 'https://api.pwnedpasswords.com/range/' + head_hash
    res = requests.get(url)
    return res

def get_password_leaks_count(hashes, hash_to_check):
    hashes = (line.split(":") for line in hashes.text.splitlines())
    for h, count in hashes:
        if h == hash_to_check:
            return count
    return 0

def pwned_api_check(pass_list):
    hashed_psw = hashlib.sha1(pass_list.encode('utf-8')).hexdigest().upper()
    first5_char, tail = hashed_psw[:5], hashed_psw[5:]
    response = request(first5_char, tail)
    return get_password_leaks_count(response, tail)

def main(args):
    for password in args:
        count = pwned_api_check(password)
        if count != 0:
            print(f'{password} was found {count} times... you should probably change your password!')
        else:
            print(f'{password} was NOT found. Carry on!')

main(sys.argv[1:])
