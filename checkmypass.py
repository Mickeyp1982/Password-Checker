# password checker

import requests
import hashlib
import sys


def request_api_data(query_char):
    # point to passwords API
    url = 'https://api.pwnedpasswords.com/range/' + query_char
    res = requests.get(url)
    if res.status_code != 200:
        raise RuntimeError(
            f'Error fetching: {res.status_code}, check the api and try again')
    return res


def get_password_leaks_count(hashes, hash_to_check):
    hashes = (line.split(':') for line in hashes.text.splitlines())
    for h, count in hashes:
        # check if any of return tailed hashes match our own tail - if they do return how many
        if h == hash_to_check:
            return count
    return 0


def pwned_api_check(password):
    # check password if it exists in api response

    # hash passord through sha1 hash algorithm
    sha1password = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    # split sha1password into first 5 characters and tail
    first5_char, tail = sha1password[:5], sha1password[5:]

    response = request_api_data(first5_char)
    # print(response, first5_char, tail)
    return get_password_leaks_count(response, tail)


def main(args):
    for password in args:
        count = pwned_api_check(password)
        if count:
            print(
                f'{password} was found {count} times, you should probably change your password.')
        else:
            print(f'{password} was not found, you are safe.')


if __name__ == '__main__':
    main(sys.argv[1:])
