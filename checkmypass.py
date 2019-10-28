import requests
import hashlib
import sys

http_proxy  = "http://proxy.rec.uba.ar:80"
https_proxy = "https://proxy.rec.uba.ar:80"

proxies = { 
              "http" : http_proxy, 
              "https": https_proxy
            }
#youre not giving the full password only the first 5 char of the password and then comparing it later on with the real one
def request_api_data(query_char):
	url = 'https://api.pwnedpasswords.com/range/' + query_char
	res = requests.get(url, proxies=proxies)
	if res.status_code != 200:
		raise RuntimeError(f"Error fetching: {res.status_code}, check the api and try again")
	return res

def pwned_api_check(password):
	sha1password = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
	first5_char, tail = sha1password[:5], sha1password[5:]
	res = request_api_data(first5_char)
	return get_passwords_leaks_counts(res, tail)

def get_passwords_leaks_counts(hashes, hash_to_check):
	hashes = (line.split(':') for line in hashes.text.splitlines())
	for h, count in hashes:
		if h == hash_to_check:
			return count
	return 0

def main(args):
	for password in args:
		count = pwned_api_check(password)
		if count:
			print(f'{password} was found {count} times... you should consider to change your password')
		else:
			print(f'{password} was Not found. Carry on!')
	return 'done'

if __name__ == '__main__':
	main(sys.argv[1:])