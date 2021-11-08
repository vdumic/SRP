# 2. Laboratorijska vježba

Symmetric key cryptography - a crypto challenge

### Zadatak

Zadatak ove vježbe je riješiti *crypto* izazov, točnije dešifrirati *ciphertext* koji je dobiven enkripcijom određenog plaintexta. Kompleksnost samog izazova krije se u činjenici da nemamo pristup enkripcijskom ključu već ga moramo otkriti *brute force* algoritmom. Težina zadatka počiva na tome što je velika domena iz koje se može izabrati enkripcijski ključ točnije entropija izazova je 22 bita sto znači da je ukupan *keyspace* jednak 2^22.

### Rješavanje zadatka

- upoznajemo se s Fernet sustavom pomoću kojeg je enkriptiran tekst u našem izazovu
    - napravimo direkorij za vježbu i pozicioniramo se u njega `cd vjezba2`  te provjerimo verziju Python-a (mora biti verzija 3) `python —version`
    - kreiramo virtualno okruženje koje je dobro jer kad ga deaktiviramo sve se automatski briše
        - `python -m venv vjezba2` → `cd vjezba2` → `cd Scripts` → `./activate` → `cd . .`
    - instaliramo potrebnu Python biblioteku
        - `pip install cryptography`
    - enkriptiramo tekst 'hello world' i pokušavamo ga dekriptirati s istim ključem
        
        ```python
        from cryptography.fernet import Fernet
        key = Fernet.generate_key()
        f = Fernet(key)
        plaintext = b"hello world"
        ciphertext = f.encrypt(plaintext)
        f.decrypt(ciphertext)
        ```
        
    - rezultat dekripcije bio je isti početni plaintext međutim da smo generirali drugi ključ i ponovno pokušali dekriptirati tekst s novim ključem to ne bi bilo moguće
- prvo moramo doznati naziv datoteke u kojoj se nalazi naš personalizirani *crypto challenge* , a on je ekriptiran korištenjem enkripcijske hash funkcije
    - `code brute_force.py` pomoću ove naredbe otvaramo datoteku za pisanje koda
    - `python brute_force.py` pomoću ove naredbe pokrećemo napisani kod
    
    ```python
    from cryptography.hazmat.primitives import hashes
    def hash(input):
    	if not isinstance(input, bytes):
    		input = input.encode()
    	digest = hashes.Hash(hashes.SHA256())
    	digest.update(input)
    	hash = digest.finalize()
    	return hash.hex()
    // filename = hash('prezime_ime') + ".encrypted"
    if __name__ == "__main__":
    	h = hash('dumic_veronika')
    	print(h)
    ```
    
- kada smo otkrili koja je naša datoteka pokušavamo dekriptrati njen sadržaj
    
    ```python
    import base64
    from cryptography.fernet import Fernet
    from cryptography.hazmat.primitives import hashes
    
    def hash(input):
    	if not isinstance(input, bytes):
    		input = input.encode()
    	digest = hashes.Hash(hashes.SHA256())
    	digest.update(input)
    	hash = digest.finalize()
    	return hash.hex()
    
    def test_png(header):
    	if header.startswith(b"\211PNG\r\n\032\n"):
    		return True
    
    def brute_force():
    	# Reading from a file
    	filename = "38f18b98a9a6a559c25a2708e11a7c39710870c956a104fbe3a070e40118aacf.encrypted"
    	with open(filename, "rb") as file:
    		ciphertext = file.read()
    	# Now do something with the ciphertext
    	ctr = 0
    	while True:
    		key_bytes = ctr.to_bytes(32, "big")
    		key = base64.urlsafe_b64encode(key_bytes)
    		if not (ctr + 1) % 1000:
    			print(f"[*]keys tested: {ctr +1:,}", end="\r")
    
    	# Now initialize the Fernet system with the given key
    	# and try to decrypt your challenge.
    	# Think, how do you know that the key tested is the correct key
    	# (i.e., how do you break out of this infinite loop)?
    		try:
    			plaintext = Fernet(key).decrypt(ciphertext)
    			header = plaintext[:32]
    			if test_png(header):
    				print(f"[+]KEY FOUND: {key}")
    				# Writing to a file
    				with open("BINGO.png", "wb") as file:
    					file.write(plaintext)

    				break
    		except Exception:
    			pass
    	ctr += 1
    
    if __name__ == "__main__":
    	brute_force()
    ```
    
- dekriptirana datoteka
    
    ![BINGO](https://user-images.githubusercontent.com/73183552/140810330-d40397e2-2641-492f-b463-05b4a6bc5365.png)
    

### Zaključak vježbe

Sadržaj datoteke uspjeli smo dekriptirati korištenjem *brute force* algoritma. Za otkriti ključ entropije 22 bita bilo je potrebno nekoliko minuta što nam pokazuje koliko bi bilo teško, odnosno predugo bi trajalo, otkrivanje ključa veće entropije. Eventualna ubrzanja mogli bi postići paralelizacijom tj. koristeći sve procesorske jezge i pri tom vodeći računa da se *keyspace* ravnomjerno podijeli svakoj jezgi. Međutim za ključeve entroprije 128 bita kakvi se koriste u realnim sustavima i na najjačim računalima nemoguće je otkriti ključ (*computational security*).
