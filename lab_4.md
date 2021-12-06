# 4. Laboratorijska vježba

---

## **Digital signatures using public-key cryptography**

Zadatak ovog dijela vježbe je provjeriti autentičnost slike potpisane privatnim ključem. Slike s odgovarajućim potpisom smo skinuli sa servera kao i javni ključ pomoću kojeg možemo provjeriti autentičnost potpisa.

### Rješenje zadatka

- za početak pokušavamo ispisati deserijalizirani javni ključ pohranjen u datoteci *public.pem*

```python
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

def load_public_key():
    with open("public.pem", "rb") as f:
        PUBLIC_KEY = serialization.load_pem_public_key(
            f.read(),
            backend=default_backend()
        )
    return PUBLIC_KEY

# ====================
# Loading public key

public_key = load_public_key()
print(public_key)
```

- dobiven je ispis:

```
<cryptography.hazmat.backends.openssl.rsa._RSAPublicKey object at 0x000001EBB32CFEB0>
```

- na temelju ovog ispisa možemo vidjeti da se koristi RSA public key kripto sustav
- kada smo se uvjerili da se javni ključ ispravno može pročitati možemo provjeriti autentičnost slika potpisanih privatnim ključem, a to ćemo napraviti sljedećim kodom

```python
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidSignature

def load_public_key():
    with open("public.pem", "rb") as f:
        PUBLIC_KEY = serialization.load_pem_public_key(
            f.read(),
            backend=default_backend()
        )
    return PUBLIC_KEY

def verify_signature_rsa(signature, message):
    PUBLIC_KEY = load_public_key()
    try:
        PUBLIC_KEY.verify(
            signature,
            message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
    except InvalidSignature:
        return False
    else:
        return True

# ====================

with open("image_1.sig", "rb") as file:
    signature = file.read()

with open("image_1.png", "rb") as file:
    image = file.read()

is_authentic = verify_signature_rsa(signature, image)
print(is_authentic)
```

- naša funkcija *verify_signature_rsa* mora primati 2 parametra, a to su potpis i slika
- funkciji je potrebno proslijediti sliku zato što se mora izračunati njena hash vrijednost jer je upravo ta hash vrijednost potpisana privatnim ključem i to je jedini način da provjerimo ispravnost ključa

### Zaključak

Na temelju izvorne poruke, u našem primjeru slike, potpisa i pripadajućeg javnog ključa mi možemo provjeriti autentičnost poruke. Ako dobijemo odgovor *True* znači da je poruka autentična, a ako dobijemo odgovor *False* to znači da ne možemo utvrditi autentičnost poruke, ali poruka ne mora nužno biti neautentična.

---

## **Password-hashing (iterative hashing, salt, memory-hard functions)**

Zadatak ove vježbe je napraviti uspredbu između *sporih* i *brzih* kriptografskih hash funkcija koje je koriste kod hashiranja lozinki. 

### Rješenje zadatka

- kopirali smo kod pomoću kojeg se provjeravaju brzine pojedinih kriptografskih hash funckija, kao i AES-a koji se koristi kod simetrične enkripcije
- iz ispisa zaključujemo da se hash funckije jako brzo izvršavaju, a mi želimo povećati vrijeme hashiranja kako bi demotivirali napadača da stvori *dictionary* s parovima lozinki i hash vrijednosti
- u primjeru smo vidjeli *linux_hash* koji koristi sol i iterativno hashiranje 5000 puta na taj način dodatno se štiti sustav
- u kod main funkcije dodajemo ispis vremena i za linux_hash, točnije računamo ga za 5000 i za 10^6 iteracija

```python
				{
            "name": "LINUX CRYPTO 5k",
            "service": lambda: linux_hash(password, measure=True)
        },
        {
            "name": "LINUX CRYPTO 1M",
            "service": lambda: linux_hash(password, rounds=10**6, measure=True)
        }
```

- dobili smo sljedeći ispis iz kojeg možemo izvući bitne zaključke koje hash funkcije koristiti, odnosno koliko iteracija istih koristiti

```
+-----------------+----------------------+
| Function        | Avg. Time (100 runs) |
+-----------------+----------------------+
| HASH_SHA256     |       3.1e-05        |
| HASH_MD5        |       3.2e-05        |
| AES             |       0.000599       |
| LINUX CRYPTO 5k |       0.006499       |
| LINUX CRYPTO 1M |       1.205571       |
+-----------------+----------------------+
```

- iz ispisa možemo vidjeti trajanje izvođenja pojedinih funkcija te zaključujemo da su jednostavne hash funkcije vrlo brze što može motivirati napadača da sastavi u relativno kratkom vremenu vrlo velik *dictionary* i napadne naš sustav
- ako povećamo broj iteracija hashiranja na 5000, a pogotovo na milijun to će značajno usporiti napadača, međutim moramo voditi računa o tome da sami sebi se napravimo DoS napad u slučaju da nam hashiranje predugo traje

### Zaključak

Ovisno o tome za što koristimo kriptografske hash funkcije koristit ćemo različite pristupe, odnosno birat ćemo najprikladniji broj iterativnih hashiranja. Na primjer, ako imamo web stranicu s ne tako bitnim podacima koristit ćemo primjerice 2000 iteracija i na taj način će naš sustav brzo raditi, ali postoji i rizik da nam sustav bude napadnut. U drugom slučaju ako štitimo jako bitne podatke, a primjerice ne pristupamo im toliko često koristit ćemo milijun iteracija hashiranja jer će u tom slučaju vjerojatnost napada biti puno manja.
