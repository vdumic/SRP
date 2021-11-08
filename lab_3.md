# 3. Laboratorijska vježba

Message authentication and integrity

### Zadatak

Zadatak ove vježbe je primjeniti naučena teorijska znanja o osnovnim kriptografskim mehanizmima koji služe za autentikaciju i zaštitu integriteta. Proučiti ćemo ih na vrlo jednostavnim primjerima i pri tome koristiti simetrične i asimetrične kriptografske mehanizme, a to su *message authentication code (MAC)* i *digitalni potpisi* temeljeni na javnim ključevima.

### Message Authentication Code (MAC)

Riješit ćemo dva izazova koja se temelje na *MAC* algoritmu, a sve potrebne mehanizme ćemo preuzeti iz Python biblioteke `cryptography`.

### Izazov 1

- kreiramo dvije datoteke *message.txt* (u njoj se nalazi poruka na koju ćemo primijeniti *MAC* algoritam) i *message_integrity.py*
- pročitamo tekst iz datoteke → generiramo neki tajni ključ *key → mac* generiramo kroz funkciju koja prima ključ i poruku kao argumente
- dobiveni *mac* upisujemo u datoteku *message.sig*
- kako bi provjerili je li poruka autentična moramo iskoristiti funkciju verify_MAC koja kao argumente prima ključ, potpis i poruku → upravo ti argumenti su nam potrebni kako bi mogli lokalno generirati *mac* i usporediti ga s onim dobivenim → ako su oni jednaki možemo reći da je poruka autentična
- ako je sve prošlo u redu na izlazu bi trebali vidjeti *True*, međutim ako se na ikakav način modificira početna poruka ili neki dio *mac* potpisa poruke na izlazu ćemo dobiti *False* → time možemo zaključiti da poruka nije autentična i da lako možemo detektirati grešku, ali ne možemo znati je li došlo do promjena u tekstu poruke ili u potpisu

```python
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.exceptions import InvalidSignature

def verify_MAC(key, signature, message):
    if not isinstance(message, bytes):
        message = message.encode()

    h = hmac.HMAC(key, hashes.SHA256())
    h.update(message)
    try:
        h.verify(signature)
    except InvalidSignature:
        return False
    else:
        return True

def generate_MAC(key, message):
    if not isinstance(message, bytes):
        message = message.encode()

    h = hmac.HMAC(key, hashes.SHA256())
    h.update(message)
    signature = h.finalize()
    return signature

if __name__ == "__main__":
    key = b"my secret key"
    # Reading from a file
    with open("message.txt", "rb") as file:
        content = file.read()   

    # mac = generate_MAC(key, content)

    # with open("message.sig", "wb") as file:
    #     file.write(mac)

    with open("message.sig", "rb") as file:
        mac = file.read()

    is_authentic = verify_MAC(key, mac, content)
    print(is_authentic)
```

### Izazov 2

- želimo utvrditi vremenski ispravnu sekvencu transakcija, odnosno ispravan redoslijed transakcija s dionicama
- provjeravamo personalizirane naloge za transakcije koji su digitalno potpisani *MAC-om*
- ključ koji koristimo je `key = "dumic_veronika".encode()` → nije siguran, ali je poslužio za potrebe demonstracije temeljnih principa *MAC* algoritma

```python
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.exceptions import InvalidSignature

def verify_MAC(key, signature, message):
    if not isinstance(message, bytes):
        message = message.encode()

    h = hmac.HMAC(key, hashes.SHA256())
    h.update(message)
    try:
        h.verify(signature)
    except InvalidSignature:
        return False
    else:
        return True

if __name__ == "__main__":
    key = "dumic_veronika".encode()

    for ctr in range(1, 11):
        msg_filename = f"order_{ctr}.txt"
        sig_filename = f"order_{ctr}.sig"    
        # print(msg_filename)
        # print(sig_filename)

        with open(msg_filename, "rb") as file:
            message = file.read()

        with open(sig_filename, "rb") as file:
            signature = file.read()

        is_authentic = verify_MAC(key, signature, message)

        print(f'Message {message.decode():>45} {"OK" if is_authentic else "NOK":<6}')
```

- na izlazu dobijemo ispis svih transakcija i potvrdu o tome jesu li autentične ili nisu

```bash
Message     Buy 68 shares of Tesla (2021-11-11T09:11) NOK
Message     Sell 2 shares of Tesla (2021-11-10T21:45) OK
Message    Sell 67 shares of Tesla (2021-11-12T13:22) NOK
Message     Buy 73 shares of Tesla (2021-11-14T03:49) NOK
Message     Buy 44 shares of Tesla (2021-11-10T07:01) OK
Message    Sell 78 shares of Tesla (2021-11-10T08:23) OK
Message     Sell 6 shares of Tesla (2021-11-11T03:51) NOK
Message     Buy 13 shares of Tesla (2021-11-11T07:39) NOK
Message     Buy 34 shares of Tesla (2021-11-14T11:51) NOK
Message     Buy 15 shares of Tesla (2021-11-13T02:30) NOK
```

- dobili smo popis svih transakcija koje imaju ispravne *timestampove* i sada kad znamo koje su verificirane mogli bi ih posložiti po redoslijedu kojim se odvijaju
