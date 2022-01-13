# 6. Laboratorijska vježba

## **Linux permissions and ACLs**

---

### Zadatak

Zadatak ove vježbe bio je upoznavanje s osnovnim postupcima upravljanja korisničkim računima u *Linux* operacijskom sustavu. Osnovni cilj bio je analizirati kontrolu pristupa, *access control*, koju korisnici imaju prilikom stvaranja novih mapa i datoteka.

---

### 1. Kreiranje novog korisničkog računa

- naredbom `id` provjeravamo *UserID* korisnika te kojim grupama pripada
- navedenu naredbu izvršavamo za korisnika koji je administrator na računalu → studen

```bash
uid=1000(student) gid=1000(student) groups=1000(student),4(adm),20(dialout),24(cdrom),25(floppy),27(sudo),29(audio),30(dip),44(video),46(plugdev),114(netdev),1001(docker)
```

- kreiramo novog korisnika → alice2

```bash
student@DESKTOP-7Q0BASR:/mnt/c/Users/A507$ sudo adduser alice2
[sudo] password for student:
Adding user alice2' ... Adding new group alice2' (1004) ...
Adding new user alice2' (1003) with group alice2' ...
Creating home directory /home/alice2' ... Copying files from /etc/skel' ...
Enter new UNIX password:
Retype new UNIX password:
passwd: password updated successfully
Changing the user information for alice2
Enter the new value, or press ENTER for the default
Full Name []:
Room Number []:
Work Phone []:
Home Phone []:
Other []:
Is the information correct? [Y/n] y
```

- logiramo se kao korisnik alice2 i provjeravamo koji je UserID korisnika i kojim grupama pripada

```bash
su - Alice2
```

```bash
alice2@DESKTOP-7Q0BASR:~$ id
uid=1003(alice2) gid=1004(alice2) groups=1004(alice2)
```

- sada želimo dodati još jednog korisnika → bob2
- međutim to nećemo moći učiniti kao korisnik alice2 zato što nemamo administratorska prava, alice2 nije član grupe `sudo` , pa ćemo se opet morati naredbom `exit` vratiti na administratorskog korisnika

---

### 2. Standardna prava pristupa datotekama

- logiramo se u sustav kao korisnik Alice2
- pozicioniramo se u direktorij `/home/alice2` i kreiramo novi direktorij `srp` te se pozicioniramo u njega
- kreiramo datoteku `security.txt` i u nju unesemo tekst *Hello World*
- pomoću naredbe `ll` izlistamo informacije o direktoriju srp i novoj datoteci u njemu

```bash
alice2@DESKTOP-7Q0BASR:~/srp$ echo Hello World > security.txt
alice2@DESKTOP-7Q0BASR:~/srp$ ll
total 12
drwxrwxr-x 2 alice2 alice2 4096 Jan 10 16:19 ./
drwxr-xr-x 5 alice2 alice2 4096 Jan 10 16:18 ../
-rw-rw-r-- 1 alice2 alice2   12 Jan 10 16:19 security.txt
```

- isto možemo napraviti i za datoteku *security.txt* pomoću naredbe `getfacl security.txt`

```bash
alice2@DESKTOP-7Q0BASR:~/srp$ getfacl security.txt
file: security.txt
owner: alice2
group: alice2
user::rw-
group::rw-
other::r--
```

- možemo vidjeti da je korisnik alice2 vlasnik datoteke i da pripada grupi alice2
- korisnik alice2 ima prava čitanja i pisanja u datoteku kao i članovi grupe alice2, a ostali korisnici imaju samo pravo čitanja datoteke
- na ovaj smo način ostvarili još bolji ispis *access control* liste zato što su u ispisu prava vezana uz resurs
- na isti način možemo ispisati i prava na direktoriju *srp*

```bash
alice2@DESKTOP-7Q0BASR:~/srp$ getfacl .
file: .
owner: alice2
group: alice2
user::rwx
group::rwx
other::r-x
```

- pravo x predstavlja naredbu `execute` što u slučaju direktorija znači da možemo pristupati direktoriju, odnosno otvoriti ga
- sada se uvjeravamo da korisnik alice2 zaista može pročitati datoteku

```bash
alice2@DESKTOP-7Q0BASR:~/srp$ cat security.txt
Hello Worl
```

- oduzimamo pravo pristupa datoteci, *access permission*, vlasniku datoteke, a to je alice2

```bash
alice2@DESKTOP-7Q0BASR:~/srp$ chmod u-r security.txt
alice2@DESKTOP-7Q0BASR:~/srp$ getfacl security.txt
file: security.txt
owner: alice2
group: alice2
user::-w-
group::rw-
other::r--
```

- uvjerili smo se da je naredba uspješno izvršena, a upravo to je moguće zato što se koristi diskrecijska kontrola pristupa što znači da sam korisnik može dodjeljivati i oduzimati prava pristupa ostalim korisnicima, pa i samome sebi
- pokušajmo sada pročitati datoteku

```bash
alice2@DESKTOP-7Q0BASR:~/srp$ cat security.txt
cat: security.txt: Permission denied
```

- vratimo prava čitanja datoteke korisniku alice2

```bash
alice2@DESKTOP-7Q0BASR:~/srp$ chmod u+r security.txt
alice2@DESKTOP-7Q0BASR:~/srp$ cat security.txt
Hello World
```

- sljedeći izazov bio je oduzeti pravo pristupa datoteci security.txt korisniku alice2, ali bez da oduzimamo pravo `read`
- to smo postigli oduzimanjem prava `execute` na cijelom direktoriju

```bash
alice2@DESKTOP-7Q0BASR:~/srp$ cd ..
alice2@DESKTOP-7Q0BASR:~$ chmod u-x srp
alice2@DESKTOP-7Q0BASR:~$ getfacl srp
file: srp
owner: alice2
group: alice2
user::rw-
group::rwx
other::r-x
alice2@DESKTOP-7Q0BASR:~$ cat srp/security.txt
cat: srp/security.txt: Permission denied
```

- vratimo `execute` pravo korisniku alice2

```bash
alice2@DESKTOP-7Q0BASR:~$ chmod u+x srp
```

- logiramo se kao korisnik bob2 i pokušavamo čitati datoteku security.txt
- to će biti moguće zato što svi imaju pravo čitanja te datoteke

```bash
bob2@DESKTOP-7Q0BASR:~$ cat /home/alice2/srp/security.txt
```

- korisnik alice2 ujedno i vlasnik datoteke oduzima ostalim korisnicima pravo čitanja

```bash
alice2@DESKTOP-7Q0BASR:~/srp$ chmod o-r security.txt
alice2@DESKTOP-7Q0BASR:~/srp$ getfacl security.txt
file: security.txt
owner: alice2
group: alice2
user::rw-
group::rw-
other::---
```

- korisnik bob2 više ne može čitati datoteku
- sada dodajemo korisnika bob2 u grupu alice2 kako bi mu opet omogućili čitanje datoteke
- kako bismo to napravili moramo biti prijavljeni u sustav kao admin

```bash
student@DESKTOP-7Q0BASR:/mnt/c/Users/A507$ sudo usermod -aG alice2 bob2
student@DESKTOP-7Q0BASR:/mnt/c/Users/A507$ su - bob2
Password:
bob2@DESKTOP-7Q0BASR:~$ cat /home/alice2/srp/security.txt Hello World
```

- kako bi omogućili korisniku bob2 da ponovno može čitati datoteku prvo smo se morali izlogirati i opet logirati kao korisnik bob2, a to je potrebno zbog sigurnosnih tokena koji vjerojatno onemogućuju pristup datoteci dok se ne ažuriraju podaci u potpunosti
- nadalje provjeravamo ima li korisnik bob2 pravo pristupa datoteci `/etc/shadow`

```bash
bob2@DESKTOP-7Q0BASR:~$ getfacl /etc/shadow
getfacl: Removing leading '/' from absolute path names
file: etc/shadow
owner: root
group: shadow
user::rw-
group::r--
other::---
```

- korisnik bob2 ne može pristupiti toj datoteci zato što ne pripada grupi *shadow* i nije *root* korisnik, a ostali nad tom datotekom nemaju nikakva prava
- pristup ostalima je onemogućen zbog sigurnosnih razloga jer je riječ o datoteci u kojoj su pohranjeni *hashevi* lozinki

---

### 3. **Kontrola pristupa korištenjem *Access Control Lists (ACL)***

- kao admin dodajemo grupi bob2 pravo na čitanje datoteke *security.txt*
- na ovaj smo način eksplicitno dodali korisnika bob2u ACL datoteke *security.txt*
- sada korisnik bob2 može čitati datoteku

```bash
student@DESKTOP-7Q0BASR:/mnt/c/Users/A507$ sudo setfacl -m
u:bob2:r /home/alice2/srp/security.txt
student@DESKTOP-7Q0BASR:/mnt/c/Users/A507$ getfacl /home/alice2/srp/security.txt
getfacl: Removing leading '/' from absolute path names
file: home/alice2/srp/security.txt
owner: alice2
group: alice2
user::rw-
user:bob2:r--
group::rw-
mask::rw-
other::---
```

- nastavljamo s uklanjanjem cijele *access control* liste

```bash
student@DESKTOP-7Q0BASR:/mnt/c/Users/A507$ sudo setfacl -b /home/alice2/srp/security.txt
```

- možemo zaključiti da je lakši način za davanje pristupa pojedinim korisnicima da napravimo grupe s potrebnim pravima pristupa, te u njih naknadno dodajemo korisnike kojima dopuštamo određena prava kako ne bi morali za svakog korisnika eksplicitno dodavati i uklanjati prava pristupa datoteci kada za to dođe potreba

---

### 4. **Linux procesi i kontrola pristupa**

- otvaramo *Python* skriptu *lab6g2.py* kao admin (student) u koju upisujemo sljedeći kod

```python
import os

print('Real (R), effective (E) and saved (S) UIDs:')
print(os.getresuid())

with open('/home/alice2/srp/security.txt', 'r') as f:
print(f.read())
```

```bash
student@DESKTOP-7Q0BASR:/mnt/c/Users/A507$ ls -l [lab6g2.py](http://lab6g2.py/)
-rwxrwxrwx 1 student student 160 Jan 10 17:00 [lab6g2.py](http://lab6g2.py/)
```

- uvjerili smo se da je student vlasnik skripte i da nad njom ima sva prava
- pokrećemo skriptu kao student i dobivamo sljedeći ispis

```bash
student@DESKTOP-7Q0BASR:/mnt/c/Users/A507$ python [lab6g2.py](http://lab6g2.py/)
Real (R), effective (E) and saved (S) UIDs:
(1000, 1000, 1000)
Traceback (most recent call last):
File "[lab6g2.py](http://lab6g2.py/)", line 6, in <module>
with open('/home/alice2/srp/security.txt', 'r') as f:
IOError: [Errno 13] Permission denied: '/home/alice2/srp/security.txt'
```

- *UserID* je oznaka korisnika koji pokreće skriptu
- vidimo da korisnik student nema pravo pristupa datoteci *security.txt*
- ispisujemo ACL za navedenu datoteku

```bash
student@DESKTOP-7Q0BASR:/mnt/c/Users/A507$ getfacl /home/alice2/srp/security.txt
getfacl: Removing leading '/' from absolute path names
file: home/alice2/srp/security.txt
owner: alice2
group: alice2
user::rw-
group::rw-
other::---
```

- provjeravamo zašto korisnik student nema pravo pristupa
- razlog je taj što spada pod korisnike *other*, a oni nemaju nikakva prava nad datotekom
- nastavljamo s pokretanjem skripte kao korisnik bob2

```bash
bob2@DESKTOP-7Q0BASR:~$ python /mnt/c/Users/A507/lab6g2.py
Real (R), effective (E) and saved (S) UIDs:
(1004, 1004, 1004)
Traceback (most recent call last):
File "/mnt/c/Users/A507/lab6g2.py", line 6, in <module>
with open('/home/alice2/srp/security.txt', 'r') as f:
IOError: [Errno 13] Permission denied: '/home/alice2/srp/security.txt'
```

- ni korisnik bob2 ne može pristupiti datoteci iz istog razloga
- dodajemo korisnika bob2 u ACL datoteke security.txt

```bash
student@DESKTOP-7Q0BASR:/mnt/c/Users/A507$ sudo setfacl -m u:bob2:r /home/alice2/srp/security.txt
```

- ponovno pokrećemo skriptu i uvjeravamo se da korisnik bob2 sada ima pravo pristupa

```bash
bob2@DESKTOP-7Q0BASR:~$ python /mnt/c/Users/A507/lab6g2.py
Real (R), effective (E) and saved (S) UIDs:
(1004, 1004, 1004)
Hello World
```

---

### Zaključak

*Access control* liste jako su bitne kako bi onemogućili određenim korisnicima pristup osjetljivim podacima. Ovisno o tome koji se model kontrole pristupa koristi takva će nam biti i sama sigurnost sustava. Ovom smo vježbom demonstrirali diskrecijsku kontrolu pristupa koja omogućuje da vlasnik datoteke sam dodjeljuje i oduzima prava pristupa što je dobro, ali nosi i određene sigurnosne prijetnje, pa u slučaju kada imamo vrlo povjerljive podatke dobro je koristiti još neki model kontrole pristupa, na primjer *mandatory access* kontrolu.
