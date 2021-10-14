# Sigurnost računala i podataka

Izvještaji laboratorijskih vježbi

# 1. Laboratorijska vježba

Man-in-the-middle attacks (ARP spoofing)

### Zadatak

Zadatak ove vježbe bio je realizirati *man-in-the-middle* i *denial of service* napad na računala koja koriste istu lokanu mrežu (LAN). Na raspolaganju su nam bila 3 virtualizirana Docker računala od kojih dvije žrtve (*station-1*, *station-2*) i napadač (*evil-station*).

![lab1](https://user-images.githubusercontent.com/73183552/137374360-419b31a8-5744-4b01-914a-8b6fd78f842d.png)

***Prikaz korištenih virtualiziranih računala i njihove IP i MAC adrese***

### Rješavanje zadatka

- uspostavljamo promet između *station-1* i *station-2*
    - `netcat -l -p 5000`   *(otvaramo vezu za TCP komunikaciju na portu 5000)*
    - `netcat station-2 5000`    *(uspostavljamu komunikaciju)*
- *evil-station* pokušava slušati promet
    - `tcpdump`
- pokušavamo preusmjeriti promet da ide preko *evil-stationa*
    - `arpspoof -t station-1 station-2`    (*station-1 je onaj kojeg pokušavamo zavarati, a predstavljamo se kao station-2)*
    - *evil-station* govori *stationu-1* da je MAC adresa *stationa-2* 02:42:ac:12:00:04 što nije istina, već je to MAC adresa *evil-stationa* i time je on uspješno komunikaciju preusmjerio preko sebe i može je promatrati
- uključujemo filter na *evil-stationu* kako bi lakše vidjeli komunikaciju
    - `tcpdump -X host station-1 and not arp`
    - podaci između *station-1* i *station-2* više nisu enkriptirani
- prekidamo promet između *station-1* i *station-2*  → *denial of service* napad (DoS)
    - `echo 0 > /proc/sys/net/ipr4/ip_forward`
    - komunikacija više nije moguća u smjeru station-1 → station-2 jer je prekinut transfer, a u suprotnom smjeru zato što pošiljatelj ne može dobiti povrdu da je poruka stigla primiocu
