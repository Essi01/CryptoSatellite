import socket
import time
import matplotlib.pyplot as plt
from datetime import datetime

# Konfigurasjon
ARDUINO_IP = "192.168.1.177"  # IP-adresse til Arduino
PORT = 5000  # Port for kommunikasjon
TIMEOUT = 2  # Timeout i sekunder

# Lagre målinger
malinger = {
    'tidspunkt': [],
    'responstid': [],
    'meldingsstorrelse': []
}


def send_til_arduino(melding, vis_statistikk=True):
    """Send melding til Arduino og få svar"""
    start_tid = time.time()

    try:
        # Opprett socket og koble til Arduino
        client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client.settimeout(TIMEOUT)
        print(f"Kobler til {ARDUINO_IP}:{PORT}...")
        client.connect((ARDUINO_IP, PORT))

        # Lag HTTP-forespørsel
        http_request = f"GET /data:{melding} HTTP/1.1\r\n"
        http_request += f"Host: {ARDUINO_IP}:{PORT}\r\n"
        http_request += "Connection: close\r\n\r\n"

        # Send forespørsel
        request_size = len(http_request.encode())
        print(f"Sender forespørsel ({request_size} bytes)...")
        client.sendall(http_request.encode())

        # Motta svar
        response = b""
        while True:
            try:
                data = client.recv(1024)
                if not data:
                    break
                response += data
            except socket.timeout:
                print("Timeout ved mottak av data")
                break

        # Beregn responstid i millisekunder
        slutt_tid = time.time()
        responstid = (slutt_tid - start_tid) * 1000

        # Dekoder svar
        svar_tekst = response.decode('utf-8', errors='replace')

        # Vis formatert svar
        vis_formatert_svar(svar_tekst, responstid, request_size, len(response))

        # Lagre måling
        if vis_statistikk:
            malinger['tidspunkt'].append(datetime.now())
            malinger['responstid'].append(responstid)
            malinger['meldingsstorrelse'].append(request_size + len(response))

        return svar_tekst

    except ConnectionRefusedError:
        print("FEIL: Tilkobling avvist. Sjekk om Arduino kjører.")
    except socket.timeout:
        print("FEIL: Tilkobling tidsavbrutt.")
    except Exception as e:
        print(f"FEIL: {e}")
    finally:
        try:
            client.close()
        except:
            pass

    return None


def vis_formatert_svar(svar_tekst, responstid, request_size, response_size):
    """Vis et pent formatert svar"""
    print("\n" + "=" * 50)
    print(f"RESPONSTID: {responstid:.2f} ms")
    print(f"FORESPØRSELSSTØRRELSE: {request_size} bytes")
    print(f"SVARSTØRRELSE: {response_size} bytes")
    print("-" * 50)

    # Vis innholdet i svaret (hopp over HTTP-headere)
    deler = svar_tekst.split("\r\n\r\n", 1)
    if len(deler) > 1:
        innhold = deler[1]
    else:
        innhold = svar_tekst

    print(innhold)
    print("=" * 50)


def vis_statistikk():
    """Vis statistikk for målinger"""
    if not malinger['responstid']:
        print("Ingen målinger registrert.")
        return

    print("\n" + "=" * 50)
    print("KOMMUNIKASJONSSTATISTIKK")
    print("-" * 50)

    # Responstid
    responstider = malinger['responstid']
    print(f"Responstid (ms):")
    print(f"  Min: {min(responstider):.2f}")
    print(f"  Maks: {max(responstider):.2f}")
    print(f"  Gjennomsnitt: {sum(responstider) / len(responstider):.2f}")

    # Meldingsstørrelse
    meldingsstørrelser = malinger['meldingsstorrelse']
    print(f"\nMeldingsstørrelse (bytes):")
    print(f"  Min: {min(meldingsstørrelser)}")
    print(f"  Maks: {max(meldingsstørrelser)}")
    print(f"  Gjennomsnitt: {sum(meldingsstørrelser) / len(meldingsstørrelser):.2f}")

    print("=" * 50)


def tegn_graf():
    """Tegn grafer for responstid og meldingsstørrelse"""
    if not malinger['tidspunkt']:
        print("Ingen data å vise.")
        return

    # Lag figur med to undernplott
    fig, (ax1, ax2) = plt.subplots(2, 1, figsize=(10, 8))
    fig.suptitle('Kommunikasjonsytelse', fontsize=16)

    # Responstid
    ax1.plot(malinger['tidspunkt'], malinger['responstid'], 'b-o')
    ax1.set_ylabel('Responstid (ms)')
    ax1.set_title('Responstid')
    ax1.grid(True)

    # Meldingsstørrelse
    ax2.plot(malinger['tidspunkt'], malinger['meldingsstorrelse'], 'm-o')
    ax2.set_ylabel('Meldingsstørrelse (bytes)')
    ax2.set_title('Meldingsstørrelse')
    ax2.grid(True)

    # Juster layout
    plt.tight_layout()
    plt.subplots_adjust(top=0.9)

    # Vis grafen
    plt.show()


def kjor_test(meldingsstorrelse=100, antall=5):
    """Kjør en test med flere meldinger"""
    print(f"\nKjører test med {antall} meldinger på {meldingsstorrelse} bytes...")

    # Lag testmelding
    melding = "A" * meldingsstorrelse

    # Send meldinger
    for i in range(antall):
        print(f"\nTest {i + 1}/{antall}:")
        send_til_arduino(melding)
        if i < antall - 1:  # Ikke vent etter siste melding
            time.sleep(0.5)

    # Vis statistikk
    vis_statistikk()


def hovedmeny():
    """Hovedmenyen for programmet"""
    print("-" * 60)
    print("Forenklet testprogram for Arduino-kommunikasjon")
    print("-" * 60)

    while True:
        print("\nValg:")
        print("1. Send melding")
        print("2. Sjekk status")
        print("3. Kjør ytelsestest")
        print("4. Vis statistikk")
        print("5. Vis graf")
        print("6. Nullstill statistikk på Arduino")
        print("7. Avslutt")

        valg = input("\nVelg et alternativ (1-7): ")

        if valg == '1':
            melding = input("Skriv melding: ")
            send_til_arduino(melding)

        elif valg == '2':
            send_til_arduino("status", vis_statistikk=False)

        elif valg == '3':
            storrelse = int(input("Meldingsstørrelse (bytes): "))
            antall = int(input("Antall meldinger: "))
            kjor_test(storrelse, antall)

        elif valg == '4':
            vis_statistikk()

        elif valg == '5':
            tegn_graf()

        elif valg == '6':
            send_til_arduino("reset", vis_statistikk=False)
            print("Statistikk nullstilt på Arduino.")

        elif valg == '7':
            print("Avslutter programmet.")
            break

        else:
            print("Ugyldig valg. Prøv igjen.")


if __name__ == "__main__":
    hovedmeny()