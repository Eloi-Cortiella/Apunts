# Mecansimes de Seguretat Activa

## Introducció

- Protecció de la informació --> Conseqüència de l'aplicació de mecanismes o estratègies de seguretat.

- Principis que han de considerar els mecanismes de seguretat:
    - La seguretat com un **Objectiu global**.
    - Seguretat dissenyada com quelcom que és part de l'organització.
    - El marc legal --> considerat com una part més del disseny de les polítiques de seguretat

- **Seguretat activa:** Aquells mecanismes, físics i lògics que pernmetens prevenir i detectar possibles intents de comprometre els components d'un sistema informàtic.

## Sistemes personals
### Atacs i contramesures

- Atacs segons l'objectiu
    - **Interrupció:** Contra la disponibilitat en el qual es destrueix, o queda deshabilitat, un recurs del sistema.
    - **Intercepció:** Contra la confidencialitat en el qual un elemnt no autoritzat aconsegueix l'accés a un recurs.
    - **Modificació:** Contra la integritat en el qual a més d'aconseguir l'accés no autoritzat a un recurs, pot modificar, esborrar o alterar el recurs de qualsevol forma
    - **Fabricació:** Contra la integritat en el qual un elemnt aconsegueix crear o inserir objectes falsificats en el sistema.

- Atacs segons la seva forma
    - **Atacs passius:** No modifica ni destrueix cap recurs del sistema, simplement observa amb la finalitat d'obtenir informació no autoritzada.
    - **Atacs actius:** Altera o destrueix un recurs del sistema. Podria causar problemes molt seriosos:
        - **Suplantació d'identitat**
        - **Re-actuació:** Un o diversos missatges legítims són interceptats i reenviats diverses vegades per produir un efecte no desitjat.
        - **Degradació fraudulenta del servei:** Evita el funcionament normal dels recursos del sistema informàtic.
        - **Modificació de missatges:** Modifica un part del missatge interceptat i es reenvia a la persona a qui anava adreçat.

- Atacs segons el tipus d'atacant
    - **Insiders/Outsiders** Un atac pot provenir tant de l'interior de la xarxa (insiders) com de l'exterior (outsiders)
    - Podem pensar que la majoria d'atacs provenen de l'exterior d'una organització i són escassos, però no és així:
        - **Atacs externs més nombrosos** que els interns.
        - **Percentatge d'èxit major en els interns** que en els externs.
        - **Dany més grans causats pels atacs interns**.
    - **Principals possibles atacants** d'un sistema informàtic:*
        - **Personal de la mateixa organització**
        - **Antics treballadors**
        - **Intrusos informàtics o hackers**
        - **Intrusos renumerats**

## Anatomia dels atacs

- Un atac informàtic sol constar de **cinc fases**:
    **1. Reconeixement**
    **2. Escaneig**
    **3. Accés al sistema**
    **4. Manteniment de l'accés**
    **5. Esborrat d'emprenents**

- Aquest coneixement ajuda a preveure activats que podrien comprometre a un sistema informàtic.

### Reconeixement

- Primera fase: **Recopil·lació de tota la informació possible** del sistema que pretén comprometre.

- Diverses tècniques de recopil·lació
    - **Enginyeria social o trashing**
    - **Recerques a internet**
    - **Sniffing (Capturar el trànsit de xarxa)**
    - **ordre whois**

### Exploració

- L'atacant usarà aquesta informació per sondejar el sistema i **detectar vulnerabilitats** que pugui aprofitar per tal d'accedir al sistema.

- Vulnerabilitats que busca l'atacant: Trobar comptes d'usuari, versions de sistema operatiu i aplicacions, ports oberts...

- Eines d'exploració: tracert (en entorns Windows) o traceroute (en entorns Linux/Unix).

### Accés

- Fase on es fa l'atac de manera efectiva aprofitant les vulnerabilitats

- Es sol iniciar amb el crackeig de contrasenyes el qual es pot usar **Online** (tests en viu com Hydra) o **Offline** (arxius on s'emmagatzemen les contrasenyes encriptades recorrent a tècniques de diccionari, força bruta o criptoanàlisi)

- És una fase complicada, ja que s'ha d'**evadir els Firewalls, realitzar evasió d'IDS, IPS i Honeypots per fer la penetració**. Ús d'eines com 007 Shell, ICMP Shell o AckCmd.

### Manteniment de l'accés

- Fase on s'intenta preservar la possibilitat d'efectuar nous accessos al futur.

- Eines: Programes de codi maliciós (malware), com els **cavalls de Troia i rootkits**

- L'atac també pot servir per:
    - **Instal·lar malware que monitori les accions** que estem fent (keylogger).
    - Capturar tot el trànsit de la xarxa (**Sniffing**).
    - Instal·lar un **FTP de contingut il·lícit**.
    - Utiltzar el sistema com a plataforma per **atacar altres sistemes informàtics**.

- **rootkit:** Eines informàtics emprades amb finalitats malicioses que permeten l'accés il·licit al sistema.¡
    - Usen tècniques per ocultar la seva presència i la d'altres processos
    - Molt perillosos ja que cedeixen el control del sistema a l'atacant
    - Actuen en tres nivells:
        - **Kernel**
        - **Llibreries**
        - **Aplicacions**


### Esborrat d'emprentes

- És vital per a l'atacant borrar les emprentes del que ha fet el sistema

- Independement del sistema operatiu atacat, queden registrades les seves accions en els logs del sistema.

- Per evitar ser culpat fan el següent:
    - **Deshabilitar l'auditoria** del sistema
    - **Esborrar tots els logs** del sistema i aplicacions compromeses
    - **Esborrar l'evidència o pistes de les eines utilitzades**.

# Seguretat en la Xarxa Corportativa

## Introducció

## Eines de monitoratge passiu

## Actiu

## Esquema de funcionament d'un escàner

## Ordres del sistema

## Seguretat en xarxes sense fil

## Riscos potencials dels serveis de xarxa

## Control d'accés a la xarxa basat en autenticació

## Atacs als serveis de la xarxa

## Atacs de falsejament d'identitat

## Sistemes de detecció d'intrusos
 
## Les xarxes públiques
### Seguretat en la connexió


# IDS (SNORT)

## SNORT IDS

## Funcionament dels IDS

## SNORT

## Ubicació dels IDS

## SNORT Inline (IPS)

## Fitxers de configuració

## Regles a Snort

## Variables SNORT

## Regles SNORT

## Creant les nostres Regles SNORT

## Revisió d’alertes

## Exemples regles SNORT


# Xarxes Privades Virtuals

## Introducció

## Interconnexió de xarxes

## Treballadors remots

## Avantatges i inconvenients VPN

## Tunneling

## Protocols de Tunneling

## Secure Shell