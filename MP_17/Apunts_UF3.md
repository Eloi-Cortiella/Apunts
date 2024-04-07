# UF3. Introducció a Seguretat Web

## Seguretat en aplicacions Web
---
### Introducció

#### Què és la seguretat en aplicacions Web?

- Branca de la seguretat informàtica que s'encarrega de la **seguretat dels llocs web, aplicacions web i serveis web**.
- Basada amb el **World Wide Web**.
- Majoria d'atacs a través de **Cross-Site Scripting (XSS) i injeccions SQL** ----> **Causa** ----> codificació o programació deficient.
Altres atacs: Phishing, Buffer Overflow...

---

### Causes de software insegur. Principals vulnerabilitats

El desenvolupament de software no està exempt de vulnerabilitats, i comprendre les causes d'aquestes vulnerabilitats és fonamental per abordar-les adequadament. Aquí hi ha una descripció detallada d'algunes de les raons comunes per les quals el software pot ser insegur, així com les principals vulnerabilitats associades:

- **No existeix un sistema 100% segur**: Malgrat els esforços per millorar la seguretat del software, cap sistema és completament immune a les vulnerabilitats.

- **Vulnerabilitats teòriques i reals (exploits)**: Les vulnerabilitats poden ser teòriques, conegudes com a possibles punts febles, o reals quan s'exploiten per atacants per comprometre la seguretat del sistema.

- **Debilitat en els principis de confidencialitat, integritat i disponibilitat**: Una debilitat en qualsevol d'aquests principis pot conduir a una vulnerabilitat explotable. La confidencialitat implica protegir la informació contra l'accés no autoritzat, la integritat implica assegurar-se que la informació no es modifica de manera no autoritzada, i la disponibilitat implica garantir que els serveis estiguin disponibles quan sigui necessari.

Entendre aquestes causes de software insegur és el primer pas per abordar adequadament les vulnerabilitats i millorar la seguretat dels sistemes informàtics.

---

### Tecnologia de seguretat

La tecnologia de seguretat en aplicacions web és una part essencial per garantir la protecció dels llocs web i les dades associades contra amenaces cibernètiques. A continuació, explorarem algunes de les principals tecnologies i estratègies utilitzades en aquest àmbit:

---

#### Proves de seguretat

Provar el software desenvolupat és una tasca crítica per identificar i mitigar les vulnerabilitats abans que siguin explotades per atacants. Aquestes proves poden incloure:

- **Escàners de seguretat**: Són eines que analitzen el codi font o les aplicacions en execució per detectar possibles vulnerabilitats, com injeccions de codi, exposició de dades sensibles, etc.
- **Proves d'entrada (Fuzzing)**: Consisteixen a enviar entrades inesperades o malicioses a una aplicació per identificar com reacciona i si pot ser explotada.

#### Caixa negra vs. caixa blanca

- **Caixa negra**: Aquest enfocament implica provar una aplicació sense accés al seu codi font. S'utilitzen escàners de seguretat i altres eines per identificar i explotar vulnerabilitats.
- **Caixa blanca**: En aquest cas, els analistes tenen accés al codi font de l'aplicació i poden realitzar proves més detallades utilitzant tècniques com l'auditoria de codi i els analitzadors sintàctics.

#### Seguretat en el desenvolupament

Garantir que els desenvolupadors segueixin pràctiques de programació segura és fonamental per prevenir vulnerabilitats des de les etapes inicials del desenvolupament. Això pot incloure:

- **Validació d'entrada**: Tot tipus de dades rebudes d'usuaris o altres fonts s'han de validar per evitar injeccions de codi o altres atacs.
- **Maneig adequat d'errors**: Els errors de programació poden ser explotats per atacants, és crucial que les aplicacions gestionin els errors de forma segura i no revelin informació sensible.

#### Firewall d'aplicacions web (WAF)

Un WAF és una solució de seguretat que filtra i supervisa el tràfic HTTP entre una aplicació web i Internet. Identifica i bloqueja atacs comuns com les injeccions SQL, les injeccions de codi i els intents d'explotar vulnerabilitats conegudes.

#### Gestió de l'accés

Controlar l'accés a les funcionalitats i les dades de l'aplicació és essencial per prevenir atacs d'autenticació i autorització. S'han de seguir pràctiques com l'ús de contrasenyes segures, l'autenticació multifactorial i la gestió de sessions segures.

---

## Programació segura. Errors de programació

La programació segura és una part essencial de la garantia de la seguretat en les aplicacions web. En aquest apartat es destaca la importància de desenvolupar codi robust i segur per prevenir vulnerabilitats i exposicions a possibles atacs.

Algunes consideracions clau sobre la programació segura són:

- Les aplicacions web són susceptibles a diversos tipus d'atacs, per la qual cosa és crucial adoptar pràctiques de programació segura des del principi.
- La seguretat no pot ser simplement una capa addicional al desenvolupament, sinó que ha de ser integrada en cada etapa del cicle de vida del desenvolupament de l'aplicació.
- És necessari ser conscient dels errors comuns de programació que poden conduir a vulnerabilitats. Això inclou no suposar que els usuaris utilitzaran l'aplicació de la manera prevista, ni confiar cegament en les dades rebudes del navegador de l'usuari.
- Totes les dades rebudes per l'aplicació s'han de tractar amb precaució i considerar-les potencialment danyades o incorrectes, per evitar la possibilitat d'injeccions o explotacions.
  
A través d'una programació segura i diligent, les organitzacions poden minimitzar les vulnerabilitats i protegir les seves aplicacions web contra una àmplia gamma de possibles amenaces.

---

## OWASP Top 10

OWASP (Open Web Application Security Project) és una organització sense ànim de lucre que té com a objectiu millorar la seguretat de les aplicacions web mitjançant la identificació i mitigació de les principals vulnerabilitats de seguretat. El seu informe anual, conegut com a "OWASP Top 10", és una llista que destaca les deu principals vulnerabilitats que s'han de tenir en compte en el desenvolupament i la gestió d'aplicacions web.

### Característiques de l'OWASP Top 10:

1. **Recopilació exhaustiva de dades**: L'OWASP Top 10 es basa en una àmplia recopilació i anàlisi de dades sobre vulnerabilitats observades en aplicacions web reals. Aquesta informació es recull de la comunitat de seguretat informàtica i d'experts en l'àmbit.

2. **Guia per als desenvolupadors**: L'informe proporciona una guia valuosa per als desenvolupadors i professionals de la seguretat per identificar, comprendre i mitigar les principals amenaces de seguretat en les seves aplicacions web. Cada punt del Top 10 està acompanyat d'explicacions detallades i exemples pràctics.

3. **Evolució constant**: L'OWASP Top 10 es revisa i actualitza regularment per reflectir les noves amenaces i tendències en el panorama de la seguretat informàtica. Això assegura que la llista sigui sempre pertinent i actualitzada amb els últims desafiaments de seguretat.

### Principals vulnerabilitats inclòs en l'OWASP Top 10:

1. **Injeccions de codi**: Aquesta vulnerabilitat es produeix quan es permet a les dades no fiables influir en l'execució de codi d'aplicació, com ara les injeccions SQL, NoSQL, comandes del sistema operatiu, LDAP, etc.

2. **Autenticació defectuosa**: Les vulnerabilitats en l'autenticació i la gestió de sessions poden permetre als atacants comprometre les contrasenyes, les claus de sessió o altres dades d'autenticació per assumir identitats d'usuaris legítims.

3. **Exposició de dades sensibles**: Moltes aplicacions web no protegeixen adequadament les dades sensibles, com ara la informació financera o mèdica dels usuaris, el que pot conduir a l'ús indegut d'aquestes dades per part d'atacants.

4. **XML External Entities (XXE)**: Aquesta vulnerabilitat es produeix quan es permet l'avaluació de referències d'entitats externes dintre de documents XML, el que pot exposar la infraestructura de l'aplicació a diversos tipus d'atacs.

5. **Control d'accés inadequat**: Les restriccions d'accés als recursos i funcionalitats de l'aplicació no es configuren correctament, permetent als atacants accedir a dades i funcions sensibles sense autorització.

6. **Configuració de seguretat defectuosa**: La configuració incorrecta de la seguretat pot incloure paràmetres per defecte, configuracions incompletes o altres errors que exposen l'aplicació a riscos de seguretat.

7. **Cross-Site Scripting (XSS)**: Aquesta vulnerabilitat permet als atacants injectar scripts maliciosos en pàgines web visitades pels usuaris, el que pot conduir a l'execució de codi no autoritzat en el navegador de les víctimes.

8. **Deserialització insegura**: Les vulnerabilitats en la deserialització de dades poden permetre l'execució remota de codi, ja que els atacants poden manipular les dades serialitzades per aconseguir l'execució de codi no autoritzat.

9. **Ús de components amb vulnerabilitats conegudes**: L'ús de llibreries, frameworks o altres components de software amb vulnerabilitats conegudes pot exposar l'aplicació a riscos de seguretat, ja que els atacants poden aprofitar-se de les vulnerabilitats existents en aquests components.

10. **Registre i monitoratge insuficients**: La manca de registre i monitoratge adequat pot permetre als atacants continuar els seus atacs sense ser detectats, mantenir la persistència en els sistemes compromesos i manipular o destruir dades sensibles sense ser detectats.

En resum, l'OWASP Top 10 ofereix una visió detallada de les principals amenaces de seguretat en les aplicacions web i proporciona orientació essencial per abordar aquestes vulnerabilitats i millorar la seguretat dels sistemes en línia.

## Eines en Seguretat Web
---
### Pentesting d'aplicacions web. Tècniques d'auditoria.

#### Proves d'intrusió

- **Avantatges**
    1. Pot ser ràpid i econòmic.
    2. Requereixen un coneixement relativament menor que una revisió de codi font.
    3. Comproven el codi que realment està exposat.
- **Inconvenients**
    1. Pot resultar massa tard des del punt de vista del cicle de vida
    del desenvolupament del software. (SDLC)
    2. Npmés són dels impactes frontals

#### Són legals aquestes tècniques d'auditoria?

Les tècniques d'auditoria podrien considerar-se legals sempre i quan estiguin autoritzades i no vulnerin les mesures de seguretat establertes per impedir l'accés no autoritzat als sistemes informàtics. L'article menciona que accedir o facilitar a un altre l'accés a un sistema informàtic sense autorització i en contra de la voluntat del legítim propietari pot ser castigat amb pena de presó. No obstant això, si les tècniques d'auditoria es duen a terme amb el consentiment i la cooperació del propietari del sistema o si s'actua d'acord amb les mesures de seguretat i amb l'autorització pertinent, llavors podrien considerar-se legals.

## Inspecció i revisió manual

---

- Els analitzadors automàtics de vulnerabilitats no poden trobar totes aquestes per:
    1. Donar **falsos positius**
    2. No són del tot eficaços
    3. No distingir situacions que per a un expert resulten òbvies.

- Requereix de **coneixements específics** del que s'està analitzant.
- **Inuició i creativat** de l'auditor: **Rol molt important** en la majoria de casos
- Aplicacions web expressament vulnerables per a practicar:
    - **WEBGOAT**: https://owasp.org/www-project-webgoat/
    - **BADSTORE**: https://www.vulnhub.com/entry/badstore-123,41/

---

### Eines d'anàlisi manual - Burpsuite i WebScarab

- **Burpsuite**: Aplicació feta amb Java. Inclou diverses eines usades tant per securitzar una aplicació web com per vulnerar-la.

- Es poden combinar moltes eines. A partir dels **resultats** d'una eina, es poden usar amb una altra.

- Algunes fan ús de proxy amb arquitectura **man-in-the-middle**

---

### Eina Burpsuite - Proxy

- Permet definir les peticions que s'intercepten i el comportament dels websockets.
- Capaç de modificar les respostes i canviar les capçaleres de les peticions

### Eina Burpsuite - Target

- Conjuntament amb el **proxy**
- Conté informació sobre les aplicacions web auditades
- Anota les peticions del navegador manual
- Capaç d'enviar peticions a altres eines

### Eina Burpsuite - Spider

- És un crawler (Software dissenyat per inspeccionar pàgines web amb detall)
- Permet configurar:
    1. El comportament del propi crawler i de cara a formularis i valors per defecte a utilitzar
    2. Credencials

### Eina Burpsuite - Intruder

- Capaç d'automatizar atacs configurables
- S'usen payloads per configurar el tipus d'atac
- Des de fuzzing a Injecció SQL o descobriment d'usuaris vàlids.

### Eina Burpsuite - Decoder

- Decodifica peticions o altres tipus de cadenes de text, amb resultats encadenats.
- Útil per a crear peticions o llegir dades codificades

### Eina Burpsuite - Comparer

- Compara visualment dues trames de dades. Útil per comparar dades semblants.

---

### Information Gathering (Recol·leció d'informació)

- S'ha d'obtenir el màxim d'informació possible sobre els servidors o serveis en una auditoria. Aquesta informació ha de ser informació que **no voldriem trobar** en una auditoria.
- Es busca **"coneixements indeguts"** (Estructura interna de la xarxa, arxius que haurien de trobar-se ocults...)

--- 

### Information Gathering - Google

- Google, eina usada per la majoria de pentesters.
- Les tècniques usades s'anomenen Google Dorks.
- S'usen operadors especials en les cerques per acotar-les i per evitar problemes. 

- Google Hacking: Tècnica usada en el buscador avançat de Google amb paràmetres específics. Poden descobrir fitxers interns de servidors:
    - **Cerca base** (cerca que fem normalment) i **cerca exacta** (la usen els Google hackers)
- **Cerca exacta**:
    - Ús d'**operadors lògics**: **OR, AND**
    - **Altres operadors**:
        - **Símbol "-"**: **Eliminar els resultats** que continguin certes paraules. S'usa amb el símbol seguidament de la cadena a eliminar de la cerca
        - **Símbol "*" (Wildcard)**: En una cadena, el símbol * **accepta qualsevol paraula** que trobi amb la cadena que estem cercant.
        - **Símbol ".."**: **Definim un rang** entre dos números.
        - **AROUND(N)**: entre dos cadenes podem configurar una cerca on hi hagi N paraules qualsevols entre les dues cadenes
    - **Operadors sobre altres elements**:
        - **inurl**: Buscarà a totes les pàgines on en la URL trobi la cadena posada seguidament del operador i del contingut posat després d'aquest (inurl:intranet usuaris).
        - **site**: Acotar la cerca per a un sol lloc (site:iesebre.com informàtica)
        - **filetype**: Acotar la cerca per tipus de fitxer. Retornarà resultats que compleixin el títol i siguin fitxers del tipus que s'hagi introduït.
        - **intitle**: Busca cadenes al títol d'una pàgina.
        - **allintitle**: Busca tots els termes al títol d'una pàgina.
    - **Mostra d'operadors**: https://www.exploit-db.com/google-hacking-database

---

### Information Gathering - PhpMyAdmin

- Criteris de cerca:
    - Podem buscar per cadenes que apareixin a la pàgina: "this page gives you" "mysql admin * no password"
    -  Retornarà el security.php d'un servidor XAMPP que no tingui configurat l'usuari root amb password.

---

### Information Gathering - PhpMyAdmin

És possible obtenir informació diversa mitjançant peticions de DNS als servidors objectiu:
- **Nombre de servidors de correu/DNS**.
- **Serveis externs** (caching, correu).
- **Subdominis**.
- **Servidors virtualitzats**.

Les eines que permeten fer aquestes peticions són:
- **Nslookup**
- **Dig**
- **FIerce**

---

### Information Gathering - Metadates

Les metadades proporcionen informació sobre:
- **Usuaris**.
- **Localització (imatges)**.
- **IP's**.
- **Software**.

Eines que s'usen per a la cerca de metadates:
- **Stat**. Exemple -> stat whois-list
- **Pdfinfo**.
- **Altres eines**: https://ubunlog.com/metadatos-imagen-verlos-desde-terminal/
- **Analitzador de metadades**: https://metashieldclean-up.elevenpaths.com/

---

### Information Gathering - Metadates - FOCA

**FOCA** (Fingerprinting Organizations with Collected Archives) combina i automatitza moltes tècniques per tal d'extreure i organitzar informació dels fitxers que es troben.

---

### Information Gathering - Metadates - Deep Web i Pastebin

- És bona idea buscar aparicions de l'entitat que estem auditant en la Deep Web i a Pastebin, ja que molts grups de "moralitat dubtosa" acostumen a deixar allà la informació que obtenen

---

### Information Gathering - Escaneig de xarxa i enumeració

- Al auditar volem saber quins serveis es troben accessibles des de fora de l'entitat. Per això, s'ha de realitzar escaneig per detectar quines IP's i ports estan oberts i quins serveis ofereixen a través seu

- **Eines útils**:
    - **Nmap**: permet realitzar escaneig de xarxa i ports. Algunes comandes són:
        - nmap -v -A nom_servidor: Escaneig detallat amb detecció de SO, versions, scripts i tracerouts.
        - nmap -F nom_servidor: Escaneig ràpid de detecció de ports oberts o filtrats.
    
- **Classificacions de ports**:
    - **Obert**: L'aplicació que ofereix el servei espera connexions o paquets al port.
    - **Tancat**: No tenen cap aplicació escoltant a través seu, però es podrien obrir en qualsevol moment.
    - **Filtrat**: un firewall o algun altre obstacle a la xarxa està bloquejant l'accés al port i per tant nmap no el pot classificar com a obert o tancat.
    - **No filtrat**: Són aquells que responen als sondejos de nmap, però pels quals l'eina no és capaç d'assignar un estat


---

## Anàlisi automatitzat

- Disposem de moltes eines d'automatització dels atacs més comuns. Tenen un alt grau de sofisticació i al kali linux les trobem ordenades depenent de la seva finalitat.

- Hi ha algunes organitzacions que disposen d'eines automatitzades per tal de detectar possibles vulnerabilitats i ajudar a evitar atacs.

- Eines d'automatització de google hacking:
    - **FoundStone Sitedigger**
    - **Apollo**
    - **Athena**
    - **Wikto**

---

### Sqlmap - https://github.com/sqlmapproject/sqlmap

- Eina potent per realitzar pentesting a bases de dades.
- Automatitza la detecció i explotació de moltes vulnerabilitats amb SQL injection
- Gran varietat de paràmetres per tal de millorar el seu ús.

---

### OWASP ZAP

- Permet automatitzar l'anàlisi de vulnerabilitats en aplicacions web.
- Fa de proxy entre el navegador i l'aplicació a auditar (S'han d'importar els certificats.).

## Explotació de vulnerabilitats

- El primer pas per explotar una vulnerabilitat és mirar si ja existeix algun exploit conegut.

- Vulnerabilitats senzilles de comprovar:
    - Fitxer ocult és accesible.
    - Es pot injectar SQL en un camp concret

--- 

### Explotació de vulnerabilitats - Metasploit

- Es tracta d'un **framework amb diverses eines** que permeten:
    1. **Desenvolupar exploits**
    2. **Executar exploits contra màquines locals o remotes**.
    3. **Escanejar màquines** cercant vulnerabilitats.
    4. **Recol·lectar informació** sobre vulnerabilitats.
    5. Manté el context d'explotació.

- Conté un conjunt de binaris del tipus **"msf"** que permeten:
    - Invocar una línia de comandes per interactuar amb Metasploit.
    - Executar una interfície gràfica per interactuar amb Metasploit.
    - Generació de payloads.

---

## Informes d'amenaces i solucions

- Les solucions a adoptar per tal d'evitar les vulnerabilitats, les veurem en l'apartat corresponent a cada vulnerabilitat.

- Links d'informació:
https://www.solvetic.com/tutoriales/article/2266-badstore-web-para-pruebas-de-pentesting/
https://www.configbox.com/informacion/alojamiento-web-50/panel-de-control_66/manual-webalizer-estadisticas-web_a_138
https://www.giac.org/paper/gsec/4320/google-hacking-tool-security-professional/107027

---

# Tipus d'injeccions

---

# Sessions i autenticacions

## Broken Authentication

- S'implementen funcions d'aplicacions relacionades amb l'**autenticació i la gestió de sessions** de manera incorrecta, permetent als atacants comprometre les contrasenyes, claus o fitxers de sessió o explotar altres defectes d'implementació per assumir la identitat d'altres usuaris de manera temporal o permanent.

- Trobem en aquesta vulnerabilitat tots els problemes relacionats amb el **procés de login**, les **sessions** i les **credencials**.

- Mesures a aplicar:
    - **HTTPS**: Permet que les connexions vagin per un canal segur encriptat, i tota web que demani username i password ha d'estar protegida amb SSL i TLS. S'ha de protegir TOT.
    - **SSL i TLS**.
    !["Proces_SSL/TLS"](/Captura%20de%20pantalla%20de%202024-04-06%2018-46-32.png)
    - **Cookies "Secure"**: flag que fa que les cookies només s'enviïn per HTTPS, de forma que si no està actiu aquest flag, no s'enviarà la nova cookie a l'usuari.
    - **Cookies "HttpOnly"**: Permet que les cookies no es vegin en Javascript i evita que un atacant pugui accedir a la cookie mitjançant un script maliciós, i modificar-la. 
    - **Session Fixation**: Es produeix quan hi ha alguna forma de passar una sessió començada a un altre usuari via URL, i la sessió no es regenera quan fem login. Això permet a l'atacant robar sessions autenticades.
    - **Emmagatzematge dels passwords**: 
        - Els **passwords** s'han de guardar encriptats.
        - Guardar un **hash** i **comparar** el hash del password amb el de la **Base de Dades**.
        - Existeixen diverses **funcions de hash**, que es podrien utilitzar. Les més habituals són MD5, SHA-1, SHA-256, ...
        - Es recomanable utilitzar a partir de la **SHA-512**, ja que les anteriors
        poden ser vulnerables.

### Broken Authenticacion - Contramesures

- Implementar multi-factor d'autenticació
- No usar cap credencial per defecte
- Implementar controls de contrasenyes febles
- Utilitzar polítiques de longitud, complexitat i rotació de les contrasenyes
- Establir un registre segur del procés de recuperació de les credencials o contrasenyes.
- Limitar o retardar els intents fallits d'inici de sessió.
- Utilitzar un gestor de sessions integrat i segur del costat del servidor que generi un nou ID de sessió aleatòria després del login.

## Sensitive Data Exposure

Vulnerabilitat la qual es podrà **accedir a informació relacionada amb el nostre sistema**:
-  Determinar les necessitats de protecció de les dades en trànsit i què hi ha a la base de dades
- Dades sensibles: passwords, targetes de crèdit, registres de salut, informació personal, secrets comercials...

- Tenir en compte el **RGPD** en els següents casos:
    - Es transmeten dades en **text clar**, inclosos el backups.    
    - Usa protocols com ara **HTTP, SMTP, FTP**
    - Es **verifica** el **trànsit intern** .
    - **Les dades sensibles es guarden en text en clar**, incloses les **còpies de seguretat**.
    - S'usen **sistemes d'encriptació antics**, o **claus per defecte o febles**.
    - Si el **certificat de servidor** rebut és **vàlid** o no.
    - S’usen **algoritmes antics com MD5 o SHA1**.

- Un atacant **vigila el trànsit de xarxa**, baixa les connexions de HTTPS a HTTP, **intercepta les sol·licituds i roba les cookies de sessió de l'usuari**. Usarà aquesta cookie per tal de **segrestar la sessió (autenticada) de l’usuari**, accedint i modificant dades privades de l’usuari. 

- Una aplicació xifra els números de la targeta de crèdit en una base de dades mitjançant **xifratge automàtic de la base de dades**. les dades es desxifren automàticament quan es recuperen, permetent la **injecció SQL**.

- **Solució**: Personalitzar la pàgina d'error que ve per defecte per no mostrar la comanda SQL que es realitza.

- **Contramesures al problema**:
    1. **Classificar les dades** i **identificar quines són sensibles**
    2. Aplicar **controls** segons la classificació
    3. **NO guardar dades sensibles** innecessàriament
    4. **Xifrar totes les dades sensibles**
    5. Assegurar-se d'**usar algorismes**, i **protocols estàndards actualitzats i forts**, i que les **claus** estiguin **emmagatzemades** en un lloc segur.
    6. Usar una **gestió de claus adequada**.
    7. **Xifrar les dades en trànsit** amb protocols segurs com **TLS**.
    8. **Desactivar la memòria "Caché" de respostes** que contenen dades sensibles
    9. **Guardar les contrasenyes amb un hash** usant el Salt

---

## Broken Access Control

- Vulnerabilitat causada pel disseny de l'aplicació, ja sigui per si es té accés desde l'aplicació a àrees no protegides, o si el control d'accés no està ben realitzat. 

- Tot això permet que els usuaris tinguin més permisos d'accions dels que haurien de tenir casualment.

- Algunes vulnerabilitats del Broken Access Control:
    - **Modificar la URL**, l'estat de l'aplicació interna o la pàgina HTML
    - Permetre **canviar la clau principal dels registre** d'altres usuaris
    - Actuar com a administrador havent iniciat com usuari normal --> **Elevació de privilegis**
    - **Manipulació de Metadades** --> manipulació d'un token de control d'accés o una cookie o camp ocult.
    - **Configuració errònia de CORS** --> **accés a API's no autoritzades** i **recursos restringits** des d'un domini diferent.
    -  Forçar la **navegació a pàgines autenticades com un usuari no autenticat** o a **pàgines privilegiades com un usuari estàndard**

---

### Exemple

- L'aplicació usa dades no verificades en una crida SQL on s'està accedint a la informació del compte.
    - `pstmt.setString(1, request.getParameter("acct")); ResultSet results = pstmt.executeQuery( );`

- L'atacant modifica el paràmetre "acct" en el navegador per enviar qualsevol nombre de compte que vulgui. Si no s'ha verificat correctament, l'atacant pot accedir a qualsevol compte d'usuari.

---

### Contramesures
    - **Proteccions declaratives:**
        - **URLs protegides** i rols dels usuaris el **més aillats possible** de la resta del programa.
    - En mans del **servidor**:
        - La **gestió de les sessions**.
        - La **comparació del login** un cop donada la llista d'usuaris.
        - La **redirecció cap a la pantalla de login**.
        - **API genèrica** per saber qui ha accedit per codi.
    - **Codi en el costat del servidor autenticat o API en servidor**, on l'atacant **no pot modificar** la validació del control d'accés o les metadades
    - Implementar els **mecanismes de control d’accés una vegada i reutilitzar-los** a tota l’aplicació.
    - Desactivar la **llista de directoris del servidor web**.
    - Assegurar-se que les metadades dels fitxers i els fitxers de còpia de seguretat **no estan presents a les arrels del web**.
    - El **log d'accés** ha d'avisar als admins.
    - L'**API de taxa limitada**.
    - Després de tancar la sessió, els tokens o cookies generats haurien de ser invalidats al servidor.

## Cross Site Scripting

- Vulnerabilitat que es produeix quan  un atacant pot arribar a **executar codi Javascript escrit per ell**, en la pàgina que està mirant un altre usuari.

- **Robatori de sessions, apropiació del compte, substitució de nodes, atacs contra el navegador de l'usuari, realitzant descàrregues de programari maliciós, registre de claus, i altres atacs del costat del client**

- **Scripts JavaScript**
    - `<script>alert("hola")</script>`
    - `<a onmouseover="alert('hola')">hola</a>`
    - `<img src="javascript:alert('hola')">`

- 3 formes de XSS
    - **Reflectit:**• L'aplicació o API inclou valors invàlids o no escapats de l'entradade l'usuari com a part de la sortida HTML.
    - **Permanent, resistent o emmagatzemat:**L'aplicació o API guarda valors d'entrada d'un usuari no tractats que poden ser vistos més tard per un altre usuari o l'administrador.
    - **Dom XSS:**Document Object Model. Interfície de programació d’aplicacions (API) que permet llegir, accedir i modificar el frontend del codi font d’una aplicació web.

### Contramesures

- Requereix separar les dades no confiables del contingut del navegador actii:
    - Usant **frameworks que automàticament escapin XSS per disseny**.
    - Escapant peticions de **dades HTTP no confiables**.
    - Aplicant **codificació sensible al context** quan es modifica el document del navegador des del client.
    - Habilitar una **política de seguretat de contingut (CSP)**.
    - Tenir quan abans millor **valors "nets" de l'entrada**.
    - **Evitar guardar a la base de dades valors escapats**.
    - **Decidir com volem escapar depenent del context de sortida** (HTTP, JSON...)

---

## Informes d'amenaces i solucions

Les solucions a adoptar per tal d'evitar les vulnerabilitats, les hem vist en l'apartat corresponent a cada vulnerabilitat :)