# UF3. Introducció a Seguretat Web

## Seguretat en aplicacions Web

### Introducció

#### Què és la seguretat en aplicacions Web?

- Branca de la seguretat informàtica que s'encarrega de la **seguretat dels llocs web, aplicacions web i serveis web**.
- Basada amb el **World Wide Web**.
- Majoria d'atacs a través de **Cross-Site Scripting (XSS) i injeccions SQL** ----> **Causa** ----> codificació o programació deficient.
Altres atacs: Phishing, Buffer Overflow...

### Causes de software insegur. Principals vulnerabilitats

El desenvolupament de software no està exempt de vulnerabilitats, i comprendre les causes d'aquestes vulnerabilitats és fonamental per abordar-les adequadament. Aquí hi ha una descripció detallada d'algunes de les raons comunes per les quals el software pot ser insegur, així com les principals vulnerabilitats associades:

- **No existeix un sistema 100% segur**: Malgrat els esforços per millorar la seguretat del software, cap sistema és completament immune a les vulnerabilitats.

- **Vulnerabilitats teòriques i reals (exploits)**: Les vulnerabilitats poden ser teòriques, conegudes com a possibles punts febles, o reals quan s'exploiten per atacants per comprometre la seguretat del sistema.

- **Debilitat en els principis de confidencialitat, integritat i disponibilitat**: Una debilitat en qualsevol d'aquests principis pot conduir a una vulnerabilitat explotable. La confidencialitat implica protegir la informació contra l'accés no autoritzat, la integritat implica assegurar-se que la informació no es modifica de manera no autoritzada, i la disponibilitat implica garantir que els serveis estiguin disponibles quan sigui necessari.

Entendre aquestes causes de software insegur és el primer pas per abordar adequadament les vulnerabilitats i millorar la seguretat dels sistemes informàtics.


### Tecnologia de seguretat

La tecnologia de seguretat en aplicacions web és una part essencial per garantir la protecció dels llocs web i les dades associades contra amenaces cibernètiques. A continuació, explorarem algunes de les principals tecnologies i estratègies utilitzades en aquest àmbit:

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

## Programació segura. Errors de programació

La programació segura és una part essencial de la garantia de la seguretat en les aplicacions web. En aquest apartat es destaca la importància de desenvolupar codi robust i segur per prevenir vulnerabilitats i exposicions a possibles atacs.

Algunes consideracions clau sobre la programació segura són:

- Les aplicacions web són susceptibles a diversos tipus d'atacs, per la qual cosa és crucial adoptar pràctiques de programació segura des del principi.
- La seguretat no pot ser simplement una capa addicional al desenvolupament, sinó que ha de ser integrada en cada etapa del cicle de vida del desenvolupament de l'aplicació.
- És necessari ser conscient dels errors comuns de programació que poden conduir a vulnerabilitats. Això inclou no suposar que els usuaris utilitzaran l'aplicació de la manera prevista, ni confiar cegament en les dades rebudes del navegador de l'usuari.
- Totes les dades rebudes per l'aplicació s'han de tractar amb precaució i considerar-les potencialment danyades o incorrectes, per evitar la possibilitat d'injeccions o explotacions.
  
A través d'una programació segura i diligent, les organitzacions poden minimitzar les vulnerabilitats i protegir les seves aplicacions web contra una àmplia gamma de possibles amenaces.


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