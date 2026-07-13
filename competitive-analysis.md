# Evaluare build vs. buy pentru analiza impactului schimbărilor

**Status:** propunere pentru milestone-ul „Impact Analysis: build vs. buy”  
**Obiectiv:** să stabilim dacă există deja o soluție care produce, cu suficientă precizie, raportul nostru dorit — `diff → simboluri → entrypoint-uri → call chains → teste → contracte → consumatori cross-repository` — și dacă este mai eficient să cumpărăm/integrăm decât să construim și să întreținem intern un motor cross-language.

## 1. Întrebarea de decizie

Nu căutăm doar un code graph sau un selector de teste. Căutăm o soluție care poate răspunde explicabil, într-un PR:

1. ce simboluri s-au schimbat;
2. ce comportamente/entrypoint-uri sunt afectate;
3. prin ce lanțuri sunt conectate;
4. ce contracte publice sunt afectate;
5. ce teste acoperă sau nu acoperă acele căi;
6. ce consumatori din alte repository-uri sunt afectați;
7. cu ce confidence și ce zone nu au putut fi analizate.

**Decizia posibilă:**

- **BUY:** produsul comercial acoperă cerințele și costă mai puțin decât dezvoltarea și mentenanța internă;
- **ADOPT:** proiect OSS acoperă cerințele, iar noi construim doar integrarea și adaptoarele lipsă;
- **HYBRID:** cumpărăm/adoptăm infrastructura semantică și păstrăm stratul nostru framework-aware de raportare;
- **BUILD:** nu există o bază suficientă; construim motorul comun și adaptoarele;
- **STOP/DROP:** valoarea nu justifică nici produsul comercial, nici mentenanța internă.

## 2. Baseline: ce avem acum

Proiectul curent oferă pentru Python/FastAPI:

- extragerea endpoint-urilor prin runtime introspection sau AST securizat;
- analiză mypy la nivel de simbol și dependențe;
- maparea liniilor din diff la endpoint-uri;
- call stacks multiple și marcarea originii endpoint-ului;
- raportarea liniilor orphan;
- output text, JSON, YAML, Markdown și HTML;
- opțiune de execuție izolată în Docker.

Limitări importante:

- este Python/FastAPI-specific, nu language-agnostic;
- AST secure este integrat în analiza completă a diff-ului, dar nu compune încă prefixele `APIRouter`/mount în identitatea publică;
- precizia depinde de mypy și de pattern-urile pe care le înțelegem;
- nu oferă cross-repository consumers;
- nu unește încă test coverage și contract diff;
- extinderea directă cu analizatoare proprii pentru fiecare limbaj ar crea un harness mare, costisitor și probabil mai slab decât indexerele bazate pe compilatoare/LSP.

## 3. Landscape

### 3.1 Cele mai apropiate soluții

| Soluție | Rol | Potrivire cu ținta | Gap principal | Verdict pentru POC |
|---|---|---:|---|---|
| [Sourcegraph Precise Impact Analysis](https://github.com/sourcegraph-community/precise-impact-analysis) + SCIP | Changed symbols, precise references și consumers cross-repo | Foarte mare | Exemplul folosește infrastructura Sourcegraph și un API fără garanție de stabilitate; nu clasifică automat entrypoint-uri framework-specific | **P0 — principal candidat BUY/HYBRID** |
| [SCIP](https://github.com/sourcegraph/scip) | Protocol comun pentru definitions/references | Mare ca fundație | Nu este produs de impact analysis și nu modelează singur entrypoint-uri, teste sau contracte | **P0 — principal candidat OSS foundation** |
| [CoDD](https://github.com/yohey-w/codd-dev) | Requirements/design/code/tests coherence; `impact`, `diff`, `propagate` | Medie-mare | Altă unitate de analiză; maturitate și scală enterprise neconfirmate | **P1 — evaluare conceptuală și benchmark** |
| [JCCI](https://github.com/baikaishuipp/jcci) | Java commit diff → methods/classes → controllers | Mare pentru Java/Spring | Java-specific; nu rezolvă arhitectura polyglot | **P1 — benchmark pentru adaptorul Spring** |
| [Glean](https://github.com/facebookincubator/Glean) | Infrastructură de facts, symbols, xrefs și call hierarchies | Mare ca motor | Necesită model, ingestie și raportare proprie | **P1 — alternativă OSS la Sourcegraph** |
| [CodeQL](https://codeql.github.com/docs/codeql-overview/supported-languages-and-frameworks/) | Graf semantic și queries multi-language | Mare potențial | Trebuie implementate diff mapping, reverse traversal și raportarea; licențierea trebuie verificată pentru utilizarea vizată | **P0/P1 — POC tehnic și legal** |
| [Joern](https://joern.io/) | Code Property Graph: AST/call/control/data flow | Medie-mare | Mai greu, nu turnkey pentru PR și framework entrypoints | **P1 — doar dacă avem nevoie de data-flow profund** |
| Tree-sitter | Parsing sintactic multi-language | Mică singur, mare ca adaptor | Nu rezolvă types, dispatch sau cross-module references | **Componentă complementară**, nu motor principal |
| Code-Ripple | Prototip diff/dependency/ranking | Medie | Maturitate și producție neconfirmate | **Watchlist**, nu candidat principal |

### 3.2 Affected targets și test impact

Aceste produse răspund în primul rând la „ce construim/testăm?”, nu la „ce comportamente sunt afectate?”.

| Familie | Exemple | Utilitate pentru noi |
|---|---|---|
| Build/project graph | bazel-diff, Nx affected, Turborepo `--affected` | Semnal grosier și rapid la nivel de target/package; bun ca strat suplimentar |
| Coverage-based test selection | pytest-testmon, Ekstazi, Datadog TIA | Mapping test ↔ cod executat; util pentru secțiunea „affected/uncovered tests” |
| Call-graph test selection | Harness Test Intelligence | Candidat comercial relevant deoarece justifică selecția testelor prin dependențe |
| Predictive selection | Develocity, CloudBees/Launchable | Optimizează timpul de CI, dar nu oferă evidence graph determinist complet |

### 3.3 Contract impact (semnal suplimentar, nu blast radius)

Aceste instrumente nu calculează propagarea schimbărilor prin cod și nu sunt competitori pentru motorul de impact. Ele răspund doar dacă s-a schimbat contractul public al unui entrypoint deja identificat. Nu trebuie să le acordăm TP/FP/FN în scorecard-ul de blast radius; rezultatele lor se măsoară într-un scorecard separat de contract compatibility.

Nu trebuie să reimplementăm analizatoare mature de contracte:

- [oasdiff](https://github.com/oasdiff/oasdiff) pentru OpenAPI;
- [GraphQL Inspector](https://github.com/kamilkisiela/graphql-inspector) pentru GraphQL;
- [Buf Breaking](https://buf.build/docs/breaking/) pentru Protobuf/gRPC;
- [Pact/PactFlow can-i-deploy](https://docs.pact.io/pact_broker/can_i_deploy) pentru compatibilitatea consumer-provider.

Aceste rezultate trebuie atașate evidence graph-ului, nu înlocuite cu inferențe LLM.

### 3.4 Produse comerciale adiacente

- **Sourcegraph Enterprise:** cel mai bun candidat pentru code intelligence precis și cross-repo;
- **Harness / Datadog / Develocity / CloudBees:** test impact, nu business/entrypoint impact complet;
- **SciTools Understand, CAST Imaging, NDepend și familia Depend:** architecture/dependency analysis puternic, dar integrarea PR și acoperirea polyglot trebuie validate;
- **CodeScene:** change risk/hotspots, nu call-chain determinist către entrypoint-uri;
- **AI reviewers:** utile numai pentru sumarizarea evidence graph-ului. Nu sunt sursă de adevăr și nu pot demonstra absența impactului.

## 4. Ipoteza de arhitectură

Cea mai promițătoare direcție este **HYBRID**, nu rescrierea unui analyzer semantic per limbaj:

```text
SCIP / Sourcegraph / CodeQL / Glean
        symbols + references
                  ↓
framework adapters (FastAPI, Django, Spring, NestJS, ASP.NET, Rails…)
                  ↓
build graph + test coverage + contract analyzers
                  ↓
evidence graph comun
                  ↓
GitHub Check: Markdown + JSON artifact
                  ↓
LLM opțional pentru sumar, niciodată pentru ground truth
```

Model minim comun:

- noduri: `changed_symbol`, `entrypoint`, `test`, `contract`, `repository`, `build_target`;
- muchii: `references`, `calls`, `implements`, `covers`, `exposes`, `consumes`, `depends_on`;
- provenance pe fiecare muchie: indexer/query/coverage tool, versiune, confidence;
- explicit `unknown/unresolved`, fără a interpreta lipsa dovezii ca „not affected”.

## 5. Scorecard de evaluare

Fiecare candidat va fi notat 0–5. Scorul ponderat maxim este 100.

| Criteriu | Pondere | Prag minim |
|---|---:|---:|
| Recall pe entrypoint-urile afectate | 20 | ≥ 90% pe benchmark |
| Precision / false positives | 10 | ≥ 80% |
| Call-chain explicabil și provenance | 10 | Obligatoriu |
| Acoperire limbaje și framework-uri | 15 | Python + Java + TS în POC |
| Cross-repository consumers | 10 | Obligatoriu pentru candidatul enterprise |
| Incremental PR latency | 5 | p95 ≤ 5 minute, separat de indexarea inițială |
| Test impact și coverage integration | 5 | API/export disponibil |
| Contract integration | 5 | Poate importa/atașa rezultate externe |
| Securitate și analiză fără execuția codului | 5 | Obligatoriu implicit |
| Operare, mentenanță și observabilitate | 5 | Estimare și owner clare |
| Licență, lock-in și data residency | 5 | Acceptabil legal/security |
| TCO pe 3 ani | 5 | Comparabil cu alternativa internă |

### Benchmark comun

POC-urile trebuie rulate pe aceleași schimbări controlate:

1. Python/FastAPI — acest repository și exemplele DI existente;
2. Java/Spring — controllers, services, overloaded methods și DI;
3. TypeScript/NestJS — controllers/providers și monorepo packages;
4. un caz cross-repository producer/consumer;
5. schimbări negative: cod orphan/unreachable, rename fără impact, comentarii;
6. schimbări de contract OpenAPI/GraphQL/Proto;
7. schimbări cu și fără test coverage.

Ground truth-ul se construiește manual înainte de rularea produselor. Măsurăm TP/FP/FN, timpul de indexare, timpul incremental și efortul de configurare.

## 6. Planul milestone-ului

### Faza A — validare desk research

- verificarea claim-urilor, licențelor și stării proiectelor;
- matrice de features cu surse și data verificării;
- definirea benchmark-ului și a ground truth-ului;
- discuții/demo cu Sourcegraph și cel puțin un vendor de test impact.

### Faza B — POC-uri scurte

1. **Sourcegraph/SCIP:** changed symbols → reverse references → cross-repo consumers;
2. **SCIP OSS:** ingestarea indexurilor într-un evidence graph minimal;
3. **CodeQL:** query de reachability de la changed symbols la entrypoint-uri;
4. **Glean sau Joern:** numai dacă primele două nu oferă relațiile necesare;
5. **JCCI/CoDD:** benchmark comparativ, nu fundație implicită;
6. **Harness sau Datadog:** evaluare separată pentru test impact.

Timebox recomandat: maximum 2–3 zile de engineering per candidat înainte de go/no-go.

### Faza C — decizie management

Livrabile:

- scorecard complet și reproductibil;
- demo pe același PR polyglot;
- TCO pe trei ani: licențe, infrastructură, onboarding, operare și dezvoltarea adaptoarelor;
- riscuri: vendor lock-in, API stability, data residency, index freshness, unsupported constructs;
- recomandare BUY / ADOPT / HYBRID / BUILD / STOP.

## 7. Criterii explicite de stop/drop

Recomandăm să oprim dezvoltarea motorului semantic propriu și să migrăm dacă un candidat:

- depășește baseline-ul nostru la recall și precision;
- acoperă limbajele prioritare și cross-repo;
- oferă API/export suficient pentru clasificarea entrypoint-urilor;
- are TCO pe trei ani mai mic decât o echipă care menține indexere cross-language;
- îndeplinește cerințele security/legal/data residency.

Continuăm proiectul, dar reducem scope-ul la stratul framework-aware, dacă infrastructura existentă oferă symbols/references bune, însă nu oferă raportul final.

Construim mai mult intern numai dacă niciun candidat nu poate furniza evidence/provenance, extensibilitate și precizie acceptabile.

## 8. Recomandare finală: HYBRID / ADOPT, cu BUY condiționat

### Decizie

**Nu construim intern un motor semantic cross-language și nu extindem analyzerul curent limbaj cu limbaj. Adoptăm SCIP/compiler indexes ca fundație și construim numai adaptoarele framework-aware și evidence graph-ul. Nu cumpărăm încă Sourcegraph Enterprise fără POC-ul cross-repository pe instanța reală.**

Dovezile măsurate:

- baseline-ul curent, rulat fără execuția codului pe cele 58 PR-uri evaluabile, a obținut `TP=0`, `FP=40`, `FN=180`, deci precision/recall/F1 zero;
- chiar și subsetul HTTP necesită compunerea router/mount și propagare prin middleware, persistence și configurare; 102 din cele 180 entrypoint-uri adjudecate nu sunt HTTP;
- SCIP Python plus un adaptor FastAPI de 0,05 secunde a obținut `TP=2/FP=0/FN=0` pe fixture-ul transitive, inclusiv `Depends`;
- SCIP TypeScript plus un adaptor NestJS subțire a obținut `TP=2/FP=0/FN=0` pe fixture;
- JCCI a obținut `TP=1/FP=0/FN=0` pe overload-ul Spring; SCIP Java rămâne nevalidat din cauza indexului incomplet pentru simbolurile JDK;
- oasdiff, GraphQL Inspector și Buf au identificat exact schimbările controlate de contract, confirmând că integrarea este preferabilă reimplementării;
- CoDD oferă impact de arhitectură după onboarding, dar nu identități de entrypoint.

### Ce păstrăm și ce oprim

1. **Păstrăm repository-ul**, benchmark-ul adjudecat, schema comună, evaluatorul, provenance și raportarea `unknown/unresolved`.
2. **Înghețăm analyzerul FastAPI actual ca adaptor/prototip**, cu mentenanță pentru benchmark și defecte critice; nu investim în semantica altor limbaje.
3. **Adoptăm SCIP** pentru Python și TypeScript după pinning/version qualification; `scip-python-plus` nu este acceptat deoarece a pierdut endpoint-ul injectat.
4. **Folosim JCCI numai ca referință/adaptor Java temporar**; pentru producție cerem index bazat pe compilator și refacem POC-ul SCIP Java într-un proiect Maven Spring real.
5. **Integrăm oasdiff, GraphQL Inspector și Buf** ca evidence separat de blast radius. Pact rămâne condiționat de existența brokerului și matricei de deployment.
6. **Separăm achiziția de test-impact**: Harness/Datadog/Develocity se justifică numai prin economie de CI și coverage export, nu ca motor de business impact.
7. **Sourcegraph Enterprise este BUY condiționat** de demonstrarea precise indexes, cross-repo consumers, API stabil/exportabil, security/data residency și TCO pe instanța organizației.

### Următorul increment recomandat

Timebox de 4–6 săptămâni pentru un vertical slice: SCIP Python + TypeScript, adaptor FastAPI/NestJS cu prefix composition, evidence graph comun, output GitHub Check și atașarea oasdiff/GraphQL/Buf. Prag de continuare: minimum 80% recall HTTP pe corpus fără execuție de cod, provenance complet și latență incrementală sub cinci minute. Dacă pragul nu este atins, oprim produsul intern și reevaluăm exclusiv BUY.

## 9. Surse inițiale

- Sourcegraph Precise Impact Analysis: <https://github.com/sourcegraph-community/precise-impact-analysis>
- Sourcegraph cross-repository navigation: <https://sourcegraph.com/blog/cross-repository-code-navigation>
- SCIP: <https://github.com/sourcegraph/scip>
- SCIP Python: <https://github.com/sourcegraph/scip-python>
- CoDD: <https://github.com/yohey-w/codd-dev>
- JCCI: <https://github.com/baikaishuipp/jcci>
- Glean: <https://github.com/facebookincubator/Glean>
- CodeQL languages/frameworks: <https://codeql.github.com/docs/codeql-overview/supported-languages-and-frameworks/>
- Joern: <https://joern.io/>
- Harness Test Intelligence: <https://developer.harness.io/docs/continuous-integration/use-ci/run-tests/tests-v2>
- oasdiff: <https://github.com/oasdiff/oasdiff>
- GraphQL Inspector: <https://github.com/kamilkisiela/graphql-inspector>
- Buf Breaking: <https://buf.build/docs/breaking/>
- Pact can-i-deploy: <https://docs.pact.io/pact_broker/can_i_deploy>

> Claim-urile comerciale, suportul de limbaje, prețurile și licențele se schimbă. Matricea finală trebuie să includă data verificării și link către documentația vendorului pentru fiecare scor.
