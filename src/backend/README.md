# Backend — Agrégateur de CVE

Service FastAPI qui prend un CPE Maven et retourne la liste des CVE connues qui l'affectent.

Il interroge quatre API publiques en parallèle (EUVD, OSV, NVD, GitHub Advisory), fusionne les résultats par identifiant CVE et les stocke dans une base MySQL locale. Les requêtes suivantes pour le même CPE sont servies depuis la base (TTL de 7 jours avant de re-interroger les sources).

## Structure

```
core/              Configuration, logging, types partagés
models/            Modèles ORM SQLAlchemy + schémas Pydantic
sources/           Un fichier par source (euvd, osv, nvd, github, ai)
matching/          Parsing CPE, comparaison de plages de versions, mapping CPE→Maven
services/          Logique d'agrégation, service de requête en base
cvss_prediction/   Modèle DistilBERT pour la prédiction de score CVSS
main.py            Application FastAPI, définition des routes
benchmark.py       Évaluation précision/rappel contre la vérité terrain OSV
```

## Sources

Les quatre sources primaires sont interrogées en parallèle. Les résultats sont fusionnés par identifiant CVE.

- **EUVD** — Base européenne de vulnérabilités. Tend à avoir des plages de versions larges, donc tout CVE signalé uniquement par EUVD (non corroboré par OSV, NVD ou GitHub) est éliminé.
- **OSV** — Open Source Vulnerabilities. Meilleure couverture Maven, plages de versions précises.
- **NVD** — Utilisé uniquement comme index CVE. Le dictionnaire CPE de NVD utilise des noms de vendeurs et produits complètement différents de Maven (ex. `pivotal_software:spring_framework` au lieu de `org.springframework:spring-webmvc`), donc une table de correspondance manuelle est maintenue dans `sources/nvd.py`. Aucune donnée de vulnérabilité n'est extraite de NVD.
- **GitHub Advisory** — Bonne couverture des bibliothèques Java. Nécessite un `GITHUB_TOKEN`.
- **IA** — Modèle DistilBERT local qui prédit un score CVSS à partir d'une description de CVE stockée en base. Ne s'exécute que quand les quatre sources précédentes ne retournent rien, et seulement si une description existe pour le produit. À activer avec `AI_FALLBACK_ENABLED=true`. Le score est informatif — il ne confirme pas l'existence d'une CVE réelle.

## Démarrage (local)

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

cp .env.example .env   # remplir DATABASE_URL, NVD_API_KEY, GITHUB_TOKEN

uvicorn main:app --reload
```

Le modèle de prédiction CVSS (`cvss_prediction/model/cvss_model.pt`) doit être
téléchargé séparément depuis <https://urlix.me/cvss-models>.

## Démarrage (Docker)

```bash
docker compose up --build
```

Lance une instance MySQL 8 et l'API sur le port 8000. Le modèle est récupéré automatiquement pendant la construction de l'image.

## API

| Méthode | Chemin | Description |
|---------|--------|-------------|
| GET | `/` | Informations sur le service |
| GET | `/health` | État de chaque source |
| GET | `/sync/status` | Statistiques de la base |
| POST | `/query` | Interroger un seul CPE |
| POST | `/query/bulk` | Interroger plusieurs CPE en parallèle |
| GET | `/cve/{cve_id}` | Détail d'une CVE |
| GET | `/cve/search?q=...` | Recherche par identifiant CVE ou texte de description |
| GET | `/config_nodes_cpe_match/` | Requête CPE utilisée par l'interface JavaFX |

## Configuration

```ini
DATABASE_URL=mysql+pymysql://user:password@host:3306/db
NVD_API_KEY=            # optionnel, passe la limite de 5 à 50 req/30s
GITHUB_TOKEN=           # requis pour la source GitHub Advisory
DEBUG=false
LOG_LEVEL=INFO
AI_FALLBACK_ENABLED=false
```
