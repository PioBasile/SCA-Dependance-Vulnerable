# TER — Contextualisation de Dépendances Vulnérables

Outil d'analyse de la sécurité des dépendances d'un projet Maven. On lui pointe un JAR ou un répertoire de projet, il génère un SBOM avec Syft, puis interroge plusieurs bases de CVE pour identifier les dépendances vulnérables et leur sévérité.

## Fonctionnement

```
Projet Maven / JAR
        ↓
    Syft (SBOM)
        ↓
  Interface JavaFX
        ↓
  API FastAPI  →  EUVD / OSV / NVD / GitHub Advisory / IA
        ↓
  Base MySQL  (résultats mis en cache, rafraîchis après 7 jours)
```

L'interface est une application desktop JavaFX qui pilote Syft et affiche les résultats. Le backend est une API Python qui effectue les recherches de CVE et les stocke localement pour que les scans suivants soient rapides.

## Structure

```
src/frontend/   Application JavaFX + wrapper Syft
src/backend/    Agrégateur FastAPI
```

## Démarrage

Voir le README de chaque composant :

- [`src/frontend/README.md`](src/frontend/README.md) — build et lancement de l'application
- [`src/backend/README.md`](src/backend/README.md) — démarrage du serveur API
