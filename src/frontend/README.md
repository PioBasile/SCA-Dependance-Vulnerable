# Frontend — Application Desktop JavaFX

Application desktop qui analyse les dépendances vulnérables d'un projet Maven.

Elle lance Syft pour générer un SBOM, en extrait les CPE, les envoie à l'API backend, puis affiche les résultats dans un tableau avec les scores CVSS et le détail des CVE.

## Prérequis

- Java 17+
- Maven
- Le backend doit tourner (voir `src/backend/README.md`)
- Syft — télécharger le binaire avant de lancer :

```bash
curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b .
```

## Build et lancement

```bash
mvn clean compile
mvn exec:java
```
