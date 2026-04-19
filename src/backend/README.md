# Natif

## Créer l'environnement python

```
python3 -m venv venv

source venv/bin/activate

pip install -r requirements.txt
```

A chaque nouveau terminal : `source venv/bin/activate`

Télécharger le modèle : `https://urlix.me/cvss-models` et le mettre dans `/cvss_prediction/model`

## Lancer le serveur

`uvicorn main:app --reload`

# Docker

## Lancer

`sudo docker compose up --build`

## Stopper

`sudo docker compose down`
