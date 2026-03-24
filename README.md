# Device Service

## Migrations SQL au démarrage

Depuis mars 2026, les migrations SQL sont exécutées automatiquement au démarrage du container applicatif grâce à l'intégration de golang-migrate.

- Le binaire `migrate` est inclus dans l'image Docker.
- Les migrations sont lancées avant le démarrage de l'application, avec gestion du lock et attente (option `-lock-timeout`).
- Plus besoin de job Kubernetes séparé pour les migrations.
- La variable d'environnement `DATABASE_URL` doit être définie (via secret Helm).

### Exemple de build local

```sh
cd device
# Build l'image Docker
DOCKER_BUILDKIT=1 docker build -t device-service:local .
```

### Déploiement Helm
- Le job de migration a été supprimé.
- Les pods applicatifs exécutent les migrations automatiquement.

### Avantages
- Pas de race condition lors du scaling.
- Déploiement simplifié.

### Pour aller plus loin
- Voir le Dockerfile pour la logique d'exécution de migrate.
- Adapter le timeout ou la stratégie selon vos besoins.
