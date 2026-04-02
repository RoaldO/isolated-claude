# isolated-claude

Een herbruikbare Docker sandbox voor het autonoom uitvoeren van Claude Code — zonder risico voor de hostomgeving.

Gebaseerd op [Anthropic's officiële devcontainer](https://github.com/anthropics/claude-code/tree/main/.devcontainer).

## Hoe het werkt

Je start de container vanaf je terminal. Claude Code draait daarbinnen en kan vrijelijk bestanden aanpassen, commando's uitvoeren en packages installeren — zonder dat jij elke actie hoeft goed te keuren.

Je projectbestanden zijn gewoon zichtbaar en bewerkbaar vanuit je eigen editor op de host. De container en jouw editor werken op dezelfde map tegelijk.

```
┌─────────────────────────────┐    ┌──────────────────────────┐
│  Terminal                   │    │  Jouw editor (Zed, Vim…) │
│  docker compose run claude  │    │  /home/roald/Projects/.. │
│                             │    │                          │
│  > Claude Code              │    │  ← ziet dezelfde files   │
│    (autonoom aan het werk)  │    │    real-time             │
└──────────┬──────────────────┘    └────────────┬─────────────┘
           │                                    │
           └──────────── /workspace ────────────┘
                      (gedeelde map)
```

## Gebruik

```bash
docker compose run claude
```

Claude start op in de container. Jij praat met Claude via de terminal. Intussen kun je bestanden gewoon openen en bekijken in je eigen editor.

## Wat Claude automatisch mag (zonder te vragen)

- Bestanden lezen, schrijven en aanpassen
- `git add`, `git commit`, `git diff`, `git log`, etc.
- `npm`, `yarn`, `node`, `python`, `cargo`, `go`, `make`
- Lokale shell commando's (`ls`, `find`, `curl`, `grep`, etc.)

## Wat nog steeds jouw goedkeuring vereist

- `git push` — code naar GitHub sturen
- `gh` — GitHub CLI (pull requests, issues, etc.)

## Gebruik in een ander project

Kopieer twee bestanden naar je projectroot:

```
jouw-project/
  docker-compose.yml    ← uit template/
  .claude/
    settings.json       ← uit template/.claude/
```

Start dan met:

```bash
docker compose run claude
```

## Netwerk (firewall)

De container heeft alleen toegang tot:

- GitHub (API, web, git)
- npm registry
- Anthropic API
- Sentry, Statsig (Claude Code telemetrie)

Al het overige netwerkverkeer wordt geblokkeerd.

## Beveiligingsnotitie

> De container beschermt je host, maar kan geen exfiltratie voorkomen van data *binnen* de container (zoals credentials die je in de workspace hebt staan). Gebruik dit alleen met vertrouwde repositories.

## Image zelf bouwen

```bash
docker compose build
```
