# CyberSight DW

**A Multi-Backend Data Warehouse for Cybersecurity Threat Intelligence**

IKT553 Intelligent Database Management — Data Warehousing Strategies

---

## Overview

CyberSight DW ingests the CICIDS 2017 network intrusion dataset (~2.8M records) through a Kafka pipeline and writes simultaneously to three interchangeable database backends:

- **PostgreSQL** — Relational star schema with pre-aggregated summary tables
- **MongoDB** — Denormalized document store with embedded sub-documents
- **Neo4j** — Graph database modelling IP-to-IP attack relationships

A unified **Streamlit dashboard** provides a sidebar-driven analytics UI (KPI + charts + backend benchmarks), and a small **FastAPI** service exposes log tailing and Kafka Dead-Letter-Queue browsing for operational visibility.

This stack is tuned for **Mac usage (including Apple Silicon)** by avoiding amd64-only images and keeping Java heap sizes conservative to reduce Docker Desktop memory pressure.

## Architecture

```
                    ┌───────────────────────────────────────┐
                    │          Streamlit Dashboard :8501     │
                    │  Analytics UI (sidebar pages + charts) │
                    └──────────────┬────────────────────────┘
                                   │ HTTP
                           ┌───────▼────────┐
                           │  API Service   │
                           │  (FastAPI)     │
                           │   :8000        │
                           │  /logs, /dlq   │
                           └───────┬────────┘
                                   │ Kafka (DLQ) / volumes (logs)
                    ┌──────────────▼────────────────────────┐
                    │                 Kafka                 │
                    │                :9092                  │
                    └──────────────┬────────────────────────┘
                                   │
                    ┌──────────────▼────────────────────────┐
                    │               Consumer                │
                    │   (writes to PostgreSQL/MongoDB/Neo4j) │
                    └──────────┬──────────┬──────────┬──────┘
                               │          │          │
                           ┌───▼───┐  ┌───▼───┐  ┌───▼───┐
                           │  PG   │  │ Mongo │  │ Neo4j │
                           │ :5433 │  │:27018 │  │ :7688 │
                           └───────┘  └───────┘  └───────┘
                                   ▲
                                   │ (queries + real-time views)
                            ┌──────┴───────┐
                            │   ksqlDB     │
                            │   :8088      │
                            └──────────────┘

                    Producer (ETL) reads CSVs from `etl_data` volume
                    and pushes events to Kafka (bulk or replay mode).
```

The producer streams cleaned events into Kafka. The consumer writes batches to PostgreSQL/MongoDB/Neo4j simultaneously, with Neo4j writes offloaded to a background thread. The dashboard reads from PostgreSQL and ksqlDB (materialized views) and can benchmark query latency across backends.

## Prerequisites

- **Docker** and **Docker Compose** (v2.x)
- ~4 GB free disk space
- ~8 GB RAM recommended
- Python 3 (for `download_data.py`)
- CICIDS 2017 CSV files inside the external Docker volume `cybersightdw_etl_data` (see Dataset Setup below)

## Dataset Setup

You have two options:

### Option A (recommended): Download + populate the Docker volume automatically

Run:

```bash
python3 download_data.py --docker-volume
```

This will:

- Download the 5 CICIDS 2017 CSV files into `./data/cicids2017/`
- Create the external Docker volume `cybersightdw_etl_data` (if missing)
- Copy the CSVs into the volume at `/data/cicids2017/` so the producer can read them

### Option B: Manual volume setup

1. Download (or place) the CSVs into `./data/cicids2017/` (see `download_data.py`)
2. Create the external Docker volume and copy data into it:

```bash
docker volume create cybersightdw_etl_data

docker run --rm \
  -v cybersightdw_etl_data:/data \
  -v ./data/cicids2017:/src \
  alpine sh -c "mkdir -p /data/cicids2017 && cp /src/*.csv /data/cicids2017/"
```

## Quick Start

```bash
# 1. Build and start all services
docker compose up --build

# 2. Open the dashboard
#    http://localhost:8501
```

## Services


| Service    | Port  | Description                  |
| ---------- | ----- | ---------------------------- |
| Dashboard  | 8501  | Streamlit web interface      |
| API        | 8000  | FastAPI logs + DLQ endpoints |
| PostgreSQL | 5433  | Relational data warehouse    |
| MongoDB    | 27018 | Document store               |
| Neo4j      | 7475  | Graph browser (HTTP)         |
| Neo4j Bolt | 7688  | Graph queries                |
| Kafka      | 9092  | Event streaming              |
| ksqlDB     | 8088  | Stream processing            |
| Zookeeper  | 2181  | Kafka coordination           |


## Dashboard Pages

1. **Overview** — KPI cards, attack category charts, protocol breakdown, plus ksqlDB real-time tables
2. **Threat Profiling** — Top attacking IPs, severity breakdown, duration profile, targeted ports
3. **Time Analysis** — Day-of-week heatmap, time-of-day distribution, weekly trend, weekend vs weekday
4. **Geo Analysis** — Country choropleth + top countries
5. **Network Graph** — Neo4j co-attacker relationships + simple network visualization
6. **Backend Comparison** — Run queries Q1–Q12 and compare execution time across backends (single query or full benchmark)
7. **Backend Logs** — View merged logs from `producer` / `consumer` / `dashboard`
8. **Dead Letter Queue** — Browse messages that failed ingestion (Kafka DLQ topic)

## Dashboard Screenshots (PDF)

- [Overview](screenshots/CyberSight%20DW_1.pdf)
- [Threat Profiling](screenshots/CyberSight%20DW_2.pdf)
- [Time Analysis](screenshots/CyberSight%20DW_3.pdf)
- [Geo Analysis](screenshots/CyberSight%20DW_4.pdf)
- [Network Graph](screenshots/CyberSight%20DW_5.pdf)
- [Backend Comparison](screenshots/CyberSight%20DW_6.pdf)
- [Backend Logs](screenshots/CyberSight%20DW_7.pdf)
- [Dead Letter Queue](screenshots/CyberSight%20DW_8.pdf)

## Project Structure

```
cybersight-dw/
├── docker-compose.yml
├── README.md
├── PRD.md
├── data/cicids2017/              ← CICIDS CSV files (not in git)
├── sql/
│   ├── init.sql                  ← Schema DDL
│   ├── seed_data.sql             ← Dimension seed data
│   ├── batch_hourly.sql          ← Batch job: hourly summary
│   ├── batch_sources.sql         ← Batch job: top sources
│   └── queries/Q1-Q12           ← Decision support queries
├── etl/
│   ├── Dockerfile.producer       ← Producer image
│   ├── Dockerfile.consumer       ← Consumer image
│   ├── requirements.txt
│   ├── producer.py               ← Kafka producer core logic
│   ├── consumer.py               ← Multi-backend Kafka consumer
│   ├── mongo_writer.py           ← MongoDB batch writer
│   ├── neo4j_writer.py           ← Neo4j incremental graph writer
│   ├── clean.py                  ← Shared cleaning functions
│   └── geo_lookup.py             ← IP → country mapping
├── dashboard/
│   ├── Dockerfile
│   ├── requirements.txt
│   ├── app.py                    ← Streamlit main app (sidebar pages)
│   └── connectors/
│       ├── postgres.py
│       ├── mongodb.py
│       ├── neo4j.py
│       └── ksqldb.py
├── api/
│   ├── Dockerfile
│   └── main.py                   ← FastAPI: logs + DLQ endpoints
└── notebooks/
    └── exploration.ipynb         ← EDA notebook
```

## Environment Variables

All services use environment variables (configured in `docker-compose.yml`):


| Variable        | Default                            | Used By             |
| --------------- | ---------------------------------- | ------------------- |
| KAFKA_BOOTSTRAP | kafka:9092                         | Producer, Consumer  |
| PG_HOST         | postgres                           | Consumer, Dashboard |
| PG_DB           | cybersight                         | Consumer, Dashboard |
| MONGO_URI       | mongodb://mongodb:27017            | Consumer, Dashboard |
| NEO4J_URI       | bolt://neo4j:7687                  | Consumer, Dashboard |
| DATA_DIR        | /data/cicids2017/                  | Producer            |
| BATCH_SIZE      | 1000                               | Consumer            |
| API_URL         | [http://api:8000](http://api:8000) | Dashboard           |


## Stopping

```bash
docker compose down          # Stop services, keep data
docker compose down -v       # Stop services and delete all data volumes
```

## Author

Yasin — IKT553, March 2026