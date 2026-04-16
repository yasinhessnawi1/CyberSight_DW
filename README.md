# CyberSight DW

**A Multi-Backend Data Warehouse for Cybersecurity Threat Intelligence**

IKT553 Intelligent Database Management — Data Warehousing Strategies

---

## Overview

CyberSight DW ingests the CICIDS 2017 network intrusion dataset (~2.8M records) through a Kafka-based streaming pipeline and writes simultaneously to three interchangeable database backends:

- **PostgreSQL** — Relational star schema with pre-aggregated summary tables
- **MongoDB** — Denormalized document store with embedded sub-documents
- **Neo4j** — Graph database modelling IP-to-IP attack relationships

A unified **Streamlit dashboard** provides live streaming controls and four analytical views across all backends.

## Architecture

```
                    ┌─────────────────────────────┐
                    │   Streamlit Dashboard :8501  │
                    │  (Streaming Control + 4 tabs)│
                    └──────┬──────────────┬────────┘
                           │ HTTP API     │ DB queries
                    ┌──────▼──────┐       │
                    │ Producer    │       │
                    │ (FastAPI    │       │
                    │  :8000)     │       │
                    └──────┬──────┘       │
                           │              │
                    ┌──────▼──────┐       │
                    │   Kafka     │       │
                    │ :9092       │       │
                    └──────┬──────┘       │
                           │              │
                    ┌──────▼──────────────▼────────┐
                    │        Consumer              │
                    │  (writes to all 3 backends)  │
                    ├──────────┬──────────┬─────────┤
                    │PostgreSQL│ MongoDB  │  Neo4j  │
                    │  :5433   │ :27018   │ :7688   │
                    └──────────┴──────────┴─────────┘
```

The producer is a controllable FastAPI service — the dashboard can start, pause, resume, stop streaming, and change replay speed. The consumer writes every batch to all three backends simultaneously, with Neo4j running in a background thread.

## Prerequisites

- **Docker** and **Docker Compose** (v2.x)
- ~4 GB free disk space
- ~8 GB RAM recommended
- CICIDS 2017 CSV files (see Dataset Setup below)

## Dataset Setup

1. Download the CICIDS 2017 dataset from:
   https://www.unb.ca/cic/datasets/ids-2017.html

2. Create the external Docker volume and copy data into it:
   ```bash
   docker volume create cybersightdw_etl_data
   
   # Copy CSV files into the volume
   docker run --rm -v cybersightdw_etl_data:/data -v ./data/cicids2017:/src alpine \
     sh -c "mkdir -p /data/cicids2017 && cp /src/*.csv /data/cicids2017/"
   ```

## Quick Start

```bash
# 1. Build and start all services
docker compose up --build

# 2. Open the dashboard
#    http://localhost:8501

# 3. Go to the "Streaming Control" tab and click "Start"
#    Watch data flow through Kafka into all three backends in real-time

# 4. Use the speed slider to control replay speed (1x, 10x, 100x, MAX)
```

## Services

| Service    | Port  | Description                       |
|------------|-------|-----------------------------------|
| Dashboard  | 8501  | Streamlit web interface           |
| Producer   | 8000  | FastAPI streaming control API     |
| PostgreSQL | 5433  | Relational data warehouse         |
| MongoDB    | 27018 | Document store                    |
| Neo4j      | 7475  | Graph browser (HTTP)              |
| Neo4j Bolt | 7688  | Graph queries                     |
| Kafka      | 9092  | Event streaming                   |
| ksqlDB     | 8088  | Stream processing                 |
| Zookeeper  | 2181  | Kafka coordination                |

## Dashboard Tabs

1. **Streaming Control** — Start/pause/stop streaming, speed slider, live metrics (auto-refreshing), progress bar, live charts
2. **Overview** — KPI cards, attack category bar chart, hourly timeline, pie chart
3. **Threat Profiling** — Top attacking IPs, country choropleth, protocol distribution, targeted ports
4. **Time Analysis** — Day-of-week heatmap, time-of-day distribution, weekly trends
5. **Backend Comparison** — Run queries Q1-Q12 on PostgreSQL/MongoDB/Neo4j and compare execution times

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
│   ├── Dockerfile.producer       ← Producer (FastAPI) image
│   ├── Dockerfile.consumer       ← Consumer image
│   ├── requirements.txt
│   ├── producer.py               ← Kafka producer core logic
│   ├── producer_api.py           ← FastAPI streaming control API
│   ├── consumer.py               ← Multi-backend Kafka consumer
│   ├── mongo_writer.py           ← MongoDB batch writer
│   ├── neo4j_writer.py           ← Neo4j incremental graph writer
│   ├── clean.py                  ← Shared cleaning functions
│   └── geo_lookup.py             ← IP → country mapping
├── dashboard/
│   ├── Dockerfile
│   ├── requirements.txt
│   ├── app.py                    ← Streamlit main app (5 tabs)
│   └── connectors/
│       ├── postgres.py
│       ├── mongodb.py
│       ├── neo4j.py
│       └── producer.py           ← Producer API client
└── notebooks/
    └── exploration.ipynb         ← EDA notebook
```

## Environment Variables

All services use environment variables (configured in `docker-compose.yml`):

| Variable         | Default                  | Used By   |
|------------------|--------------------------|-----------|
| KAFKA_BOOTSTRAP  | kafka:9092               | Producer, Consumer |
| PG_HOST          | postgres                 | Consumer, Dashboard |
| PG_DB            | cybersight               | Consumer, Dashboard |
| MONGO_URI        | mongodb://mongodb:27017  | Consumer, Dashboard |
| NEO4J_URI        | bolt://neo4j:7687        | Consumer, Dashboard |
| DATA_DIR         | /data/cicids2017/        | Producer |
| PRODUCER_API_URL | http://producer:8000     | Dashboard |
| BATCH_SIZE       | 1000                     | Consumer |

## Stopping

```bash
docker compose down          # Stop services, keep data
docker compose down -v       # Stop services and delete all data volumes
```

## Author

Yasin — IKT553 Solo Project, March 2026
