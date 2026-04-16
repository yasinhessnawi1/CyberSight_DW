-- ============================================================
-- CyberSight DW — PostgreSQL Star Schema DDL
-- Auto-executed on container first start via docker-entrypoint-initdb.d
-- ============================================================

-- ============================================================
-- DIMENSION TABLES
-- ============================================================

CREATE TABLE dim_time (
    time_key        SERIAL PRIMARY KEY,
    timestamp       TIMESTAMP NOT NULL,
    hour            SMALLINT NOT NULL CHECK (hour BETWEEN 0 AND 23),
    day             SMALLINT NOT NULL CHECK (day BETWEEN 1 AND 31),
    week            SMALLINT NOT NULL CHECK (week BETWEEN 1 AND 53),
    month           SMALLINT NOT NULL CHECK (month BETWEEN 1 AND 12),
    year            SMALLINT NOT NULL,
    day_of_week     VARCHAR(10) NOT NULL,
    is_weekend      BOOLEAN NOT NULL DEFAULT FALSE,
    time_of_day     VARCHAR(10) NOT NULL
);

CREATE UNIQUE INDEX idx_dim_time_ts ON dim_time(timestamp);


CREATE TABLE dim_source (
    source_key      SERIAL PRIMARY KEY,
    source_ip       INET NOT NULL,
    source_port     INTEGER NOT NULL CHECK (source_port BETWEEN 0 AND 65535),
    country         VARCHAR(100) DEFAULT 'Unknown',
    region          VARCHAR(100) DEFAULT 'Unknown',
    ip_class        VARCHAR(10),
    UNIQUE (source_ip, source_port)
);

CREATE INDEX idx_dim_source_ip ON dim_source(source_ip);


CREATE TABLE dim_destination (
    dest_key        SERIAL PRIMARY KEY,
    dest_ip         INET NOT NULL,
    dest_port       INTEGER NOT NULL CHECK (dest_port BETWEEN 0 AND 65535),
    service_name    VARCHAR(50) DEFAULT 'Unknown',
    service_type    VARCHAR(50) DEFAULT 'Unknown',
    UNIQUE (dest_ip, dest_port)
);

CREATE INDEX idx_dim_dest_ip ON dim_destination(dest_ip);


CREATE TABLE dim_attack (
    attack_key      SERIAL PRIMARY KEY,
    attack_label    VARCHAR(100) NOT NULL UNIQUE,
    attack_category VARCHAR(50)  NOT NULL,
    severity        VARCHAR(10)  NOT NULL CHECK (severity IN ('LOW','MEDIUM','HIGH','CRITICAL')),
    description     TEXT
);


CREATE TABLE dim_protocol (
    protocol_key    SERIAL PRIMARY KEY,
    protocol_name   VARCHAR(20)  NOT NULL UNIQUE,
    transport_layer VARCHAR(20)  NOT NULL
);


-- ============================================================
-- FACT TABLE
-- ============================================================

CREATE TABLE fact_network_event (
    event_id            BIGSERIAL PRIMARY KEY,
    time_key            INTEGER NOT NULL REFERENCES dim_time(time_key),
    source_key          INTEGER NOT NULL REFERENCES dim_source(source_key),
    dest_key            INTEGER NOT NULL REFERENCES dim_destination(dest_key),
    attack_key          INTEGER NOT NULL REFERENCES dim_attack(attack_key),
    protocol_key        INTEGER NOT NULL REFERENCES dim_protocol(protocol_key),
    flow_duration       BIGINT  NOT NULL DEFAULT 0,
    fwd_packets         INTEGER NOT NULL DEFAULT 0,
    bwd_packets         INTEGER NOT NULL DEFAULT 0,
    fwd_bytes           BIGINT  NOT NULL DEFAULT 0,
    bwd_bytes           BIGINT  NOT NULL DEFAULT 0,
    flow_bytes_per_sec  NUMERIC(15,4) DEFAULT 0,
    flow_pkts_per_sec   NUMERIC(15,4) DEFAULT 0,
    is_attack           BOOLEAN NOT NULL DEFAULT FALSE
);

CREATE INDEX idx_fact_time           ON fact_network_event(time_key);
CREATE INDEX idx_fact_source         ON fact_network_event(source_key);
CREATE INDEX idx_fact_attack         ON fact_network_event(attack_key);
CREATE INDEX idx_fact_is_attack      ON fact_network_event(is_attack);
CREATE INDEX idx_fact_time_attack    ON fact_network_event(time_key, attack_key);
CREATE INDEX idx_fact_protocol       ON fact_network_event(protocol_key);
CREATE INDEX idx_fact_dest           ON fact_network_event(dest_key);
CREATE INDEX idx_fact_is_attack_time ON fact_network_event(is_attack, time_key);


-- ============================================================
-- PRE-AGGREGATED SUMMARY TABLES
-- ============================================================

CREATE TABLE summary_attack_hourly (
    summary_id      SERIAL PRIMARY KEY,
    hour_bucket     TIMESTAMP NOT NULL,
    attack_category VARCHAR(50) NOT NULL,
    attack_label    VARCHAR(100) NOT NULL,
    event_count     BIGINT NOT NULL DEFAULT 0,
    total_bytes     BIGINT NOT NULL DEFAULT 0,
    avg_duration_ms NUMERIC(12,2) DEFAULT 0,
    unique_sources  INTEGER DEFAULT 0,
    created_at      TIMESTAMP DEFAULT NOW(),
    UNIQUE (hour_bucket, attack_label)
);

CREATE INDEX idx_summary_hourly_bucket ON summary_attack_hourly(hour_bucket);
CREATE INDEX idx_summary_hourly_cat    ON summary_attack_hourly(attack_category);


CREATE TABLE summary_top_sources (
    summary_id      SERIAL PRIMARY KEY,
    day_bucket      DATE NOT NULL,
    source_ip       INET NOT NULL,
    country         VARCHAR(100),
    attack_count    INTEGER NOT NULL DEFAULT 0,
    distinct_targets INTEGER NOT NULL DEFAULT 0,
    primary_attack  VARCHAR(100),
    threat_score    NUMERIC(12,2) DEFAULT 0,
    created_at      TIMESTAMP DEFAULT NOW(),
    UNIQUE (day_bucket, source_ip)
);

CREATE INDEX idx_summary_sources_day ON summary_top_sources(day_bucket);
CREATE INDEX idx_summary_sources_ip  ON summary_top_sources(source_ip);


CREATE TABLE summary_protocol_daily (
    summary_id      SERIAL PRIMARY KEY,
    day_bucket      DATE NOT NULL,
    protocol_name   VARCHAR(20) NOT NULL,
    total_events    BIGINT NOT NULL DEFAULT 0,
    attack_events   BIGINT NOT NULL DEFAULT 0,
    attack_ratio    NUMERIC(5,4) DEFAULT 0,
    UNIQUE (day_bucket, protocol_name)
);

CREATE INDEX idx_summary_protocol_day ON summary_protocol_daily(day_bucket);


CREATE TABLE summary_severity_daily (
    summary_id      SERIAL PRIMARY KEY,
    day_bucket      DATE NOT NULL,
    severity        VARCHAR(10) NOT NULL,
    event_count     BIGINT NOT NULL DEFAULT 0,
    unique_sources  INTEGER DEFAULT 0,
    created_at      TIMESTAMP DEFAULT NOW(),
    UNIQUE (day_bucket, severity)
);

CREATE INDEX idx_summary_severity_day ON summary_severity_daily(day_bucket);


CREATE TABLE summary_dest_port_daily (
    summary_id      SERIAL PRIMARY KEY,
    day_bucket      DATE NOT NULL,
    dest_port       INTEGER NOT NULL,
    service_name    VARCHAR(50) DEFAULT 'Unknown',
    attack_category VARCHAR(50) NOT NULL,
    event_count     BIGINT NOT NULL DEFAULT 0,
    created_at      TIMESTAMP DEFAULT NOW(),
    UNIQUE (day_bucket, dest_port, attack_category)
);

CREATE INDEX idx_summary_dest_port_day ON summary_dest_port_daily(day_bucket);


CREATE TABLE summary_weekend_weekday (
    summary_id      SERIAL PRIMARY KEY,
    is_weekend      BOOLEAN NOT NULL,
    attack_category VARCHAR(50) NOT NULL,
    total_events    BIGINT NOT NULL DEFAULT 0,
    attack_events   BIGINT NOT NULL DEFAULT 0,
    attack_rate_pct NUMERIC(5,2) DEFAULT 0,
    created_at      TIMESTAMP DEFAULT NOW(),
    UNIQUE (is_weekend, attack_category)
);

CREATE INDEX idx_summary_weekend ON summary_weekend_weekday(is_weekend);
