-- DSV Block Explorer Database Schema
-- PostgreSQL 14+

-- Chain state table
CREATE TABLE IF NOT EXISTS chain_state (
    id INTEGER PRIMARY KEY DEFAULT 1 CHECK (id = 1),
    best_tip_hash BYTEA NOT NULL,
    best_height BIGINT NOT NULL DEFAULT 0,
    best_chainwork BYTEA NOT NULL,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Blocks table
CREATE TABLE IF NOT EXISTS blocks (
    hash BYTEA PRIMARY KEY,
    height BIGINT UNIQUE NOT NULL,
    prev_hash BYTEA NOT NULL,
    time TIMESTAMP WITH TIME ZONE NOT NULL,
    bits INTEGER NOT NULL,
    nonce BIGINT NOT NULL,
    merkle BYTEA NOT NULL,
    chainwork BYTEA NOT NULL,
    file_no BIGINT NOT NULL,
    file_offset BIGINT NOT NULL,
    tx_count INTEGER NOT NULL DEFAULT 0,
    size_bytes INTEGER NOT NULL DEFAULT 0,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_blocks_height ON blocks(height);
CREATE INDEX IF NOT EXISTS idx_blocks_time ON blocks(time);
CREATE INDEX IF NOT EXISTS idx_blocks_prev_hash ON blocks(prev_hash);

-- Transactions table
CREATE TABLE IF NOT EXISTS txs (
    txid BYTEA PRIMARY KEY,
    block_hash BYTEA REFERENCES blocks(hash) ON DELETE CASCADE,
    block_height BIGINT NOT NULL,
    idx_in_block INTEGER NOT NULL,
    fee_lgb BYTEA NOT NULL,  -- 40-byte 320-bit integer
    size_bytes INTEGER NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_txs_block_hash ON txs(block_hash);
CREATE INDEX IF NOT EXISTS idx_txs_block_height ON txs(block_height);
CREATE INDEX IF NOT EXISTS idx_txs_created_at ON txs(created_at);

-- Transaction inputs
CREATE TABLE IF NOT EXISTS tx_inputs (
    txid BYTEA NOT NULL REFERENCES txs(txid) ON DELETE CASCADE,
    n INTEGER NOT NULL,
    prev_txid BYTEA NOT NULL,
    prev_vout INTEGER NOT NULL,
    address VARCHAR(64),
    amount_lgb BYTEA,  -- 40-byte 320-bit integer
    is_coinbase BOOLEAN NOT NULL DEFAULT FALSE,
    PRIMARY KEY (txid, n)
);

CREATE INDEX IF NOT EXISTS idx_tx_inputs_prev ON tx_inputs(prev_txid, prev_vout);
CREATE INDEX IF NOT EXISTS idx_tx_inputs_address ON tx_inputs(address);

-- Transaction outputs
CREATE TABLE IF NOT EXISTS tx_outputs (
    txid BYTEA NOT NULL REFERENCES txs(txid) ON DELETE CASCADE,
    n INTEGER NOT NULL,
    address VARCHAR(64) NOT NULL,
    amount_lgb BYTEA NOT NULL,  -- 40-byte 320-bit integer
    spent_by_txid BYTEA,
    spent_at_height BIGINT,
    PRIMARY KEY (txid, n)
);

CREATE INDEX IF NOT EXISTS idx_tx_outputs_address ON tx_outputs(address);
CREATE INDEX IF NOT EXISTS idx_tx_outputs_unspent ON tx_outputs(address) WHERE spent_by_txid IS NULL;

-- Address statistics (materialized view-like table)
CREATE TABLE IF NOT EXISTS address_stats (
    address VARCHAR(64) PRIMARY KEY,
    balance_lgb BYTEA NOT NULL DEFAULT E'\\x' || repeat('00', 40),
    total_received_lgb BYTEA NOT NULL DEFAULT E'\\x' || repeat('00', 40),
    total_sent_lgb BYTEA NOT NULL DEFAULT E'\\x' || repeat('00', 40),
    utxo_count INTEGER NOT NULL DEFAULT 0,
    tx_count INTEGER NOT NULL DEFAULT 0,
    first_seen_height BIGINT,
    last_seen_height BIGINT,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Reorg log for debugging and auditing
CREATE TABLE IF NOT EXISTS reorg_log (
    id SERIAL PRIMARY KEY,
    from_hash BYTEA NOT NULL,
    to_hash BYTEA NOT NULL,
    from_height BIGINT NOT NULL,
    to_height BIGINT NOT NULL,
    detached_count INTEGER NOT NULL,
    attached_count INTEGER NOT NULL,
    at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Mempool tracking (optional, for mempool explorer feature)
CREATE TABLE IF NOT EXISTS mempool (
    txid BYTEA PRIMARY KEY,
    raw_tx BYTEA NOT NULL,
    fee_lgb BYTEA NOT NULL,
    size_bytes INTEGER NOT NULL,
    received_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Initialize chain state
INSERT INTO chain_state (best_tip_hash, best_height, best_chainwork)
VALUES (E'\\x' || repeat('00', 32), -1, E'\\x' || repeat('00', 32))
ON CONFLICT (id) DO NOTHING;

-- Helper functions

-- Convert bytea to hex string
CREATE OR REPLACE FUNCTION bytea_to_hex(data BYTEA) RETURNS VARCHAR AS $$
BEGIN
    RETURN encode(data, 'hex');
END;
$$ LANGUAGE plpgsql IMMUTABLE;

-- Convert hex string to bytea
CREATE OR REPLACE FUNCTION hex_to_bytea(hex VARCHAR) RETURNS BYTEA AS $$
BEGIN
    RETURN decode(hex, 'hex');
END;
$$ LANGUAGE plpgsql IMMUTABLE;

-- Add 320-bit integers (stored as 40-byte bytea, little-endian)
CREATE OR REPLACE FUNCTION u320_add(a BYTEA, b BYTEA) RETURNS BYTEA AS $$
DECLARE
    result BYTEA;
    carry BIGINT := 0;
    i INTEGER;
    sum BIGINT;
BEGIN
    IF octet_length(a) != 40 OR octet_length(b) != 40 THEN
        RAISE EXCEPTION 'Invalid u320 length';
    END IF;
    
    result := E'\\x' || repeat('00', 40);
    
    FOR i IN 0..39 LOOP
        sum := get_byte(a, i) + get_byte(b, i) + carry;
        result := set_byte(result, i, (sum % 256)::INTEGER);
        carry := sum / 256;
    END LOOP;
    
    RETURN result;
END;
$$ LANGUAGE plpgsql IMMUTABLE;

-- Subtract 320-bit integers
CREATE OR REPLACE FUNCTION u320_sub(a BYTEA, b BYTEA) RETURNS BYTEA AS $$
DECLARE
    result BYTEA;
    borrow BIGINT := 0;
    i INTEGER;
    diff BIGINT;
BEGIN
    IF octet_length(a) != 40 OR octet_length(b) != 40 THEN
        RAISE EXCEPTION 'Invalid u320 length';
    END IF;
    
    result := E'\\x' || repeat('00', 40);
    
    FOR i IN 0..39 LOOP
        diff := get_byte(a, i)::BIGINT - get_byte(b, i)::BIGINT - borrow;
        IF diff < 0 THEN
            diff := diff + 256;
            borrow := 1;
        ELSE
            borrow := 0;
        END IF;
        result := set_byte(result, i, diff::INTEGER);
    END LOOP;
    
    RETURN result;
END;
$$ LANGUAGE plpgsql IMMUTABLE;

-- Compare 320-bit integers
CREATE OR REPLACE FUNCTION u320_cmp(a BYTEA, b BYTEA) RETURNS INTEGER AS $$
DECLARE
    i INTEGER;
BEGIN
    IF octet_length(a) != 40 OR octet_length(b) != 40 THEN
        RAISE EXCEPTION 'Invalid u320 length';
    END IF;
    
    FOR i IN REVERSE 39..0 LOOP
        IF get_byte(a, i) > get_byte(b, i) THEN
            RETURN 1;
        ELSIF get_byte(a, i) < get_byte(b, i) THEN
            RETURN -1;
        END IF;
    END LOOP;
    
    RETURN 0;
END;
$$ LANGUAGE plpgsql IMMUTABLE;

-- Zero 320-bit integer
CREATE OR REPLACE FUNCTION u320_zero() RETURNS BYTEA AS $$
BEGIN
    RETURN E'\\x' || repeat('00', 40);
END;
$$ LANGUAGE plpgsql IMMUTABLE;

-- Grants for explorer user
-- GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO dsv_explorer;
-- GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO dsv_explorer;

