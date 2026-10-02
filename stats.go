package main

import (
	"database/sql"
	"log"
	"strings"
	"sync"
	"time"

	_ "modernc.org/sqlite"
)

const (
	maxStatsBuffer = 5000
	flushInterval  = 5 * time.Second
	batchSize      = 100
)

const statsSchema = `
PRAGMA journal_mode=WAL;
PRAGMA synchronous=NORMAL;
PRAGMA busy_timeout=5000;

CREATE TABLE IF NOT EXISTS raw_requests (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    ts          INTEGER NOT NULL,
    location    TEXT    NOT NULL,
    user_name   TEXT,
    host        TEXT    NOT NULL,
    port        INTEGER,
    status      TEXT    NOT NULL,
    bytes_in    INTEGER DEFAULT 0,
    bytes_out   INTEGER DEFAULT 0,
    duration_ms INTEGER DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_raw_ts ON raw_requests(ts);
CREATE INDEX IF NOT EXISTS idx_raw_user ON raw_requests(user_name);

CREATE TABLE IF NOT EXISTS hourly_stats (
    hour            INTEGER NOT NULL,
    location        TEXT    NOT NULL,
    host            TEXT    NOT NULL,
    allowed_count   INTEGER DEFAULT 0,
    blocked_count   INTEGER DEFAULT 0,
    error_count     INTEGER DEFAULT 0,
    geoblock_count  INTEGER DEFAULT 0,
    total_bytes     INTEGER DEFAULT 0,
    unique_users    INTEGER DEFAULT 0,
    avg_duration_ms INTEGER DEFAULT 0,
    PRIMARY KEY (hour, location, host)
);

CREATE TABLE IF NOT EXISTS user_stats (
    user_name      TEXT PRIMARY KEY,
    location       TEXT NOT NULL,
    last_seen      INTEGER,
    requests_today INTEGER DEFAULT 0,
    requests_total INTEGER DEFAULT 0,
    bytes_total    INTEGER DEFAULT 0,
    first_seen     INTEGER,
    day_marker     TEXT
);
CREATE INDEX IF NOT EXISTS idx_user_lastseen ON user_stats(last_seen);
`

type RequestRecord struct {
	Ts         int64
	Location   string
	UserName   string
	Host       string
	Port       int
	Status     string
	BytesIn    int64
	BytesOut   int64
	DurationMs int64
}

type StatsManager struct {
	dbPath   string
	location string
	db       *sql.DB
	recordCh chan RequestRecord
	stopCh   chan struct{}
	wg       sync.WaitGroup
	enabled  bool
}

func NewStatsManager(dbPath, location string) *StatsManager {
	if dbPath == "" {
		return &StatsManager{enabled: false}
	}

	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		log.Printf("[Stats] Warning: Failed to open SQLite database %s: %v", dbPath, err)
		return &StatsManager{enabled: false}
	}

	// Optimize connection pool for SQLite WAL
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)

	if _, err := db.Exec(statsSchema); err != nil {
		log.Printf("[Stats] Warning: Failed to initialize schema: %v", err)
		_ = db.Close()
		return &StatsManager{enabled: false}
	}

	sm := &StatsManager{
		dbPath:   dbPath,
		location: location,
		db:       db,
		recordCh: make(chan RequestRecord, maxStatsBuffer),
		stopCh:   make(chan struct{}),
		enabled:  true,
	}

	sm.wg.Add(1)
	go sm.worker()

	log.Printf("[Stats] Telemetry logging active in SQLite: %s (Location: %s)", dbPath, location)
	return sm
}

func (sm *StatsManager) Record(user, host string, port int, status string, bytesIn, bytesOut, durationMs int64) {
	if !sm.enabled {
		return
	}

	h := strings.ToLower(strings.TrimSpace(host))
	if idx := strings.Index(h, ":"); idx != -1 && !strings.HasPrefix(h, "[") {
		h = h[:idx]
	}
	h = strings.TrimSuffix(h, ".")
	if h == "" {
		h = "-"
	}
	if user == "" {
		user = "-"
	}

	rec := RequestRecord{
		Ts:         time.Now().Unix(),
		Location:   sm.location,
		UserName:   user,
		Host:       h,
		Port:       port,
		Status:     status,
		BytesIn:    bytesIn,
		BytesOut:   bytesOut,
		DurationMs: durationMs,
	}

	select {
	case sm.recordCh <- rec:
	default:
		// Drop silently if channel buffer is full to preserve proxy throughput
	}
}

func (sm *StatsManager) worker() {
	defer sm.wg.Done()

	ticker := time.NewTicker(flushInterval)
	cleanupTicker := time.NewTicker(1 * time.Hour)
	defer ticker.Stop()
	defer cleanupTicker.Stop()

	var batch []RequestRecord

	flush := func() {
		if len(batch) == 0 {
			return
		}
		sm.insertBatch(batch)
		batch = batch[:0]
	}

	for {
		select {
		case rec := <-sm.recordCh:
			batch = append(batch, rec)
			if len(batch) >= batchSize {
				flush()
			}
		case <-ticker.C:
			flush()
		case <-cleanupTicker.C:
			sm.cleanupOldLogs()
		case <-sm.stopCh:
			// Drain remaining records
			for {
				select {
				case rec := <-sm.recordCh:
					batch = append(batch, rec)
				default:
					flush()
					return
				}
			}
		}
	}
}

func (sm *StatsManager) insertBatch(records []RequestRecord) {
	if len(records) == 0 || sm.db == nil {
		return
	}

	tx, err := sm.db.Begin()
	if err != nil {
		log.Printf("[Stats] Error beginning transaction: %v", err)
		return
	}
	defer func() { _ = tx.Rollback() }()

	stmtRaw, err := tx.Prepare(`
		INSERT INTO raw_requests
		(ts, location, user_name, host, port, status, bytes_in, bytes_out, duration_ms)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
	`)
	if err != nil {
		log.Printf("[Stats] Error preparing raw insert: %v", err)
		return
	}
	defer stmtRaw.Close()

	for _, r := range records {
		_, err := stmtRaw.Exec(r.Ts, r.Location, r.UserName, r.Host, r.Port, r.Status, r.BytesIn, r.BytesOut, r.DurationMs)
		if err != nil {
			log.Printf("[Stats] Error inserting raw request: %v", err)
		}
	}

	// Update user stats
	today := time.Now().Format("2006-01-02")
	stmtUser, err := tx.Prepare(`
		INSERT INTO user_stats (user_name, location, last_seen, requests_today, requests_total, bytes_total, first_seen, day_marker)
		VALUES (?, ?, ?, 1, 1, ?, ?, ?)
		ON CONFLICT(user_name) DO UPDATE SET
			last_seen = excluded.last_seen,
			requests_today = CASE WHEN user_stats.day_marker = excluded.day_marker THEN user_stats.requests_today + 1 ELSE 1 END,
			requests_total = user_stats.requests_total + 1,
			bytes_total = user_stats.bytes_total + excluded.bytes_total,
			day_marker = excluded.day_marker
	`)
	if err == nil {
		defer stmtUser.Close()
		for _, r := range records {
			if r.UserName == "" || r.UserName == "-" {
				continue
			}
			totalBytes := r.BytesIn + r.BytesOut
			_, _ = stmtUser.Exec(r.UserName, r.Location, r.Ts, totalBytes, r.Ts, today)
		}
	}

	if err := tx.Commit(); err != nil {
		log.Printf("[Stats] Error committing batch: %v", err)
	}
}

func (sm *StatsManager) cleanupOldLogs() {
	if sm.db == nil {
		return
	}
	// Delete raw requests older than 7 days
	cutoff := time.Now().Add(-7 * 24 * time.Hour).Unix()
	_, _ = sm.db.Exec("DELETE FROM raw_requests WHERE ts < ?", cutoff)
}

func (sm *StatsManager) Stop() {
	if !sm.enabled {
		return
	}
	close(sm.stopCh)
	sm.wg.Wait()
	if sm.db != nil {
		_ = sm.db.Close()
	}
}
