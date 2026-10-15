package main

import (
	"encoding/json"
	"log"
	"os"
	"sync"
	"time"
)

type TrafficData struct {
	Month   string           `json:"month"`
	Traffic map[string]int64 `json:"traffic"`
}

type TrafficManager struct {
	mu         sync.Mutex
	filePath   string
	limitBytes int64
	month      string
	userBytes  map[string]int64
}

func NewTrafficManager(filePath string, limitBytes int64) *TrafficManager {
	tm := &TrafficManager{
		filePath:   filePath,
		limitBytes: limitBytes,
		month:      time.Now().Format("2006-01"),
		userBytes:  make(map[string]int64),
	}
	tm.load()
	return tm
}

func (tm *TrafficManager) load() {
	if tm.filePath == "" {
		return
	}
	data, err := os.ReadFile(tm.filePath)
	if err != nil {
		return
	}
	var td TrafficData
	if err := json.Unmarshal(data, &td); err == nil && td.Month == tm.month {
		tm.userBytes = td.Traffic
		log.Printf("[Traffic] Loaded traffic records for %d users (%s)", len(tm.userBytes), tm.month)
	}
}

func (tm *TrafficManager) Flush() {
	if tm.filePath == "" {
		return
	}
	tm.mu.Lock()
	td := TrafficData{
		Month:   tm.month,
		Traffic: make(map[string]int64, len(tm.userBytes)),
	}
	for k, v := range tm.userBytes {
		td.Traffic[k] = v
	}
	tm.mu.Unlock()

	data, err := json.Marshal(td)
	if err != nil {
		return
	}

	tmpFile := tm.filePath + ".tmp"
	if err := os.WriteFile(tmpFile, data, 0644); err == nil {
		_ = os.Rename(tmpFile, tm.filePath)
	}
}

func (tm *TrafficManager) Record(user string, bytes int64) {
	if user == "" || bytes <= 0 {
		return
	}
	curMonth := time.Now().Format("2006-01")

	tm.mu.Lock()
	defer tm.mu.Unlock()

	if curMonth != tm.month {
		tm.month = curMonth
		tm.userBytes = make(map[string]int64)
	}

	tm.userBytes[user] += bytes
}

func (tm *TrafficManager) IsThrottled(user string) bool {
	if tm.limitBytes <= 0 || user == "" {
		return false
	}
	tm.mu.Lock()
	defer tm.mu.Unlock()
	return tm.userBytes[user] > tm.limitBytes
}

func (tm *TrafficManager) StartFlushLoop(stopCh <-chan struct{}) {
	ticker := time.NewTicker(60 * time.Second)
	go func() {
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				tm.Flush()
			case <-stopCh:
				tm.Flush()
				return
			}
		}
	}()
}
