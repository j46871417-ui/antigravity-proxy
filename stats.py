"""
stats.py — Модуль сбора статистики запросов Antigravity Proxy.

Назначение:
  Собирать метрики CONNECT-запросов без замедления основного цикла прокси.
  Буферизация в памяти + пакетная запись в SQLite раз в N секунд.

Использование в proxy.py:

    from stats import RequestStats
    STATS = RequestStats("/opt/antigravity_proxy/stats.db", location="it")

    # при каждом CONNECT:
    STATS.log(user, host, port, status, bytes_in, bytes_out, duration_ms)

    # при старте:
    STATS.start()   # запускает фоновый flush-loop

    # при остановке:
    STATS.stop()

ВАЖНО: модуль не должен бросать исключения наружу — прокси важнее статистики.
Любая ошибка логируется и глотается.
"""

import os
import sys
import time
import sqlite3
import threading
import logging
from collections import deque

log = logging.getLogger("stats")

# --- Константы ---
FLUSH_INTERVAL = 30        # секунд между пакетными записями
AGGREGATE_INTERVAL = 300   # секунд между агрегациями (5 мин)
RAW_RETENTION_DAYS = 7     # сырые логи храним 7 дней
HOURLY_RETENTION_DAYS = 90 # часовые агрегаты храним 90 дней
MAX_BUFFER = 5000          # предохранитель от утечки памяти


SCHEMA = """
PRAGMA journal_mode=WAL;
PRAGMA synchronous=NORMAL;

-- Сырые запросы (для расследования инцидентов, короткое хранение)
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

-- Часовые агрегаты (основная таблица для отчётов)
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

-- Активность пользователей (обновляется инкрементально)
CREATE TABLE IF NOT EXISTS user_stats (
    user_name     TEXT PRIMARY KEY,
    location      TEXT,
    last_seen     INTEGER,
    requests_today INTEGER DEFAULT 0,
    requests_total INTEGER DEFAULT 0,
    bytes_total    INTEGER DEFAULT 0,
    first_seen     INTEGER,
    day_marker     TEXT
);
CREATE INDEX IF NOT EXISTS idx_user_lastseen ON user_stats(last_seen);

-- Здоровье локаций (для умного fallback)
CREATE TABLE IF NOT EXISTS location_health (
    ts              INTEGER NOT NULL,
    location        TEXT    NOT NULL,
    window_minutes  INTEGER,
    success_rate    REAL,
    geoblock_rate   REAL,
    error_rate      REAL,
    active_users    INTEGER,
    health_score    REAL,
    PRIMARY KEY (ts, location)
);

-- Метаданные (версия схемы и пр.)
CREATE TABLE IF NOT EXISTS meta (
    key   TEXT PRIMARY KEY,
    value TEXT
);
"""


class RequestStats:
    """Сборщик статистики с буферизацией.

    Потокобезопасен: proxy.py работает в отдельных потоках на каждое соединение.
    """

    def __init__(self, db_path, location="it"):
        self.db_path = db_path
        self.location = location
        self.buffer = deque(maxlen=MAX_BUFFER)
        self.lock = threading.Lock()
        self._stop = threading.Event()
        self._thread = None
        self._counters = {"logged": 0, "dropped": 0, "errors": 0}
        self._last_aggregate = 0

    # ---------- Инициализация ----------

    def init_db(self):
        """Создаёт схему. Безопасно вызывать повторно."""
        try:
            conn = sqlite3.connect(self.db_path, timeout=10)
            conn.executescript(SCHEMA)
            conn.execute(
                "INSERT OR REPLACE INTO meta(key, value) VALUES('schema_version', '1')")
            conn.commit()
            conn.close()
            log.info("stats: схема готова (%s)", self.db_path)
            return True
        except Exception as e:
            log.error("stats: не удалось создать схему: %s", e)
            return False

    # ---------- Публичный API ----------

    def log(self, user, host, port, status,
            bytes_in=0, bytes_out=0, duration_ms=0):
        """Регистрирует запрос. Никогда не бросает исключения.

        status: 'allowed' | 'blocked_whitelist' | 'blocked_auth'
                | 'error' | 'geoblock'

        Хост нормализуется здесь: убираем порт, приводим к нижнему регистру.
        Так 'example.com:443' и 'example.com' не раздваивают статистику.
        """
        try:
            h = (host or "-").strip().lower()
            # отрезаем порт, если он приклеен к хосту
            if h.count(":") == 1 and not h.startswith("["):
                maybe_host, maybe_port = h.rsplit(":", 1)
                if maybe_port.isdigit():
                    if not port:
                        port = int(maybe_port)
                    h = maybe_host
            h = h.rstrip(".") or "-"

            with self.lock:
                self.buffer.append((
                    int(time.time()), self.location, user or "-",
                    h, int(port or 0), status,
                    int(bytes_in or 0), int(bytes_out or 0), int(duration_ms or 0),
                ))
                self._counters["logged"] += 1
        except Exception:
            self._counters["errors"] += 1

    def start(self):
        """Запускает фоновый поток записи."""
        if self._thread and self._thread.is_alive():
            return
        self._stop.clear()
        self._thread = threading.Thread(target=self._loop, daemon=True,
                                        name="stats-flush")
        self._thread.start()
        log.info("stats: фоновый поток запущен (location=%s)", self.location)

    def stop(self):
        self._stop.set()
        self._flush()  # финальный сброс

    def counters(self):
        return dict(self._counters)

    # ---------- Внутреннее ----------

    def _loop(self):
        """Периодический сброс буфера и агрегация."""
        last_cleanup = 0
        while not self._stop.wait(FLUSH_INTERVAL):
            try:
                self._flush()
                now = time.time()
                if now - self._last_aggregate > AGGREGATE_INTERVAL:
                    self._aggregate()
                    self._last_aggregate = now
                if now - last_cleanup > 3600:
                    self._cleanup()
                    last_cleanup = now
            except Exception as e:
                log.error("stats: ошибка в цикле: %s", e)

    def _flush(self):
        """Пакетная запись буфера в SQLite."""
        with self.lock:
            if not self.buffer:
                return
            batch = list(self.buffer)
            self.buffer.clear()

        try:
            conn = sqlite3.connect(self.db_path, timeout=15)
            conn.executemany(
                """INSERT INTO raw_requests
                   (ts, location, user_name, host, port, status,
                    bytes_in, bytes_out, duration_ms)
                   VALUES (?,?,?,?,?,?,?,?,?)""",
                batch)
            self._update_users(conn, batch)
            conn.commit()
            conn.close()
        except Exception as e:
            log.error("stats: flush не удался (%d записей потеряно): %s",
                      len(batch), e)
            self._counters["dropped"] += len(batch)

    def _update_users(self, conn, batch):
        """Инкрементальное обновление user_stats."""
        today = time.strftime("%Y-%m-%d")
        agg = {}
        for (ts, loc, user, host, port, status, bi, bo, dur) in batch:
            if not user or user == "-":
                continue
            a = agg.setdefault(user, {"n": 0, "b": 0, "last": 0})
            a["n"] += 1
            a["b"] += bi + bo
            a["last"] = max(a["last"], ts)

        for user, a in agg.items():
            cur = conn.execute(
                "SELECT requests_today, requests_total, bytes_total, day_marker, first_seen "
                "FROM user_stats WHERE user_name=?", (user,))
            row = cur.fetchone()
            if row is None:
                conn.execute(
                    """INSERT INTO user_stats
                       (user_name, location, last_seen, requests_today,
                        requests_total, bytes_total, first_seen, day_marker)
                       VALUES (?,?,?,?,?,?,?,?)""",
                    (user, self.location, a["last"], a["n"],
                     a["n"], a["b"], a["last"], today))
            else:
                req_today, req_total, bytes_total, marker, first_seen = row
                if marker != today:
                    req_today = 0
                conn.execute(
                    """UPDATE user_stats
                       SET last_seen=?, requests_today=?, requests_total=?,
                           bytes_total=?, day_marker=?, location=?
                       WHERE user_name=?""",
                    (a["last"], req_today + a["n"], req_total + a["n"],
                     bytes_total + a["b"], today, self.location, user))

    def _aggregate(self):
        """Сворачивает сырые логи в часовые агрегаты."""
        try:
            conn = sqlite3.connect(self.db_path, timeout=20)
            cutoff = int(time.time()) - 7200  # последние 2 часа

            conn.execute("""
                INSERT INTO hourly_stats
                    (hour, location, host, allowed_count, blocked_count,
                     error_count, geoblock_count, total_bytes, unique_users,
                     avg_duration_ms)
                SELECT
                    (ts / 3600) * 3600 AS hour,
                    location,
                    host,
                    SUM(CASE WHEN status='allowed' THEN 1 ELSE 0 END),
                    SUM(CASE WHEN status LIKE 'blocked%' THEN 1 ELSE 0 END),
                    SUM(CASE WHEN status='error' THEN 1 ELSE 0 END),
                    SUM(CASE WHEN status='geoblock' THEN 1 ELSE 0 END),
                    SUM(bytes_in + bytes_out),
                    COUNT(DISTINCT user_name),
                    CAST(AVG(duration_ms) AS INTEGER)
                FROM raw_requests
                WHERE ts >= ?
                GROUP BY hour, location, host
                ON CONFLICT(hour, location, host) DO UPDATE SET
                    allowed_count  = excluded.allowed_count,
                    blocked_count  = excluded.blocked_count,
                    error_count    = excluded.error_count,
                    geoblock_count = excluded.geoblock_count,
                    total_bytes    = excluded.total_bytes,
                    unique_users   = excluded.unique_users,
                    avg_duration_ms= excluded.avg_duration_ms
            """, (cutoff,))

            conn.commit()
            conn.close()
        except Exception as e:
            log.error("stats: агрегация не удалась: %s", e)

    def _cleanup(self):
        """Удаляет устаревшие записи."""
        try:
            conn = sqlite3.connect(self.db_path, timeout=20)
            raw_cut = int(time.time()) - RAW_RETENTION_DAYS * 86400
            hr_cut = int(time.time()) - HOURLY_RETENTION_DAYS * 86400
            n1 = conn.execute("DELETE FROM raw_requests WHERE ts < ?", (raw_cut,)).rowcount
            n2 = conn.execute("DELETE FROM hourly_stats WHERE hour < ?", (hr_cut,)).rowcount
            conn.commit()
            conn.close()
            if n1 or n2:
                log.info("stats: очистка — удалено %d сырых, %d часовых", n1, n2)
        except Exception as e:
            log.error("stats: очистка не удалась: %s", e)


def compute_health(db_path, location, window_minutes=15):
    """Считает health score локации за окно. Возвращает dict.

    Используется умным fallback (Фаза 4).

    ВАЖНО про latency: длительность соединения в этом прокси НЕ является
    задержкой. Antigravity держит SSE-стрим открытым, пока идёт генерация
    кода — типичное соединение живёт 4-15 минут. Поэтому latency
    исключена из health score: она измеряет время работы пользователя,
    а не качество канала.

    Вместо неё учитываются показатели, которые действительно говорят
    о здоровье локации:
      - success_rate   (доля успешных CONNECT)
      - geoblock_rate  (доля запросов, отвергнутых Google по геолокации)
      - error_rate     (доля сбоев подключения к цели)
      - active_users   (жива ли локация вообще)
    """
    try:
        conn = sqlite3.connect(db_path, timeout=10)
        since = int(time.time()) - window_minutes * 60
        cur = conn.execute("""
            SELECT
                COUNT(*) AS total,
                SUM(CASE WHEN status='allowed' THEN 1 ELSE 0 END) AS ok,
                SUM(CASE WHEN status='geoblock' THEN 1 ELSE 0 END) AS geo,
                SUM(CASE WHEN status='error' THEN 1 ELSE 0 END) AS err,
                SUM(CASE WHEN status='blocked_auth' THEN 1 ELSE 0 END) AS auth_blocked,
                COUNT(DISTINCT CASE WHEN status != 'blocked_auth' THEN user_name END) AS users
            FROM raw_requests
            WHERE location=? AND ts >= ?
        """, (location, since))
        row = cur.fetchone()
        conn.close()

        total, ok, geo, err, auth_blocked, users = row
        total = total or 0
        ok = ok or 0
        geo = geo or 0
        err = err or 0
        auth_blocked = auth_blocked or 0
        users = users or 0

        # Исключаем спам старых/отозванных паролей из оценки качества сети
        valid_total = total - auth_blocked

        if valid_total <= 0:
            return {"location": location, "samples": total, "health_score": 1.0 if total > 0 else None,
                    "success_rate": 1.0 if total > 0 else None, "geoblock_rate": 0.0,
                    "error_rate": 0.0, "avg_latency_ms": 0, "active_users": users}

        success_rate = ok / valid_total
        geo_rate = geo / valid_total
        err_rate = err / valid_total

        # Веса: успешность 50%, гео-блоки 30%, сбои 10%, активность 10%
        score = (success_rate * 0.5 +
                 (1.0 - geo_rate) * 0.3 +
                 (1.0 - err_rate) * 0.1 +
                 min(users / 5.0, 1.0) * 0.1)

        return {
            "location": location,
            "samples": total,
            "health_score": round(score, 3),
            "success_rate": round(success_rate, 3),
            "geoblock_rate": round(geo_rate, 3),
            "error_rate": round(err_rate, 3),
            "avg_latency_ms": 0,  # не используется как метрика здоровья
            "active_users": users,
        }
    except Exception as e:
        log.error("stats: compute_health не удался: %s", e)
        return {"location": location, "samples": 0, "health_score": None,
                "success_rate": None, "geoblock_rate": None,
                "error_rate": None, "avg_latency_ms": 0, "active_users": 0}


# ---------- CLI для отладки ----------
if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO,
                        format="%(asctime)s [%(levelname)s] %(message)s")
    cmd = sys.argv[1] if len(sys.argv) > 1 else "init"
    path = sys.argv[2] if len(sys.argv) > 2 else "/opt/antigravity_proxy/stats.db"
    loc = sys.argv[3] if len(sys.argv) > 3 else "it"

    if cmd == "init":
        s = RequestStats(path, loc)
        print("OK" if s.init_db() else "FAIL")

    elif cmd == "health":
        import json
        print(json.dumps(compute_health(path, loc, 60), indent=2))

    elif cmd == "summary":
        conn = sqlite3.connect(path)
        print("=== Сырых записей ===")
        for r in conn.execute(
                "SELECT location, status, COUNT(*) FROM raw_requests "
                "GROUP BY location, status ORDER BY 3 DESC"):
            print("  %-4s %-18s %d" % r)
        print("=== Топ хостов (24ч) ===")
        since = int(time.time()) - 86400
        for r in conn.execute(
                "SELECT host, COUNT(*) FROM raw_requests WHERE ts>=? "
                "GROUP BY host ORDER BY 2 DESC LIMIT 10", (since,)):
            print("  %-50s %d" % r)
        print("=== Активные пользователи ===")
        n = conn.execute("SELECT COUNT(*) FROM user_stats").fetchone()[0]
        print("  всего:", n)
        conn.close()
