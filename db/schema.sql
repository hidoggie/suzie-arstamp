-- ============================================================
--  Bird AR Stamp Tour — Database Schema
--  PostgreSQL 17 / render.com
--  슈퍼관리자 + 이벤트별 담당자 2단계 권한
-- ============================================================

-- 행사 테이블
CREATE TABLE IF NOT EXISTS events (
  id           SERIAL PRIMARY KEY,
  slug         VARCHAR(100) UNIQUE NOT NULL,   -- URL용 ID (예: bird-2024, event1)
  name         VARCHAR(255) NOT NULL,
  description  TEXT,
  targets      JSONB NOT NULL DEFAULT '["macaw","puffin","cardinal","blue-jay"]',
  is_active    BOOLEAN DEFAULT true,
  created_at   TIMESTAMPTZ DEFAULT NOW()
);

-- 경품 테이블 (행사당 1개 이상 가능)
CREATE TABLE IF NOT EXISTS prizes (
  id            SERIAL PRIMARY KEY,
  event_id      INTEGER NOT NULL REFERENCES events(id) ON DELETE CASCADE,
  name          VARCHAR(255) NOT NULL DEFAULT '사은품',
  stock         INTEGER NOT NULL DEFAULT 0,
  initial_stock INTEGER NOT NULL DEFAULT 0,
  sort_order    INTEGER DEFAULT 0,
  is_active     BOOLEAN DEFAULT true,
  created_at    TIMESTAMPTZ DEFAULT NOW()
);

-- 스탬프 세션 (유저 1인 = 토큰 1개)
CREATE TABLE IF NOT EXISTS stamp_sessions (
  id           SERIAL PRIMARY KEY,
  token        VARCHAR(64) UNIQUE NOT NULL,
  event_id     INTEGER NOT NULL REFERENCES events(id),
  stamps       JSONB NOT NULL DEFAULT '{}',   -- {macaw: true, puffin: true, ...}
  is_complete  BOOLEAN DEFAULT false,
  reward_code  VARCHAR(20) UNIQUE,
  prize_id     INTEGER REFERENCES prizes(id),
  claimed      BOOLEAN DEFAULT false,
  claimed_at   TIMESTAMPTZ,
  completed_at TIMESTAMPTZ,
  created_at   TIMESTAMPTZ DEFAULT NOW(),
  updated_at   TIMESTAMPTZ DEFAULT NOW()
);

-- ─────────────────────────────────────────────────────────
--  슈퍼관리자 계정 (전체 이벤트 접근, 1개만 존재)
--  비밀번호는 환경변수(SUPER_ADMIN_PASSWORD) 우선,
--  없으면 이 테이블에서 조회
-- ─────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS super_admin (
  id            SERIAL PRIMARY KEY,
  password_hash VARCHAR(255) NOT NULL,
  created_at    TIMESTAMPTZ DEFAULT NOW()
);

-- ─────────────────────────────────────────────────────────
--  이벤트 담당자 계정 (슈퍼관리자가 생성)
--  event_id 와 1:1 매핑 — 해당 이벤트 데이터만 접근 가능
-- ─────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS event_managers (
  id            SERIAL PRIMARY KEY,
  event_id      INTEGER UNIQUE NOT NULL REFERENCES events(id) ON DELETE CASCADE,
  password_hash VARCHAR(255) NOT NULL,
  created_by    INTEGER,               -- super_admin.id (감사 로그용)
  created_at    TIMESTAMPTZ DEFAULT NOW(),
  updated_at    TIMESTAMPTZ DEFAULT NOW()
);

-- 인덱스
CREATE INDEX IF NOT EXISTS idx_sessions_token    ON stamp_sessions(token);
CREATE INDEX IF NOT EXISTS idx_sessions_event    ON stamp_sessions(event_id);
CREATE INDEX IF NOT EXISTS idx_sessions_code     ON stamp_sessions(reward_code);
CREATE INDEX IF NOT EXISTS idx_sessions_complete ON stamp_sessions(event_id, is_complete);
CREATE INDEX IF NOT EXISTS idx_prizes_event      ON prizes(event_id);
CREATE INDEX IF NOT EXISTS idx_managers_event    ON event_managers(event_id);
