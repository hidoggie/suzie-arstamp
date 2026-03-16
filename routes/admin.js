// routes/admin.js — 관리자 API
// ┌─────────────────────────────────────────────────────────┐
// │  권한 구조                                               │
// │  슈퍼관리자(super) : 전체 이벤트 조회/생성, 담당자 생성   │
// │  이벤트담당자(manager) : 자신의 이벤트 1개만 접근         │
// │                                                         │
// │  URL 구조                                               │
// │  /admin          → 슈퍼관리자 로그인                     │
// │  /admin/event1   → event1 담당자 로그인                  │
// └─────────────────────────────────────────────────────────┘

const express = require('express');
const bcrypt  = require('bcrypt');
const jwt     = require('jsonwebtoken');
const { pool, withTransaction } = require('../db');

const router      = express.Router();
const JWT_SECRET  = process.env.JWT_SECRET || 'change_this_secret';
const SALT_ROUNDS = 10;

// ─────────────────────────────────────────
//  JWT 미들웨어 팩토리
// ─────────────────────────────────────────

/** 인증만 검사 (role 무관) */
function requireAuth(req, res, next) {
  const auth = req.headers.authorization;
  if (!auth?.startsWith('Bearer ')) {
    return res.status(401).json({ error: '인증이 필요합니다' });
  }
  try {
    req.admin = jwt.verify(auth.slice(7), JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ error: '토큰이 만료되었거나 유효하지 않습니다' });
  }
}

/** 슈퍼관리자만 허용 */
function requireSuper(req, res, next) {
  if (req.admin?.role !== 'super') {
    return res.status(403).json({ error: '슈퍼관리자 권한이 필요합니다' });
  }
  next();
}

/**
 * 이벤트 접근 권한 검사
 * - super : 모든 이벤트 접근 가능
 * - manager : JWT에 저장된 event_slug 와 요청 slug 가 일치해야 함
 */
function requireEventAccess(req, res, next) {
  const slug = req.params.slug;
  if (req.admin.role === 'super') return next();
  if (req.admin.role === 'manager' && req.admin.event_slug === slug) return next();
  return res.status(403).json({ error: '해당 이벤트에 대한 접근 권한이 없습니다' });
}

// ─────────────────────────────────────────
//  유틸
// ─────────────────────────────────────────
function todayStart() {
  const d = new Date();
  d.setHours(0, 0, 0, 0);
  return d;
}

async function getEventBySlug(slug) {
  const { rows } = await pool.query('SELECT * FROM events WHERE slug = $1', [slug]);
  return rows[0] || null;
}

// ═══════════════════════════════════════════════════════════
//  로그인 (공개 엔드포인트)
// ═══════════════════════════════════════════════════════════

/**
 * POST /api/admin/login
 * body: { password }
 * → 슈퍼관리자 로그인, role: 'super'
 */
router.post('/login', async (req, res) => {
  const { password } = req.body;
  if (!password) return res.status(400).json({ error: '비밀번호를 입력하세요' });

  try {
    // 환경변수 우선
    const envPw = process.env.SUPER_ADMIN_PASSWORD;
    if (envPw) {
      if (password !== envPw) {
        return res.status(401).json({ error: '비밀번호가 올바르지 않습니다' });
      }
    } else {
      const { rows } = await pool.query('SELECT password_hash FROM super_admin ORDER BY id LIMIT 1');
      if (!rows[0]) return res.status(401).json({ error: '슈퍼관리자 계정이 설정되지 않았습니다' });
      const match = await bcrypt.compare(password, rows[0].password_hash);
      if (!match) return res.status(401).json({ error: '비밀번호가 올바르지 않습니다' });
    }

    const token = jwt.sign({ role: 'super' }, JWT_SECRET, { expiresIn: '24h' });
    res.json({ token, role: 'super', expires_in: 86400 });
  } catch (err) {
    console.error('[super login]', err);
    res.status(500).json({ error: '서버 오류' });
  }
});

/**
 * POST /api/admin/events/:slug/login
 * body: { password }
 * → 이벤트 담당자 로그인, role: 'manager', event_slug
 */
router.post('/events/:slug/login', async (req, res) => {
  const { password } = req.body;
  if (!password) return res.status(400).json({ error: '비밀번호를 입력하세요' });

  try {
    const event = await getEventBySlug(req.params.slug);
    if (!event) return res.status(404).json({ error: '행사를 찾을 수 없습니다' });

    const { rows } = await pool.query(
      'SELECT password_hash FROM event_managers WHERE event_id = $1',
      [event.id]
    );
    if (!rows[0]) {
      return res.status(401).json({ error: '담당자 계정이 설정되지 않았습니다. 슈퍼관리자에게 문의하세요.' });
    }
    const match = await bcrypt.compare(password, rows[0].password_hash);
    if (!match) return res.status(401).json({ error: '비밀번호가 올바르지 않습니다' });

    const token = jwt.sign(
      { role: 'manager', event_id: event.id, event_slug: event.slug, event_name: event.name },
      JWT_SECRET,
      { expiresIn: '24h' }
    );
    res.json({ token, role: 'manager', event_slug: event.slug, event_name: event.name, expires_in: 86400 });
  } catch (err) {
    console.error('[manager login]', err);
    res.status(500).json({ error: '서버 오류' });
  }
});

// ═══════════════════════════════════════════════════════════
//  이하 인증 필요
// ═══════════════════════════════════════════════════════════
router.use(requireAuth);

// ─────────────────────────────────────────
//  내 정보 (토큰 확인용)
// ─────────────────────────────────────────
router.get('/me', (req, res) => {
  res.json({
    role: req.admin.role,
    event_slug: req.admin.event_slug || null,
    event_name: req.admin.event_name || null,
  });
});

// ═══════════════════════════════════════════════════════════
//  슈퍼관리자 전용 — 이벤트 관리
// ═══════════════════════════════════════════════════════════

/** GET  /api/admin/events  — 전체 이벤트 목록 (슈퍼만) */
router.get('/events', requireSuper, async (req, res) => {
  const { rows } = await pool.query(`
    SELECT e.id, e.slug, e.name, e.description, e.targets, e.is_active, e.created_at,
           CASE WHEN em.id IS NOT NULL THEN true ELSE false END AS has_manager
    FROM events e
    LEFT JOIN event_managers em ON em.event_id = e.id
    ORDER BY e.created_at DESC
  `);
  res.json(rows);
});

/** POST /api/admin/events  — 행사 생성 (슈퍼만) */
router.post('/events', requireSuper, async (req, res) => {
  const { slug, name, description, targets, manager_password } = req.body;
  if (!slug || !name) return res.status(400).json({ error: 'slug, name은 필수입니다' });

  try {
    const result = await withTransaction(async (client) => {
      const { rows } = await client.query(
        `INSERT INTO events (slug, name, description, targets)
         VALUES ($1, $2, $3, $4) RETURNING *`,
        [slug, name, description || null,
         JSON.stringify(targets || ['macaw','puffin','cardinal','blue-jay'])]
      );
      const event = rows[0];

      // 담당자 비밀번호도 함께 설정한 경우
      if (manager_password) {
        const hash = await bcrypt.hash(manager_password, SALT_ROUNDS);
        await client.query(
          `INSERT INTO event_managers (event_id, password_hash) VALUES ($1, $2)`,
          [event.id, hash]
        );
      }
      return event;
    });
    res.status(201).json(result);
  } catch (err) {
    if (err.code === '23505') return res.status(409).json({ error: '이미 사용 중인 slug입니다' });
    console.error('[events POST]', err);
    res.status(500).json({ error: '서버 오류' });
  }
});

/** PATCH /api/admin/events/:slug  — 행사 수정 (슈퍼만) */
router.patch('/events/:slug', requireSuper, async (req, res) => {
  const { name, description, is_active, targets } = req.body;
  const event = await getEventBySlug(req.params.slug);
  if (!event) return res.status(404).json({ error: '행사를 찾을 수 없습니다' });

  const fields = [], vals = [];
  if (name        !== undefined) { fields.push(`name=$${fields.length+1}`);        vals.push(name); }
  if (description !== undefined) { fields.push(`description=$${fields.length+1}`); vals.push(description); }
  if (is_active   !== undefined) { fields.push(`is_active=$${fields.length+1}`);   vals.push(is_active); }
  if (targets     !== undefined) { fields.push(`targets=$${fields.length+1}`);     vals.push(JSON.stringify(targets)); }
  if (!fields.length) return res.status(400).json({ error: '수정할 항목이 없습니다' });

  vals.push(event.id);
  const { rows } = await pool.query(
    `UPDATE events SET ${fields.join(', ')} WHERE id=$${vals.length} RETURNING *`, vals
  );
  res.json(rows[0]);
});

// ─────────────────────────────────────────
//  슈퍼관리자 전용 — 담당자 계정 관리
// ─────────────────────────────────────────

/**
 * POST /api/admin/events/:slug/manager
 * 담당자 계정 생성 또는 비밀번호 재설정 (슈퍼만)
 */
router.post('/events/:slug/manager', requireSuper, async (req, res) => {
  const { password } = req.body;
  if (!password || password.length < 4) {
    return res.status(400).json({ error: '비밀번호는 4자 이상이어야 합니다' });
  }

  const event = await getEventBySlug(req.params.slug);
  if (!event) return res.status(404).json({ error: '행사를 찾을 수 없습니다' });

  try {
    const hash = await bcrypt.hash(password, SALT_ROUNDS);
    await pool.query(
      `INSERT INTO event_managers (event_id, password_hash)
       VALUES ($1, $2)
       ON CONFLICT (event_id) DO UPDATE SET password_hash = $2, updated_at = NOW()`,
      [event.id, hash]
    );
    res.json({ success: true, message: `${event.name} 담당자 비밀번호가 설정되었습니다` });
  } catch (err) {
    console.error('[manager create]', err);
    res.status(500).json({ error: '서버 오류' });
  }
});

/**
 * DELETE /api/admin/events/:slug/manager
 * 담당자 계정 삭제 (슈퍼만)
 */
router.delete('/events/:slug/manager', requireSuper, async (req, res) => {
  const event = await getEventBySlug(req.params.slug);
  if (!event) return res.status(404).json({ error: '행사를 찾을 수 없습니다' });

  await pool.query('DELETE FROM event_managers WHERE event_id = $1', [event.id]);
  res.json({ success: true });
});

/**
 * GET /api/admin/super/stats  — 전체 통계 요약 (슈퍼만)
 */
router.get('/super/stats', requireSuper, async (req, res) => {
  const { rows } = await pool.query(`
    SELECT
      e.id, e.slug, e.name, e.is_active,
      COUNT(s.id) FILTER (WHERE s.is_complete)         AS total,
      COUNT(s.id) FILTER (WHERE s.is_complete AND NOT s.claimed) AS pending,
      COUNT(s.id) FILTER (WHERE s.is_complete AND s.claimed)     AS claimed,
      COUNT(s.id) FILTER (WHERE s.is_complete AND s.completed_at >= $1) AS today,
      COALESCE(SUM(p.stock), 0) AS stock_remaining
    FROM events e
    LEFT JOIN stamp_sessions s ON s.event_id = e.id
    LEFT JOIN prizes p ON p.event_id = e.id AND p.is_active = true
    GROUP BY e.id, e.slug, e.name, e.is_active
    ORDER BY e.created_at DESC
  `, [todayStart()]);
  res.json(rows);
});

/**
 * POST /api/admin/super/password  — 슈퍼관리자 비밀번호 변경 (슈퍼만)
 */
router.post('/super/password', requireSuper, async (req, res) => {
  const { new_password } = req.body;
  if (!new_password || new_password.length < 4) {
    return res.status(400).json({ error: '4자 이상 입력하세요' });
  }
  const hash = await bcrypt.hash(new_password, SALT_ROUNDS);
  await pool.query(
    `INSERT INTO super_admin (password_hash) VALUES ($1)
     ON CONFLICT (id) DO UPDATE SET password_hash = $1`,
    [hash]
  );
  res.json({ success: true });
});

// ═══════════════════════════════════════════════════════════
//  이벤트별 공통 라우트 (슈퍼 + 해당 담당자 접근 가능)
//  requireEventAccess 미들웨어로 권한 분리
// ═══════════════════════════════════════════════════════════

/** GET /api/admin/events/:slug/stats */
router.get('/events/:slug/stats', requireEventAccess, async (req, res) => {
  const event = await getEventBySlug(req.params.slug);
  if (!event) return res.status(404).json({ error: '행사를 찾을 수 없습니다' });

  const { rows } = await pool.query(`
    SELECT
      COUNT(*) FILTER (WHERE is_complete)                      AS total,
      COUNT(*) FILTER (WHERE is_complete AND NOT claimed)      AS pending,
      COUNT(*) FILTER (WHERE is_complete AND claimed)          AS claimed,
      COUNT(*) FILTER (WHERE is_complete AND completed_at>=$2) AS today
    FROM stamp_sessions WHERE event_id=$1
  `, [event.id, todayStart()]);

  const { rows: prizeRows } = await pool.query(
    `SELECT id, name, stock, initial_stock, is_active FROM prizes
     WHERE event_id=$1 ORDER BY sort_order, id`, [event.id]
  );

  const { rows: hourRows } = await pool.query(`
    SELECT EXTRACT(HOUR FROM completed_at)::int AS hour, COUNT(*)::int AS cnt
    FROM stamp_sessions
    WHERE event_id=$1 AND is_complete=true AND completed_at>=$2
    GROUP BY hour ORDER BY hour
  `, [event.id, todayStart()]);

  const hours = Array(24).fill(0);
  hourRows.forEach(r => { hours[r.hour] = r.cnt; });

  res.json({ ...rows[0], event: { slug: event.slug, name: event.name }, prizes: prizeRows, hour_chart: hours });
});

/** GET /api/admin/events/:slug/logs */
router.get('/events/:slug/logs', requireEventAccess, async (req, res) => {
  const event = await getEventBySlug(req.params.slug);
  if (!event) return res.status(404).json({ error: '행사를 찾을 수 없습니다' });

  const { filter, search, limit = 500, offset = 0 } = req.query;

  let where = 'WHERE s.event_id=$1 AND s.is_complete=true';
  const params = [event.id];

  if (filter === 'pending') where += ' AND s.claimed=false';
  if (filter === 'claimed') where += ' AND s.claimed=true';
  if (search) { params.push(`%${search.toUpperCase()}%`); where += ` AND s.reward_code ILIKE $${params.length}`; }

  params.push(limit, offset);
  const { rows } = await pool.query(`
    SELECT s.id, s.reward_code, s.completed_at AS time, s.claimed, s.claimed_at,
           p.name AS prize_name, p.id AS prize_id
    FROM stamp_sessions s
    LEFT JOIN prizes p ON p.id = s.prize_id
    ${where}
    ORDER BY s.completed_at DESC
    LIMIT $${params.length-1} OFFSET $${params.length}
  `, params);

  res.json(rows);
});

/** GET /api/admin/events/:slug/codes/:code — 코드 확인 */
router.get('/events/:slug/codes/:code', requireEventAccess, async (req, res) => {
  const event = await getEventBySlug(req.params.slug);
  if (!event) return res.status(404).json({ error: '행사를 찾을 수 없습니다' });

  const { rows } = await pool.query(`
    SELECT s.reward_code, s.claimed, s.claimed_at, s.completed_at, p.name AS prize_name
    FROM stamp_sessions s
    LEFT JOIN prizes p ON s.prize_id = p.id
    WHERE s.event_id=$1 AND s.reward_code=$2
  `, [event.id, req.params.code.toUpperCase()]);

  if (!rows[0]) return res.json({ valid: false });
  res.json({
    valid: true,
    claimed: rows[0].claimed,
    issued_at: rows[0].completed_at,
    claimed_at: rows[0].claimed_at,
    prize_name: rows[0].prize_name,
  });
});

/** POST /api/admin/events/:slug/codes/:code/claim — 지급 처리 */
router.post('/events/:slug/codes/:code/claim', requireEventAccess, async (req, res) => {
  const event = await getEventBySlug(req.params.slug);
  if (!event) return res.status(404).json({ error: '행사를 찾을 수 없습니다' });

  try {
    const result = await withTransaction(async (client) => {
      const { rows } = await client.query(
        `SELECT * FROM stamp_sessions WHERE event_id=$1 AND reward_code=$2 FOR UPDATE`,
        [event.id, req.params.code.toUpperCase()]
      );
      if (!rows[0]) return { error: '유효하지 않은 코드입니다', status: 404 };
      if (rows[0].claimed) return { error: '이미 수령 처리된 코드입니다', status: 409 };

      await client.query(
        `UPDATE stamp_sessions SET claimed=true, claimed_at=NOW() WHERE id=$1`, [rows[0].id]
      );
      return { success: true, code: rows[0].reward_code };
    });

    if (result.error) return res.status(result.status).json({ error: result.error });
    res.json(result);
  } catch (err) {
    console.error('[claim]', err);
    res.status(500).json({ error: '서버 오류' });
  }
});

/** GET/POST/PUT  경품 관리 */
router.get('/events/:slug/prizes', requireEventAccess, async (req, res) => {
  const event = await getEventBySlug(req.params.slug);
  if (!event) return res.status(404).json({ error: '행사를 찾을 수 없습니다' });
  const { rows } = await pool.query('SELECT * FROM prizes WHERE event_id=$1 ORDER BY sort_order, id', [event.id]);
  res.json(rows);
});

router.post('/events/:slug/prizes', requireEventAccess, async (req, res) => {
  const event = await getEventBySlug(req.params.slug);
  if (!event) return res.status(404).json({ error: '행사를 찾을 수 없습니다' });
  const { name, stock, sort_order = 0 } = req.body;
  if (!name || stock == null) return res.status(400).json({ error: 'name, stock은 필수입니다' });
  const { rows } = await pool.query(
    `INSERT INTO prizes (event_id, name, stock, initial_stock, sort_order) VALUES ($1,$2,$3,$3,$4) RETURNING *`,
    [event.id, name, stock, sort_order]
  );
  res.status(201).json(rows[0]);
});

router.put('/events/:slug/prizes/:id', requireEventAccess, async (req, res) => {
  const event = await getEventBySlug(req.params.slug);
  if (!event) return res.status(404).json({ error: '행사를 찾을 수 없습니다' });

  const { name, set_stock, add_stock, is_active } = req.body;
  const fields = [], vals = [];

  if (name      !== undefined) { fields.push(`name=$${fields.length+1}`);      vals.push(name); }
  if (is_active !== undefined) { fields.push(`is_active=$${fields.length+1}`); vals.push(is_active); }

  if (set_stock != null) {
    fields.push(`stock=$${fields.length+1}`, `initial_stock=$${fields.length+2}`);
    vals.push(set_stock, set_stock);
  } else if (add_stock != null) {
    fields.push(`stock=stock+$${fields.length+1}`, `initial_stock=initial_stock+$${fields.length+2}`);
    vals.push(add_stock, add_stock);
  }
  if (!fields.length) return res.status(400).json({ error: '수정할 항목이 없습니다' });

  vals.push(req.params.id, event.id);
  const { rows } = await pool.query(
    `UPDATE prizes SET ${fields.join(', ')} WHERE id=$${vals.length-1} AND event_id=$${vals.length} RETURNING *`, vals
  );
  if (!rows[0]) return res.status(404).json({ error: '경품을 찾을 수 없습니다' });
  res.json(rows[0]);
});

/** GET /api/admin/events/:slug/export — CSV */
router.get('/events/:slug/export', requireEventAccess, async (req, res) => {
  const event = await getEventBySlug(req.params.slug);
  if (!event) return res.status(404).json({ error: '행사를 찾을 수 없습니다' });

  const { rows } = await pool.query(`
    SELECT s.id, s.reward_code, s.completed_at, s.claimed, s.claimed_at, p.name AS prize_name
    FROM stamp_sessions s
    LEFT JOIN prizes p ON s.prize_id = p.id
    WHERE s.event_id=$1 AND s.is_complete=true ORDER BY s.completed_at
  `, [event.id]);

  const header = '번호,코드,경품명,발급시각,수령여부,수령시각\n';
  const body = rows.map((r, i) =>
    `${i+1},${r.reward_code},${r.prize_name||'없음'},` +
    `${new Date(r.completed_at).toLocaleString('ko-KR')},` +
    `${r.claimed?'완료':'대기'},` +
    `${r.claimed_at ? new Date(r.claimed_at).toLocaleString('ko-KR') : ''}`
  ).join('\n');

  const d = new Date().toISOString().slice(0,10);
  res.setHeader('Content-Type', 'text/csv; charset=utf-8');
  res.setHeader('Content-Disposition', `attachment; filename="stamp_${event.slug}_${d}.csv"`);
  res.send('\uFEFF' + header + body);
});

/** POST /api/admin/events/:slug/password  — 담당자 본인 비밀번호 변경 (해당 manager만) */
router.post('/events/:slug/password', requireEventAccess, async (req, res) => {
  // super는 위 /events/:slug/manager 로 변경, manager는 자신만 변경 가능
  if (req.admin.role === 'super') {
    return res.status(400).json({ error: '슈퍼관리자는 /manager 엔드포인트를 사용하세요' });
  }
  const { new_password } = req.body;
  if (!new_password || new_password.length < 4) {
    return res.status(400).json({ error: '4자 이상 입력하세요' });
  }
  const event = await getEventBySlug(req.params.slug);
  if (!event) return res.status(404).json({ error: '행사를 찾을 수 없습니다' });

  const hash = await bcrypt.hash(new_password, SALT_ROUNDS);
  await pool.query(
    `UPDATE event_managers SET password_hash=$1, updated_at=NOW() WHERE event_id=$2`,
    [hash, event.id]
  );
  res.json({ success: true });
});

/** DELETE /api/admin/events/:slug/logs — 로그 초기화 (슈퍼만) */
router.delete('/events/:slug/logs', requireSuper, async (req, res) => {
  const event = await getEventBySlug(req.params.slug);
  if (!event) return res.status(404).json({ error: '행사를 찾을 수 없습니다' });
  const { confirm } = req.body;
  if (confirm !== 'DELETE') return res.status(400).json({ error: '확인 값이 필요합니다' });
  await pool.query('DELETE FROM stamp_sessions WHERE event_id=$1 AND is_complete=true', [event.id]);
  res.json({ success: true });
});

module.exports = router;
