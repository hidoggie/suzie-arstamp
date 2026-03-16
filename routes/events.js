// routes/events.js — 유저용 스탬프 투어 API
const express = require('express');
const crypto = require('crypto');
const { pool, withTransaction } = require('../db');

const router = express.Router();

// ─────────────────────────────────────────
//  유틸
// ─────────────────────────────────────────
function generateToken() {
  return crypto.randomBytes(32).toString('hex');
}

function generateRewardCode(prefix = 'BIRD') {
  const n = String(Math.floor(1000 + Math.random() * 9000));
  const ts = Date.now().toString(36).toUpperCase().slice(-3);
  return `${prefix}-${ts}${n}`;
}

async function getEvent(slug) {
  const { rows } = await pool.query(
    'SELECT * FROM events WHERE slug = $1 AND is_active = true',
    [slug]
  );
  return rows[0] || null;
}

// ─────────────────────────────────────────
//  POST /api/events/:slug/sessions
//  세션 생성 또는 기존 세션 복원
// ─────────────────────────────────────────
router.post('/:slug/sessions', async (req, res) => {
  try {
    const event = await getEvent(req.params.slug);
    if (!event) return res.status(404).json({ error: '행사를 찾을 수 없습니다' });

    const { token } = req.body;

    // 기존 토큰으로 복원 시도
    if (token) {
      const { rows } = await pool.query(
        'SELECT * FROM stamp_sessions WHERE token = $1 AND event_id = $2',
        [token, event.id]
      );
      if (rows[0]) {
        return res.json(formatSession(rows[0], event));
      }
    }

    // 새 세션 생성
    const newToken = generateToken();
    const { rows } = await pool.query(
      `INSERT INTO stamp_sessions (token, event_id, stamps)
       VALUES ($1, $2, '{}') RETURNING *`,
      [newToken, event.id]
    );

    res.status(201).json(formatSession(rows[0], event));
  } catch (err) {
    console.error('[sessions POST]', err);
    res.status(500).json({ error: '서버 오류' });
  }
});

// ─────────────────────────────────────────
//  GET /api/events/:slug/sessions/:token
//  세션 상태 조회
// ─────────────────────────────────────────
router.get('/:slug/sessions/:token', async (req, res) => {
  try {
    const event = await getEvent(req.params.slug);
    if (!event) return res.status(404).json({ error: '행사를 찾을 수 없습니다' });

    const { rows } = await pool.query(
      'SELECT * FROM stamp_sessions WHERE token = $1 AND event_id = $2',
      [req.params.token, event.id]
    );
    if (!rows[0]) return res.status(404).json({ error: '세션을 찾을 수 없습니다' });

    res.json(formatSession(rows[0], event));
  } catch (err) {
    console.error('[sessions GET]', err);
    res.status(500).json({ error: '서버 오류' });
  }
});

// ─────────────────────────────────────────
//  POST /api/events/:slug/sessions/:token/stamps
//  스탬프 찍기 (동시 접속 안전 처리)
// ─────────────────────────────────────────
router.post('/:slug/sessions/:token/stamps', async (req, res) => {
  const { bird } = req.body;
  if (!bird) return res.status(400).json({ error: 'bird 필드가 필요합니다' });

  try {
    const event = await getEvent(req.params.slug);
    if (!event) return res.status(404).json({ error: '행사를 찾을 수 없습니다' });

    const targets = event.targets;
    if (!targets.includes(bird)) {
      return res.status(400).json({ error: `유효하지 않은 새입니다: ${bird}` });
    }

    const result = await withTransaction(async (client) => {
      // 세션 잠금 (FOR UPDATE)
      const { rows: sessionRows } = await client.query(
        'SELECT * FROM stamp_sessions WHERE token = $1 AND event_id = $2 FOR UPDATE',
        [req.params.token, event.id]
      );
      if (!sessionRows[0]) throw Object.assign(new Error('세션 없음'), { status: 404 });

      const session = sessionRows[0];
      const already_stamped = !!session.stamps[bird];

      // 이미 찍은 도장이면 현재 상태만 반환
      if (already_stamped) {
        return { session, already_stamped: true, event };
      }

      // 스탬프 추가
      const newStamps = { ...session.stamps, [bird]: true };
      const allDone = targets.every(t => newStamps[t]);

      let rewardCode = session.reward_code;
      let prizeId = session.prize_id;
      let isComplete = session.is_complete;

      // 모든 스탬프 완료 → 경품 코드 발급
      if (allDone && !session.is_complete) {
        isComplete = true;

        // 재고 있는 경품 선택 (stock > 0, sort_order 순)
        const { rows: prizeRows } = await client.query(
          `SELECT * FROM prizes
           WHERE event_id = $1 AND is_active = true AND stock > 0
           ORDER BY sort_order, id
           LIMIT 1
           FOR UPDATE`,
          [event.id]
        );

        if (prizeRows[0]) {
          prizeId = prizeRows[0].id;
          // 재고 1 차감
          await client.query(
            'UPDATE prizes SET stock = stock - 1 WHERE id = $1',
            [prizeId]
          );
        }

        // 고유한 보상 코드 생성 (충돌 방지 재시도)
        let attempts = 0;
        while (!rewardCode && attempts < 5) {
          const candidate = generateRewardCode(
            event.slug.toUpperCase().slice(0, 6)
          );
          const { rows: exist } = await client.query(
            'SELECT 1 FROM stamp_sessions WHERE reward_code = $1',
            [candidate]
          );
          if (!exist[0]) rewardCode = candidate;
          attempts++;
        }
      }

      // 세션 업데이트
      const { rows: updated } = await client.query(
        `UPDATE stamp_sessions
         SET stamps = $1, is_complete = $2, reward_code = $3,
             prize_id = $4, completed_at = $5, updated_at = NOW()
         WHERE token = $6 RETURNING *`,
        [
          JSON.stringify(newStamps),
          isComplete,
          rewardCode,
          prizeId,
          allDone && !session.is_complete ? new Date() : session.completed_at,
          req.params.token,
        ]
      );

      return { session: updated[0], already_stamped: false, event };
    });

    res.json(formatSession(result.session, result.event, result.already_stamped));
  } catch (err) {
    if (err.status === 404) return res.status(404).json({ error: err.message });
    console.error('[stamps POST]', err);
    res.status(500).json({ error: '서버 오류' });
  }
});

// ─────────────────────────────────────────
//  응답 포맷
// ─────────────────────────────────────────
function formatSession(session, event, already_stamped = false) {
  return {
    token: session.token,
    event: { slug: event.slug, name: event.name, targets: event.targets },
    stamps: session.stamps,
    stamp_count: Object.values(session.stamps).filter(Boolean).length,
    total: event.targets.length,
    is_complete: session.is_complete,
    reward_code: session.reward_code,
    already_stamped,
  };
}

module.exports = router;
