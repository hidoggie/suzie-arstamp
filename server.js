// server.js — 메인 서버
require('dotenv').config();

const express = require('express');
const cors    = require('cors');
const path    = require('path');
const fs      = require('fs');
const { initDb, pool } = require('./db');

const app  = express();
const PORT = process.env.PORT || 3000;

app.use(cors({
  origin: process.env.ALLOWED_ORIGINS
    ? process.env.ALLOWED_ORIGINS.split(',')
    : '*',
}));
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// ── API ────────────────────────────────────────────────
app.use('/api/events', require('./routes/events'));
app.use('/api/admin',  require('./routes/admin'));

// 헬스체크 (render.com 모니터링용)
app.get('/health', (req, res) =>
  res.json({ status: 'ok', time: new Date().toISOString() })
);

// ── 관리자 페이지 라우팅 ─────────────────────────────────
// /admin          → 슈퍼관리자 페이지
// /admin/:slug    → 이벤트 담당자 페이지 (slug/name 서버에서 주입)
app.get('/admin', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'super-admin.html'));
});

app.get('/admin/:slug', async (req, res) => {
  try {
    const { rows } = await pool.query(
      'SELECT slug, name FROM events WHERE slug=$1 AND is_active=true',
      [req.params.slug]
    );
    if (!rows[0]) return res.status(404).send('행사를 찾을 수 없습니다');

    let html = fs.readFileSync(
      path.join(__dirname, 'public', 'event-admin.html'), 'utf8'
    );
    // 슬러그와 행사명을 플레이스홀더에 주입
    html = html
      .replace(/__EVENT_SLUG__/g, rows[0].slug)
      .replace(/__EVENT_NAME__/g, rows[0].name);
    res.send(html);
  } catch (err) {
    console.error(err);
    res.status(500).send('서버 오류');
  }
});

// ── 에러 핸들러 ────────────────────────────────────────
app.use((err, req, res, next) => {
  console.error('Unhandled error:', err);
  res.status(500).json({ error: '서버 내부 오류' });
});

// ── 시작 ───────────────────────────────────────────────
async function start() {
  try {
    await initDb();
    app.listen(PORT, '0.0.0.0', () => {
      console.log(`✅ Stamp Tour Server running on port ${PORT}`);
      console.log(`   Environment: ${process.env.NODE_ENV || 'development'}`);
    });
  } catch (err) {
    console.error('❌ Failed to start server:', err);
    process.exit(1);
  }
}

start();
