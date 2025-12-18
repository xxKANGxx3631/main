const express = require('express');
const cors = require('cors');
const axios = require('axios');

const app = express();

// CORS 설정
app.use(cors({
origin: true,
credentials: true,
methods: ['GET', 'POST', 'PUT', 'DELETE'],
allowedHeaders: ['Content-Type', 'Authorization', 'x-api-key']
}));

app.use(express.json());

// 인메모리 저장소
let whitelist = {};
let gameBlacklist = {};

// API 키 검증
const API_SECRET = process.env.API_SECRET || 'dnpqgnrrkdxorud3631A!';

const requireAuth = (req, res, next) => {
const apiKey = req.headers['x-api-key'];
if (apiKey !== API_SECRET) {
return res.status(403).json({ error: 'Forbidden' });
}
next();
};

// Axios 인스턴스 생성
const createAxios = () => {
return axios.create({
timeout: 10000,
headers: {
'User-Agent': 'Mozilla/5.0',
'Accept': 'application/json'
}
});
};

// 유틸리티: 유저네임 → User ID
const getUserId = async (username) => {
try {
const api = createAxios();
const response = await api.post('https://users.roproxy.com/v1/usernames/users', {
usernames: [username.trim()]
});
return response.data?.data?.[0]?.id || null;
} catch (error) {
console.error('getUserId error:', error.message);
return null;
}
};

// ============= 화이트리스트 API =============

// 화이트리스트 확인
app.get('/api/whitelist/:userId', (req, res) => {
const { userId } = req.params;

const user = whitelist[userId];
if (user) {
res.json({
wl: user.wl,
tier: user.tier,
username: user.username
});
} else {
res.json({
wl: 'no',
tier: null,
username: null
});
}
});

// 화이트리스트 추가 (유저네임)
app.post('/api/whitelist', async (req, res) => {
const { username, tier = 'regular' } = req.body;

if (!username) {
return res.status(400).json({ error: 'Username required' });
}

try {
const userId = await getUserId(username);
if (!userId) {
return res.status(404).json({ error: 'User not found' });
}

whitelist[userId] = {
username: username,
wl: 'yes',
tier: tier,
addedAt: new Date().toISOString()
};

res.json({
success: true,
userId: userId,
data: whitelist[userId]
});
} catch (error) {
console.error('Add whitelist error:', error);
res.status(500).json({ error: 'Internal error' });
}
});

// 화이트리스트 삭제 (유저네임)
app.delete('/api/whitelist', async (req, res) => {
const { username } = req.body;

if (!username) {
return res.status(400).json({ error: 'Username required' });
}

try {
const userId = await getUserId(username);
if (!userId) {
return res.status(404).json({ error: 'User not found' });
}

if (whitelist[userId]) {
delete whitelist[userId];
res.json({ success: true, message: 'Removed from whitelist' });
} else {
res.status(404).json({ error: 'Not in whitelist' });
}
} catch (error) {
console.error('Delete whitelist error:', error);
res.status(500).json({ error: 'Internal error' });
}
});

// 전체 화이트리스트 조회 (관리자)
app.get('/api/admin/whitelist', requireAuth, (req, res) => {
res.json({
count: Object.keys(whitelist).length,
data: whitelist
});
});

// ============= 게임 블랙리스트 API =============

// 게임 블랙리스트 확인
app.get('/api/game/:placeId', (req, res) => {
const { placeId } = req.params;

const game = gameBlacklist[placeId];
res.json({
blacklisted: game?.blacklisted || 'no',
reason: game?.reason || null
});
});

// 게임 블랙리스트 추가/수정 (관리자)
app.post('/api/game/:placeId', requireAuth, (req, res) => {
const { placeId } = req.params;
const { blacklisted = 'yes', reason } = req.body;

gameBlacklist[placeId] = {
blacklisted: blacklisted,
reason: reason || null,
updatedAt: new Date().toISOString()
};

res.json({
success: true,
data: gameBlacklist[placeId]
});
});

// 전체 블랙리스트 조회 (관리자)
app.get('/api/admin/games', requireAuth, (req, res) => {
res.json({
count: Object.keys(gameBlacklist).length,
data: gameBlacklist
});
});

// ============= 웹훅 API =============

app.get('/api/webhook/a', (req, res) => {
res.json({
hook: "https://discord.com/api/webhooks/1447049446557876436/O3r1MBehqyZ0gif__mAb12QZ9kiMC7EG6uDTKL8I6ytWG-Q5WT-HoOjpX5Yz09MgBEs_"
});
});

app.get('/api/webhook/g', (req, res) => {
res.json({
hook: "https://discord.com/api/webhooks/1447049446557876436/O3r1MBehqyZ0gif__mAb12QZ9kiMC7EG6uDTKL8I6ytWG-Q5WT-HoOjpX5Yz09MgBEs_"
});
});

app.get('/api/webhook/h', (req, res) => {
res.json({
hook: "https://discord.com/api/webhooks/1447049446557876436/O3r1MBehqyZ0gif__mAb12QZ9kiMC7EG6uDTKL8I6ytWG-Q5WT-HoOjpX5Yz09MgBEs_"
});
});

// 웹훅 전송 (관리자)
app.post('/api/webhook/send', requireAuth, async (req, res) => {
const { content } = req.body;

if (!content || content.length > 2000) {
return res.status(400).json({ error: 'Invalid content' });
}

try {
const WEBHOOK_URL = "https://discord.com/api/webhooks/1396424351418552350/CSjr1Sxayqsa0WEOFhRt6g1TayZsqe9CIemhtNxlwUoITi2wxMYAUwnconye2BMFooFa";

const api = createAxios();
await api.post(WEBHOOK_URL, { content });

res.json({ success: true });
} catch (error) {
console.error('Webhook error:', error);
res.status(500).json({ error: 'Failed to send webhook' });
}
});

// ============= 애셋 API =============

app.get('/api/asset/p', (req, res) => {
    res.json({ assetId: 125300653766343 });
    res.json({ assetId: 108057164912977 });
});

app.get('/api/asset/t', (req, res) => {
res.json({ assetId: 77589013654495 });
});

app.get('/api/asset/bypass', (req, res) => {
res.json({ assetId: 111484144633506 });
});

// ============= 스크립트 API =============

app.get('/api/script', async (req, res) => {
try {
const api = createAxios();
const response = await api.get('https://raw.githubusercontent.com/xxKANGxx3631/Nyphor/refs/heads/main/Nyphor.lua');

res.setHeader('Content-Type', 'text/plain');
res.send(response.data);
} catch (error) {
console.error('Script fetch error:', error);
res.status(500).json({ error: 'Failed to fetch script' });
}
});

// ============= 헬스체크 =============

app.get('/', (req, res) => {
res.json({
name: 'Roblox Whitelist API',
version: '2.0.0',
status: 'running'
});
});

app.get('/health', (req, res) => {
res.json({
status: 'OK',
timestamp: new Date().toISOString()
});
});

// 404 핸들러
app.use('*', (req, res) => {
res.status(404).json({ error: 'Endpoint not found' });
});

// 에러 핸들러
app.use((err, req, res, next) => {
console.error('Error:', err);
res.status(500).json({ error: 'Internal server error' });
});

module.exports = app;
