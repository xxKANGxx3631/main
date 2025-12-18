const express = require('express');
const cors = require('cors');
const axios = require('axios');
const { kv } = require('@vercel/kv');

const app = express();

// CORS 설정
app.use(cors({
    origin: '*',  // 모든 origin 허용 (로블록스 포함)
    credentials: false,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization', 'x-api-key', 'User-Agent']
}));

// OPTIONS preflight 요청 처리
app.options('*', cors());

app.use(express.json());

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
app.get('/api/whitelist/:userId', async (req, res) => {
    const { userId } = req.params;
    
    // CORS 헤더 명시적 추가
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET, OPTIONS');
    res.setHeader('Content-Type', 'application/json');
    
    try {
        const user = await kv.hgetall(`whitelist:${userId}`);
        
        if (user && Object.keys(user).length > 0) {
            res.json({
                wl: user.wl || 'no',
                tier: user.tier || null,
                username: user.username || null
            });
        } else {
            res.json({
                wl: 'no',
                tier: null,
                username: null
            });
        }
    } catch (error) {
        console.error('KV error:', error);
        res.status(500).json({ error: 'Database error' });
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
        
        await kv.hset(`whitelist:${userId}`, {
            username: username,
            wl: 'yes',
            tier: tier,
            addedAt: new Date().toISOString()
        });
        
        res.json({
            success: true,
            userId: userId,
            data: {
                username: username,
                wl: 'yes',
                tier: tier
            }
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
        
        const exists = await kv.exists(`whitelist:${userId}`);
        if (exists) {
            await kv.del(`whitelist:${userId}`);
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
app.get('/api/admin/whitelist', requireAuth, async (req, res) => {
    try {
        const keys = await kv.keys('whitelist:*');
        const whitelist = {};
        
        for (const key of keys) {
            const userId = key.replace('whitelist:', '');
            whitelist[userId] = await kv.hgetall(key);
        }
        
        res.json({
            count: keys.length,
            data: whitelist
        });
    } catch (error) {
        console.error('Get whitelist error:', error);
        res.status(500).json({ error: 'Internal error' });
    }
});

// ============= 게임 블랙리스트 API =============

// 게임 블랙리스트 확인
app.get('/api/game/:placeId', async (req, res) => {
    const { placeId } = req.params;
    
    try {
        const game = await kv.hgetall(`game:${placeId}`);
        
        res.json({
            blacklisted: game?.blacklisted || 'no',
            reason: game?.reason || null
        });
    } catch (error) {
        console.error('Get game error:', error);
        res.status(500).json({ error: 'Internal error' });
    }
});

// 게임 블랙리스트 추가/수정 (관리자)
app.post('/api/game/:placeId', requireAuth, async (req, res) => {
    const { placeId } = req.params;
    const { blacklisted = 'yes', reason } = req.body;
    
    try {
        await kv.hset(`game:${placeId}`, {
            blacklisted: blacklisted,
            reason: reason || null,
            updatedAt: new Date().toISOString()
        });
        
        const game = await kv.hgetall(`game:${placeId}`);
        
        res.json({
            success: true,
            data: game
        });
    } catch (error) {
        console.error('Update game error:', error);
        res.status(500).json({ error: 'Internal error' });
    }
});

// 전체 블랙리스트 조회 (관리자)
app.get('/api/admin/games', requireAuth, async (req, res) => {
    try {
        const keys = await kv.keys('game:*');
        const games = {};
        
        for (const key of keys) {
            const placeId = key.replace('game:', '');
            games[placeId] = await kv.hgetall(key);
        }
        
        res.json({
            count: keys.length,
            data: games
        });
    } catch (error) {
        console.error('Get games error:', error);
        res.status(500).json({ error: 'Internal error' });
    }
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
