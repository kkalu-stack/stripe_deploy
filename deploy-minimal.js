// Trontiq Minimal Server Deployment
// Single file deployment - includes all necessary code

const express = require('express');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const { createClient } = require('@supabase/supabase-js');
const cookieParser = require('cookie-parser');
const stripe = require('stripe')(process.env.STRIPE_SECRET_KEY);
const { Redis } = require('@upstash/redis');

// Supabase configuration for direct HTTP requests
const SUPABASE_URL = process.env.SUPABASE_URL;
const SUPABASE_SERVICE_ROLE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY;

// Initialize Supabase client
const supabase = createClient(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY);

// Initialize Upstash Redis client
const redisClient = new Redis({
    url: process.env.UPSTASH_REDIS_REST_URL,
    token: process.env.UPSTASH_REDIS_REST_TOKEN,
});


// Test Redis connection on startup
async function testRedisConnection() {
    try {
        
        // Test basic operations like in the Upstash documentation
        await redisClient.set("test:connection", "working");
        const result = await redisClient.get("test:connection");
        
        
        // Clean up test key
        await redisClient.del("test:connection");
        
    } catch (error) {
        // Redis connection failed
    }
}

// Run Redis test on startup
testRedisConnection();

// In-memory session store (in production, use Redis or database)
const sessions = new Map();

// Session configuration
const SESSION_CONFIG = {
    maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'none',
    path: '/'
};

// Authentication middleware - handle session validation once
function authenticateSession(req, res, next) {
    const sessionId = req.cookies.sid;
    
    
    if (!sessionId) {
        return res.status(401).json({
            success: false,
            error: 'SESSION_EXPIRED',
            reason: 'No session cookie'
        });
    }
    
    const session = getSession(sessionId);
    
    if (!session) {
        return res.status(401).json({
            success: false,
            error: 'SESSION_EXPIRED',
            reason: 'Invalid or expired session'
        });
    }
    
    // Add session info to request object for use in route handlers
    req.session = session;
    req.userId = session.userId;
    
    // Extend session on each request (rolling renewal)
    extendSession(sessionId);
    
    next();
}

// OpenAI API Key Rotation System (10 keys + fallback to single key)
const openaiApiKeys = [
    process.env.OPENAI_API_KEY_1,
    process.env.OPENAI_API_KEY_2,
    process.env.OPENAI_API_KEY_3,
    process.env.OPENAI_API_KEY_4,
    process.env.OPENAI_API_KEY_5,
    process.env.OPENAI_API_KEY_6,
    process.env.OPENAI_API_KEY_7,
    process.env.OPENAI_API_KEY_8,
    process.env.OPENAI_API_KEY_9,
    process.env.OPENAI_API_KEY_10
].filter(key => key && key.trim() !== ''); // Filter out empty keys

// Fallback to single API key if no rotation keys are found
if (openaiApiKeys.length === 0 && process.env.OPENAI_API_KEY) {
    openaiApiKeys.push(process.env.OPENAI_API_KEY);
}

if (openaiApiKeys.length === 0) {
    // No OpenAI API keys found
}

// Key rotation system - Initialize AFTER all keys are loaded
let currentKeyIndex = 0;
let keyUsageCount = new Array(openaiApiKeys.length).fill(0);

function getNextApiKey() {
    if (openaiApiKeys.length === 0) {
        // No OpenAI API keys configured
        return null;
    }
    
    
    // Find the key with the lowest usage count
    let minUsage = Math.min(...keyUsageCount);
    let availableKeys = keyUsageCount.map((usage, index) => ({ usage, index }))
        .filter(key => key.usage === minUsage);
    
    // Select a random key from those with minimum usage
    const selectedKey = availableKeys[Math.floor(Math.random() * availableKeys.length)];
    currentKeyIndex = selectedKey.index;
    
    // Increment usage count
    keyUsageCount[currentKeyIndex]++;
    
    return openaiApiKeys[currentKeyIndex];
}

function markKeyAsFailed(keyIndex) {
    if (keyIndex >= 0 && keyIndex < keyUsageCount.length) {
        // Add a penalty to this key's usage count
        keyUsageCount[keyIndex] += 10;
    }
}

// Validate required environment variables
if (!SUPABASE_URL || !SUPABASE_SERVICE_ROLE_KEY) {
    // Missing required environment variables
    process.exit(1);
}

// Helper function to handle subscription creation errors
function handleSubscriptionCreationError(createError, res) {
    // Error creating free tier subscription
    
    // Check if it's a foreign key constraint error
    if (createError.code === '23503') {
        // Return free tier status without creating record
        res.json({
            status: 'free',
            tokens_used: 0,
            tokens_limit: 50,
            is_unlimited: false,
            current_period_end: null
        });
    } else {
        // Other error - fallback to free tier response
        res.json({
            status: 'free',
            tokens_used: 0,
            tokens_limit: 50,
            is_unlimited: false,
            current_period_end: null
        });
    }
}

// Session management functions
function createSession(userId, userAgent, email) {
    const sessionId = 'sid_' + Date.now() + '_' + Math.random().toString(36).substr(2, 9);
    const session = {
        id: sessionId,
        userId: userId,
        userAgent: userAgent,
        email: email,
        createdAt: new Date(),
        expiresAt: new Date(Date.now() + SESSION_CONFIG.maxAge),
        lastActivity: new Date()
    };
    
    sessions.set(sessionId, session);
    return sessionId;
}

function getSession(sessionId) {
    const session = sessions.get(sessionId);
    if (!session) return null;
    
    // Check if session is expired
    if (new Date() > session.expiresAt) {
        sessions.delete(sessionId);
        return null;
    }
    
    // Update last activity for rolling renewal
    session.lastActivity = new Date();
    
    // Extend session if it's close to expiring (within 1 hour)
    const oneHourFromNow = new Date(Date.now() + 60 * 60 * 1000);
    if (session.expiresAt < oneHourFromNow) {
        extendSession(sessionId);
    }
    
    return session;
}

function extendSession(sessionId) {
    const session = sessions.get(sessionId);
    if (session) {
        session.expiresAt = new Date(Date.now() + SESSION_CONFIG.maxAge);
        session.lastActivity = new Date();
    }
}

function deleteSession(sessionId) {
    sessions.delete(sessionId);
}

// Helper function to make Supabase requests
async function supabaseRequest(endpoint, options = {}) {
    const url = `${SUPABASE_URL}/rest/v1/${endpoint}`;
    const headers = {
        'apikey': SUPABASE_SERVICE_ROLE_KEY,
        'Authorization': `Bearer ${SUPABASE_SERVICE_ROLE_KEY}`,
        'Content-Type': 'application/json',
        ...options.headers
    };
    
    
    try {
        const response = await fetch(url, {
            method: options.method || 'GET',
            headers,
            body: options.body ? JSON.stringify(options.body) : undefined
        });
        
        
        if (!response.ok) {
            const errorText = await response.text();
            // Supabase error response
            
            let error;
            try {
                error = JSON.parse(errorText);
            } catch {
                error = { message: `HTTP error! status: ${response.status} - ${errorText}` };
            }
            
            throw error;
        }
        
        // Handle 204 No Content responses (common for PATCH/DELETE operations)
        if (response.status === 204) {
            return null; // No data to return for 204 responses
        }
        
        // For other successful responses, try to parse JSON
        try {
            const responseText = await response.text();
            
            if (!responseText || responseText.trim() === '') {
                return null;
            }
            
            const data = JSON.parse(responseText);
        return data;
        } catch (jsonError) {
            // Could not parse JSON response
            return null;
        }
    } catch (fetchError) {
        // Supabase request failed
        throw fetchError;
    }
}

const app = express();

// Trust proxy for rate limiting (required for Render.com deployment)
app.set('trust proxy', 1);

// Security configuration (embedded)
const SECURITY_CONFIG = {
    rateLimit: {
        windowMs: 15 * 60 * 1000, // 15 minutes
        max: 100, // limit each IP to 100 requests per windowMs
        message: 'Too many requests from this IP, please try again later.',
        standardHeaders: true,
        legacyHeaders: false,
    },
    cors: {
        origin: function (origin, callback) {
            // Allow requests with no origin (like mobile apps or curl requests)
            if (!origin) return callback(null, true);
            
            // Allow all origins for browser extension compatibility
            // This is necessary because the extension works on any website
            callback(null, true);
        },
        credentials: true,
        methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
        allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With', 'x-user-email', 'x-user-id'],
        exposedHeaders: ['X-Total-Count']
    },
    headers: {
        'X-Content-Type-Options': 'nosniff',
        'X-Frame-Options': 'DENY',
        'X-XSS-Protection': '1; mode=block',
        'Strict-Transport-Security': 'max-age=31536000; includeSubDomains',
        'Content-Security-Policy': "default-src 'self'; script-src 'self' 'unsafe-inline' https://js.stripe.com; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; connect-src 'self' https://api.stripe.com;"
    }
};

// Security middleware
app.use(helmet());
app.use(rateLimit(SECURITY_CONFIG.rateLimit));
app.use(cors(SECURITY_CONFIG.cors));

// Additional CORS headers for preflight requests
app.options('*', cors(SECURITY_CONFIG.cors));

// Webhook handler for Stripe events (MUST come before JSON parsing middleware)
app.post('/api/webhook', express.raw({ type: 'application/json' }), async (req, res) => {
    const sig = req.headers['stripe-signature'];
    const endpointSecret = process.env.STRIPE_WEBHOOK_SECRET;


    let event;

    try {
        event = stripe.webhooks.constructEvent(req.body, sig, endpointSecret);
    } catch (err) {
        // Webhook signature verification failed
        return res.status(400).send('Webhook signature verification failed');
    }

    // Handle the event with Supabase database operations
    try {
        
        switch (event.type) {
            case 'checkout.session.completed':
                await handleCheckoutCompleted(event.data.object);
                break;
                
            case 'customer.subscription.created':
                await handleSubscriptionCreated(event.data.object);
                break;
                
            case 'customer.subscription.updated':
                await handleSubscriptionUpdated(event.data.object);
                break;
                
            case 'customer.subscription.deleted':
                await handleSubscriptionDeleted(event.data.object);
                break;
                
            case 'invoice.payment_succeeded':
                await handlePaymentSucceeded(event.data.object);
                break;
                
            case 'invoice.payment_failed':
                await handlePaymentFailed(event.data.object);
                break;
                
            default:
        }
        
    } catch (error) {
        // Error: Error processing webhook event:', error.message);
    }

    res.json({ received: true });
});

// JSON parsing middleware (MUST come after webhook handler)
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true })); // Add this for form data
app.use(cookieParser());

// Add security headers
app.use((req, res, next) => {
    Object.entries(SECURITY_CONFIG.headers).forEach(([key, value]) => {
        res.setHeader(key, value);
    });
    next();
});

// Health check endpoint
app.get('/api/health', (req, res) => {
    res.json({ 
        status: 'ok', 
        timestamp: new Date().toISOString(),
        message: 'Trontiq Stripe API is running',
        environment: process.env.NODE_ENV || 'production'
    });
});

// Session health check endpoint
app.get('/api/session-health', cors(SECURITY_CONFIG.cors), (req, res) => {
    try {
        const sessionId = req.cookies.sid;
        
        if (!sessionId) {
            return res.status(401).json({ 
                success: false, 
                error: 'NO_SESSION',
                message: 'No session cookie found'
            });
        }
        
        const session = getSession(sessionId);
        
        if (!session) {
            return res.status(401).json({ 
                success: false, 
                error: 'SESSION_EXPIRED',
                message: 'Session not found or expired'
            });
        }
        
        res.json({ 
            success: true, 
            session: {
                userId: session.userId,
                expiresAt: session.expiresAt,
                lastActivity: session.lastActivity,
                isValid: true
            }
        });
        
    } catch (error) {
        // Error: Session health check error:', error);
        res.status(500).json({ 
            success: false, 
            error: 'INTERNAL_ERROR',
            message: 'Internal server error'
        });
    }
});

// Email verification endpoint (Supabase default)
app.get('/auth/confirm', async (req, res) => {
    try {
        // Extract token and type from query parameters
        const { token_hash, type, next } = req.query;
        
        if (type === 'signup' && token_hash) {
            // Actually verify the email with Supabase
            try {
                const { data, error } = await supabase.auth.verifyOtp({
                    token_hash: token_hash,
                    type: 'signup'
                });
                
                if (error) {
                    console.error('Supabase verification error:', error);
                    throw error;
                }
                
                console.log('Email verified successfully:', data);
            } catch (verificationError) {
                console.error('Failed to verify email with Supabase:', verificationError);
                // Still show success page to user, but log the error
            }
            
            res.send(`
                <!DOCTYPE html>
                <html lang="en">
                <head>
                    <meta charset="UTF-8">
                    <meta name="viewport" content="width=device-width, initial-scale=1.0">
                    <title>Email Verified - Trontiq</title>
                    <style>
                        body {
                            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
                            background: #f8f9fa;
                            margin: 0;
                            padding: 0;
                            min-height: 100vh;
                            display: flex;
                            align-items: center;
                            justify-content: center;
                        }
                        .container {
                            background: white;
                            border-radius: 8px;
                            padding: 40px;
                            text-align: center;
                            box-shadow: 0 2px 10px rgba(0, 0, 0, 0.1);
                            max-width: 400px;
                            width: 90%;
                        }
                        .success-icon {
                            font-size: 48px;
                            color: #2c3e50;
                            margin-bottom: 20px;
                        }
                        h1 {
                            color: #2c3e50;
                            margin-bottom: 16px;
                            font-size: 24px;
                            font-weight: 600;
                        }
                        p {
                            color: #6c757d;
                            line-height: 1.6;
                            margin-bottom: 24px;
                        }
                        .brand {
                            color: #2c3e50;
                            font-weight: 600;
                        }
                        .close-btn {
                            background: #2c3e50;
                            color: white;
                            border: none;
                            padding: 12px 24px;
                            border-radius: 8px;
                            font-size: 16px;
                            cursor: pointer;
                            font-weight: 600;
                            transition: all 0.2s;
                        }
                        .close-btn:hover {
                            background: #34495e;
                            transform: translateY(-1px);
                            box-shadow: 0 4px 12px rgba(44, 62, 80, 0.3);
                        }
                    </style>
                </head>
                <body>
                    <div class="container">
                        <div class="success-icon">✅</div>
                        <h1>Email Verified!</h1>
                        <p>Your <span class="brand">Trontiq</span> account has been verified successfully.</p>
                        <p>You can now close this window and return to the extension to sign in.</p>
                        <button class="close-btn" onclick="window.close()">Close Window</button>
                    </div>
                </body>
                </html>
            `);
        } else {
            // Invalid or missing parameters
            res.status(400).send(`
                <!DOCTYPE html>
                <html lang="en">
                <head>
                    <meta charset="UTF-8">
                    <meta name="viewport" content="width=device-width, initial-scale=1.0">
                    <title>Verification Error - Trontiq</title>
                    <style>
                        body {
                            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
                            background: #f8f9fa;
                            margin: 0;
                            padding: 0;
                            min-height: 100vh;
                            display: flex;
                            align-items: center;
                            justify-content: center;
                        }
                        .container {
                            background: white;
                            border-radius: 8px;
                            padding: 40px;
                            text-align: center;
                            box-shadow: 0 2px 10px rgba(0, 0, 0, 0.1);
                            max-width: 400px;
                            width: 90%;
                        }
                        .error-icon {
                            font-size: 48px;
                            color: #EF4444;
                            margin-bottom: 20px;
                        }
                        h1 {
                            color: #2c3e50;
                            margin-bottom: 16px;
                            font-size: 24px;
                            font-weight: 600;
                        }
                        p {
                            color: #6c757d;
                            line-height: 1.6;
                            margin-bottom: 24px;
                        }
                        .brand {
                            color: #2c3e50;
                            font-weight: 600;
                        }
                        .close-btn {
                            background: #2c3e50;
                            color: white;
                            border: none;
                            padding: 12px 24px;
                            border-radius: 8px;
                            font-size: 16px;
                            cursor: pointer;
                            font-weight: 600;
                            transition: all 0.2s;
                        }
                        .close-btn:hover {
                            background: #34495e;
                            transform: translateY(-1px);
                            box-shadow: 0 4px 12px rgba(44, 62, 80, 0.3);
                        }
                    </style>
                </head>
                <body>
                    <div class="container">
                        <div class="error-icon">❌</div>
                        <h1>Verification Error</h1>
                        <p>There was an error verifying your <span class="brand">Trontiq</span> account.</p>
                        <p>Please try again or contact support if the problem persists.</p>
                        <button class="close-btn" onclick="window.close()">Close Window</button>
                    </div>
                </body>
                </html>
            `);
        }
    } catch (error) {
        console.error('Email verification error:', error);
        res.status(500).send(`
            <!DOCTYPE html>
            <html lang="en">
            <head>
                <meta charset="UTF-8">
                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                <title>Server Error - Trontiq</title>
                <style>
                    body {
                        font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
                        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                        margin: 0;
                        padding: 0;
                        min-height: 100vh;
                        display: flex;
                        align-items: center;
                        justify-content: center;
                    }
                    .container {
                        background: white;
                        border-radius: 12px;
                        padding: 40px;
                        text-align: center;
                        box-shadow: 0 20px 40px rgba(0,0,0,0.1);
                        max-width: 400px;
                        width: 90%;
                    }
                    .error-icon {
                        font-size: 48px;
                        color: #EF4444;
                        margin-bottom: 20px;
                    }
                    h1 {
                        color: #1F2937;
                        margin-bottom: 16px;
                        font-size: 24px;
                        font-weight: 600;
                    }
                    p {
                        color: #6B7280;
                        line-height: 1.6;
                        margin-bottom: 24px;
                    }
                    .brand {
                        color: #4F46E5;
                        font-weight: 600;
                    }
                    .close-btn {
                        background: #4F46E5;
                        color: white;
                        border: none;
                        padding: 12px 24px;
                        border-radius: 8px;
                        font-size: 16px;
                        cursor: pointer;
                        transition: background-color 0.2s;
                    }
                    .close-btn:hover {
                        background: #4338CA;
                    }
                </style>
            </head>
            <body>
                <div class="container">
                    <div class="error-icon">⚠️</div>
                    <h1>Server Error</h1>
                    <p>There was a server error processing your <span class="brand">Trontiq</span> account verification.</p>
                    <p>Please try again later or contact support if the problem persists.</p>
                    <button class="close-btn" onclick="window.close()">Close Window</button>
                </div>
            </body>
            </html>
        `);
    }
});

// Email verification completion endpoint
app.get('/auth/verify-complete', async (req, res) => {
    try {
        // Extract token and type from query parameters
        const { token_hash, type } = req.query;
        
        if (type === 'signup' && token_hash) {
            // Actually verify the email with Supabase
            try {
                const { data, error } = await supabase.auth.verifyOtp({
                    token_hash: token_hash,
                    type: 'signup'
                });
                
                if (error) {
                    console.error('Supabase verification error:', error);
                    throw error;
                }
                
                console.log('Email verified successfully:', data);
            } catch (verificationError) {
                console.error('Failed to verify email with Supabase:', verificationError);
                // Still show success page to user, but log the error
            }
            
            res.send(`
                <!DOCTYPE html>
                <html lang="en">
                <head>
                    <meta charset="UTF-8">
                    <meta name="viewport" content="width=device-width, initial-scale=1.0">
                    <title>Email Verified - Trontiq</title>
                    <style>
                        body {
                            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
                            background: #f8f9fa;
                            margin: 0;
                            padding: 0;
                            min-height: 100vh;
                            display: flex;
                            align-items: center;
                            justify-content: center;
                        }
                        .container {
                            background: white;
                            border-radius: 8px;
                            padding: 40px;
                            text-align: center;
                            box-shadow: 0 2px 10px rgba(0, 0, 0, 0.1);
                            max-width: 400px;
                            width: 90%;
                        }
                        .success-icon {
                            font-size: 48px;
                            color: #2c3e50;
                            margin-bottom: 20px;
                        }
                        h1 {
                            color: #2c3e50;
                            margin-bottom: 16px;
                            font-size: 24px;
                            font-weight: 600;
                        }
                        p {
                            color: #6c757d;
                            line-height: 1.6;
                            margin-bottom: 24px;
                        }
                        .brand {
                            color: #2c3e50;
                            font-weight: 600;
                        }
                        .close-btn {
                            background: #2c3e50;
                            color: white;
                            border: none;
                            padding: 12px 24px;
                            border-radius: 8px;
                            font-size: 16px;
                            cursor: pointer;
                            font-weight: 600;
                            transition: all 0.2s;
                        }
                        .close-btn:hover {
                            background: #34495e;
                            transform: translateY(-1px);
                            box-shadow: 0 4px 12px rgba(44, 62, 80, 0.3);
                        }
                    </style>
                </head>
                <body>
                    <div class="container">
                        <div class="success-icon">✅</div>
                        <h1>Email Verified!</h1>
                        <p>Your <span class="brand">Trontiq</span> account has been verified successfully.</p>
                        <p>You can now close this window and return to the extension to sign in.</p>
                        <button class="close-btn" onclick="window.close()">Close Window</button>
                    </div>
                </body>
                </html>
            `);
        } else {
            // Invalid or missing parameters
            res.status(400).send(`
                <!DOCTYPE html>
                <html lang="en">
                <head>
                    <meta charset="UTF-8">
                    <meta name="viewport" content="width=device-width, initial-scale=1.0">
                    <title>Verification Error - Trontiq</title>
                    <style>
                        body {
                            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
                            background: #f8f9fa;
                            margin: 0;
                            padding: 0;
                            min-height: 100vh;
                            display: flex;
                            align-items: center;
                            justify-content: center;
                        }
                        .container {
                            background: white;
                            border-radius: 8px;
                            padding: 40px;
                            text-align: center;
                            box-shadow: 0 2px 10px rgba(0, 0, 0, 0.1);
                            max-width: 400px;
                            width: 90%;
                        }
                        .error-icon {
                            font-size: 48px;
                            color: #EF4444;
                            margin-bottom: 20px;
                        }
                        h1 {
                            color: #2c3e50;
                            margin-bottom: 16px;
                            font-size: 24px;
                            font-weight: 600;
                        }
                        p {
                            color: #6c757d;
                            line-height: 1.6;
                            margin-bottom: 24px;
                        }
                        .brand {
                            color: #2c3e50;
                            font-weight: 600;
                        }
                    </style>
                </head>
                <body>
                    <div class="container">
                        <div class="error-icon">❌</div>
                        <h1>Verification Error</h1>
                        <p>Invalid verification link. Please try again or contact support.</p>
                        <p><span class="brand">Trontiq</span> Support</p>
                    </div>
                </body>
                </html>
            `);
        }
    } catch (error) {
        console.error('Verification endpoint error:', error);
        res.status(500).send(`
            <!DOCTYPE html>
            <html lang="en">
            <head>
                <meta charset="UTF-8">
                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                <title>Server Error - Trontiq</title>
                <style>
                    body {
                        font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
                        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                        margin: 0;
                        padding: 0;
                        min-height: 100vh;
                        display: flex;
                        align-items: center;
                        justify-content: center;
                    }
                    .container {
                        background: white;
                        border-radius: 12px;
                        padding: 40px;
                        text-align: center;
                        box-shadow: 0 20px 40px rgba(0,0,0,0.1);
                        max-width: 400px;
                        width: 90%;
                    }
                    .error-icon {
                        font-size: 48px;
                        color: #EF4444;
                        margin-bottom: 20px;
                    }
                    h1 {
                        color: #1F2937;
                        margin-bottom: 16px;
                        font-size: 24px;
                        font-weight: 600;
                    }
                    p {
                        color: #6B7280;
                        line-height: 1.6;
                        margin-bottom: 24px;
                    }
                    .brand {
                        color: #4F46E5;
                        font-weight: 600;
                    }
                </style>
            </head>
            <body>
                <div class="container">
                    <div class="error-icon">⚠️</div>
                    <h1>Server Error</h1>
                    <p>Something went wrong. Please try again later.</p>
                    <p><span class="brand">Trontiq</span> Support</p>
                </div>
            </body>
            </html>
        `);
    }
});

// Auth exchange endpoint - exchange Supabase token for server session
app.post('/api/auth/exchange', async (req, res) => {
    try {
        const { idToken } = req.body;
        
        if (!idToken) {
            return res.status(400).json({ 
                success: false, 
                error: 'ID token required' 
            });
        }
        
        
        // Verify the Supabase ID token
        const { data: { user }, error } = await supabase.auth.getUser(idToken);
        
        if (error || !user) {
            // Error: Token verification failed:', error);
            return res.status(401).json({ 
                success: false, 
                error: 'Invalid token' 
            });
        }
        
        
        // Create server session
        const sessionId = createSession(user.id, req.headers['user-agent'], user.email);
        
        // Set HttpOnly cookie
        res.cookie('sid', sessionId, SESSION_CONFIG);
        
        
        res.json({ 
            success: true, 
            message: 'Authentication successful' 
        });
        
    } catch (error) {
        // Error: Auth exchange error:', error);
        res.status(500).json({ 
            success: false, 
            error: 'Internal server error' 
        });
    }
});

// Auth logout endpoint
app.post('/api/auth/logout', (req, res) => {
    try {
        
        // Get session from cookie
        const sessionId = req.cookies.sid;
        
        if (sessionId) {
            const session = getSession(sessionId);
            
            // NEW: Clean up chat sessions and job description in Redis
            if (session && session.userId) {
                deleteUserChatSessions(session.userId).catch(error => {
                    // Error: [LOGOUT] Error cleaning up chat sessions:', error);
                });
                deleteJobDescriptionFromRedis(session.userId).catch(error => {
                    // Error: [LOGOUT] Error cleaning up job description:', error);
                });
            }
            
            // Delete session from storage
            deleteSession(sessionId);
        }
        
        // Clear the session cookie
        res.clearCookie('sid', {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: 'none',
            path: '/'
        });
        
        
        res.json({ 
            success: true, 
            message: 'Logged out successfully' 
        });
        
    } catch (error) {
        // Error: Logout error:', error);
        res.status(500).json({ 
            success: false, 
            error: 'Internal server error' 
        });
    }
});

// Simple test endpoint
app.get('/api/simple-test', (req, res) => {
    res.json({ message: 'Simple test endpoint working!' });
});

// API Key status endpoint
app.get('/api/api-key-status', (req, res) => {
    const keyCount = openaiApiKeys.length;
    const hasKeys = keyCount > 0;
    const keyStatus = openaiApiKeys.map((key, index) => ({
        index: index + 1,
        hasKey: !!key,
        keyLength: key ? key.length : 0,
        keyPrefix: key ? key.substring(0, 8) + '...' : 'none'
    }));
    
    res.json({
        hasApiKeys: hasKeys,
        keyCount: keyCount,
        keyStatus: keyStatus,
        environment: process.env.NODE_ENV || 'production',
        hasFallbackKey: !!process.env.OPENAI_API_KEY,
        supabaseUrl: SUPABASE_URL,
        supabaseUrlPrefix: SUPABASE_URL ? SUPABASE_URL.substring(0, 30) + '...' : 'undefined',
        message: hasKeys ? 'API keys are configured' : 'No API keys found - please set OPENAI_API_KEY_1 through OPENAI_API_KEY_10 OR OPENAI_API_KEY'
    });
});

// Test OpenAI API endpoint (no authentication required for testing)
app.post('/api/test-openai', async (req, res) => {
    try {
        
        const apiKey = getNextApiKey();
        if (!apiKey) {
            return res.status(500).json({
                success: false,
                error: 'No API keys available',
                message: 'Please set OPENAI_API_KEY environment variable'
            });
        }
        
        
        const testResponse = await fetch('https://api.openai.com/v1/chat/completions', {
            method: 'POST',
            headers: {
                'Authorization': `Bearer ${apiKey}`,
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                model: 'gpt-3.5-turbo',
                messages: [
                    { role: 'user', content: 'Say "Hello, API test successful!"' }
                ],
                max_tokens: 50,
                temperature: 0.7
            })
        });
        
        
        if (!testResponse.ok) {
            const errorData = await testResponse.text();
            // Error:🧪 [TEST] OpenAI API error:', errorData);
            return             res.status(500).json({
                success: false,
                error: 'OpenAI API test failed'
            });
        }
        
        const data = await testResponse.json();
        
        res.json({
            success: true,
            message: 'OpenAI API test successful',
            response: data.choices[0].message.content,
            usage: data.usage
        });
        
    } catch (error) {
        // Error:🧪 [TEST] Test error:', error);
        res.status(500).json({
            success: false,
            error: 'Test failed',
            message: error.message
        });
    }
});

// Test Supabase connection
app.get('/api/test-supabase', async (req, res) => {
    try {
        
        // Test a simple query
        const testData = await supabaseRequest('user_subscriptions?limit=1&select=count');
        
        res.json({ 
            status: 'ok',
            message: 'Supabase connection successful',
            testData
        });
    } catch (error) {
        // Error: Supabase test failed:', error);
        res.status(500).json({ 
            status: 'error',
            message: 'Supabase connection failed'
        });
    }
});

// Test webhook secret
app.get('/api/test-webhook-secret', (req, res) => {
    const webhookSecret = process.env.STRIPE_WEBHOOK_SECRET;
    res.json({
        hasWebhookSecret: !!webhookSecret,
        secretLength: webhookSecret ? webhookSecret.length : 0,
        secretPrefix: webhookSecret ? webhookSecret.substring(0, 5) + '...' : 'none',
        message: webhookSecret ? 'Webhook secret is configured' : 'Webhook secret is missing',
        stripeMode: process.env.STRIPE_SECRET_KEY ? (process.env.STRIPE_SECRET_KEY.startsWith('sk_test_') ? 'test' : 'live') : 'unknown'
    });
});

// Test webhook processing manually
app.post('/api/test-webhook-processing', async (req, res) => {
    try {
        const { email } = req.body;
        
        if (!email) {
            return res.status(400).json({ error: 'email is required' });
        }
        
        
        // Simulate a subscription created event
        const mockEvent = {
            type: 'customer.subscription.created',
            data: {
                object: {
                    id: 'sub_test_' + Date.now(),
                    customer: 'cus_test_' + Date.now(),
                    status: 'active',
                    current_period_start: Math.floor(Date.now() / 1000),
                    current_period_end: Math.floor((Date.now() + 30 * 24 * 60 * 60 * 1000) / 1000)
                }
            }
        };
        
        
        // Process the mock event
        await handleSubscriptionCreated(mockEvent.data.object);
        
        res.json({ 
            status: 'ok',
            message: 'Mock webhook event processed successfully',
            event: mockEvent
        });
        
    } catch (error) {
        // Error: Test webhook processing failed:', error);
        res.status(500).json({ 
            status: 'error',
            message: 'Test webhook processing failed'
        });
    }
});

// Test subscription creation manually
app.post('/api/test-create-subscription', async (req, res) => {
    try {
        const { userId, email } = req.body;
        
        if (!userId || !email) {
            return res.status(400).json({ error: 'userId and email are required' });
        }
        
        
        // Return success without creating subscription records
        // The system now uses checkUserRequestLimit() function for tracking user limits
        res.json({ 
            status: 'ok',
            message: 'Test subscription endpoint deprecated - using waitlist system instead',
            subscription: {
                status: 'free',
                tokens_used: 0,
                tokens_limit: 50,
                is_unlimited: false,
                current_period_end: null
            }
        });
        
    } catch (error) {
        // Error: Test subscription creation failed:', error);
        res.status(500).json({ 
            status: 'error',
            message: 'Test subscription creation failed'
        });
    }
});

// Success page endpoint
app.get('/success', (req, res) => {
    const sessionId = req.query.session_id;
    res.send(`
        <!DOCTYPE html>
        <html>
        <head>
            <title>Payment Successful - Trontiq</title>
            <style>
                body { font-family: Arial, sans-serif; text-align: center; padding: 50px; background: #f8f9fa; }
                .container { background: white; border-radius: 12px; padding: 40px; box-shadow: 0 4px 12px rgba(0,0,0,0.1); max-width: 400px; margin: 0 auto; }
                .success { color: #28a745; font-size: 24px; font-weight: bold; margin-bottom: 20px; }
                .message { color: #6c757d; margin-bottom: 30px; line-height: 1.5; }
                .btn { background: #2c3e50; color: white; padding: 12px 24px; border: none; border-radius: 8px; cursor: pointer; font-size: 16px; font-weight: 600; }
                .btn:hover { background: #34495e; }
                .auto-close { color: #6c757d; font-size: 14px; margin-top: 20px; }
            </style>
        </head>
        <body>
            <div class="container">
            <div class="success">✅ Payment Successful!</div>
                <div class="message">
            <p>Your Trontiq Pro subscription has been activated.</p>
                    <p>You can now close this window and return to the extension.</p>
                </div>
                <button class="btn" onclick="closeAndRefresh()">Close & Refresh Extension</button>
                <div class="auto-close">This window will close automatically in 5 seconds...</div>
            </div>
            
            <script>
                if (sessionId) {
                }
                
                function closeAndRefresh() {
                    // Try to send a message to the extension if it's open
                    try {
                        if (window.opener) {
                            window.opener.postMessage({ type: 'PAYMENT_SUCCESS', sessionId: sessionId }, '*');
                        }
                    } catch (e) {
                    }
                    
                    // Close the window
                    window.close();
                }
                
                // Auto-close after 5 seconds
                setTimeout(() => {
                    closeAndRefresh();
                }, 5000);
            </script>
        </body>
        </html>
    `);
});

// Cancel page endpoint
app.get('/cancel', (req, res) => {
    res.send(`
        <!DOCTYPE html>
        <html>
        <head>
            <title>Payment Cancelled - Trontiq</title>
            <style>
                body { font-family: Arial, sans-serif; text-align: center; padding: 50px; }
                .cancel { color: red; font-size: 24px; }
                .btn { background: #667eea; color: white; padding: 10px 20px; border: none; border-radius: 5px; cursor: pointer; }
            </style>
        </head>
        <body>
            <div class="cancel">❌ Payment Cancelled</div>
            <p>Your payment was cancelled. You can try again anytime.</p>
            <button class="btn" onclick="window.close()">Close</button>
        </body>
        </html>
    `);
});

// STRIPE DISABLED FOR FREE TIER + WAITLIST RELEASE
// Create checkout session (REQUIRES AUTHENTICATION)
/*
app.post('/api/create-checkout-session', cors(SECURITY_CONFIG.cors), async (req, res) => {
    try {
        // SECURITY: Validate user session before allowing checkout
        
        const sessionId = req.cookies.sid;
        
        if (!sessionId) {
            return res.status(401).json({ error: 'No session cookie found' });
        }

        // Get user from session
        
        const session = sessions.get(sessionId);
        
        if (!session) {
            return res.status(401).json({ error: 'Invalid session' });
        }

        // Validate session hasn't expired
        
        if (Date.now() > session.expiresAt) {
            sessions.delete(sessionId);
            return res.status(401).json({ error: 'Session expired' });
        }
        

        // Get user email from session for Stripe checkout
        // Note: We can't query auth.users directly, so we'll use a placeholder
        // The actual user email will be handled by Stripe's customer creation
        let userEmail = null;
        
        // For now, we'll create the checkout without customer_email
        // Stripe will prompt the user to enter their email during checkout
        // This prevents cross-user data leakage since each user enters their own email

        // Handle both JSON and form data
        const priceId = req.body.priceId;

        if (!priceId) {
            return res.status(400).json({ error: 'Price ID is required' });
        }

        // Use hardcoded base URL
        const baseUrl = 'https://stripe-deploy.onrender.com';

        // Create Stripe checkout session for Prebuilt Checkout
        const stripeSession = await stripe.checkout.sessions.create({
            // SECURITY: Unique client reference to prevent cross-user data
            client_reference_id: `user_${session.userId}_${Date.now()}`,
            payment_method_types: ['card'],
            line_items: [
                {
                    price: priceId, // Your $4.99/month price ID
                    quantity: 1,
                },
            ],
            mode: 'subscription',
            success_url: `${baseUrl}/success?session_id={CHECKOUT_SESSION_ID}&user_id=${session.userId}&timestamp=${Date.now()}&subscription=active`,
            cancel_url: `${baseUrl}/cancel?user_id=${session.userId}&timestamp=${Date.now()}`,
            // SECURITY: Force fresh checkout to prevent cross-user data leakage
            billing_address_collection: 'required', // Force address collection
            // SECURITY: Force Stripe to ignore cached customer data
            locale: 'auto', // Force locale detection
            // Enable all the features you want
            allow_promotion_codes: true,
            automatic_tax: {
                enabled: true
            },
            // Store user-specific metadata in Stripe session to prevent cross-user data
            metadata: {
                user_id: session.userId,
                created_at: new Date().toISOString(),
                session_id: sessionId,
                browser_session: `session_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`,
                force_fresh_checkout: 'true',
                prevent_caching: 'true'
            }
        });

        
        // Return the checkout URL for the frontend to handle
        res.json({ 
            success: true, 
            checkoutUrl: stripeSession.url,
            sessionId: stripeSession.id
        });
        
        
        // Note: The success page will handle immediate subscription activation
        // while the webhook processes in the background for redundancy
        
    } catch (error) {
        // Error:Error creating checkout session:', error);
        res.status(500).json({ error: 'Failed to create checkout session' });
    }
});
*/

// STRIPE DISABLED FOR FREE TIER + WAITLIST RELEASE
// Success page handler - immediately activate subscription
/*
app.get('/success', async (req, res) => {
    try {
        const { session_id, user_id, subscription } = req.query;
        
        if (subscription === 'active' && user_id) {
            
            // Create a temporary subscription record immediately
            const tempSubscriptionData = {
                user_id: user_id,
                stripe_subscription_id: `temp_${Date.now()}`, // Temporary ID
                stripe_customer_id: `temp_customer_${Date.now()}`,
                status: 'active',
                current_period_start: new Date().toISOString(),
                current_period_end: new Date(Date.now() + (30 * 24 * 60 * 60 * 1000)).toISOString(), // 30 days from now
                tokens_limit: -1, // Unlimited for Pro
                tokens_used: 0,
                updated_at: new Date().toISOString(),
                is_temp: true // Mark as temporary
            };
            
            
            // Save to database immediately
            const subResponse = await fetch(`${SUPABASE_URL}/rest/v1/user_subscriptions`, {
                method: 'POST',
                headers: {
                    'Authorization': `Bearer ${SUPABASE_SERVICE_ROLE_KEY}`,
                    'apikey': SUPABASE_SERVICE_ROLE_KEY,
                    'Content-Type': 'application/json',
                    'Prefer': 'resolution=merge-duplicates'
                },
                body: JSON.stringify(tempSubscriptionData)
            });
            
            if (subResponse.ok) {
            } else {
            }
        }
        
        // Send success page HTML
        res.send(`
            <!DOCTYPE html>
            <html>
            <head>
                <title>Payment Successful - Trontiq Pro</title>
                <style>
                    body { font-family: Arial, sans-serif; text-align: center; padding: 50px; background: #f8f9fa; }
                    .success { background: white; padding: 40px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
                    .checkmark { color: #28a745; font-size: 48px; margin-bottom: 20px; }
                    h1 { color: #333; }
                    p { color: #666; line-height: 1.6; }
                    .close { background: #007bff; color: white; border: none; padding: 12px 24px; border-radius: 5px; cursor: pointer; }
                </style>
            </head>
            <body>
                <div class="success">
                    <div class="checkmark">✅</div>
                    <h1>Payment Successful!</h1>
                    <p>Welcome to Trontiq Pro! Your subscription has been activated.</p>
                    <p>You can now close this window and return to your extension.</p>
                    <p><strong>Note:</strong> Your subscription status will update in the extension within a few minutes.</p>
                    <button class="close" onclick="window.close()">Close Window</button>
                </div>
            </body>
            </html>
        `);
        
    } catch (error) {
        // Error: [SUCCESS] Error handling success page:', error);
        res.status(500).send('Error processing success page');
    }
});
*/

// STRIPE DISABLED FOR FREE TIER + WAITLIST RELEASE
// Verify payment (no user data storage)
/*
app.post('/api/verify-payment', async (req, res) => {
    try {
        const { sessionId } = req.body;


        // Retrieve the session from Stripe
        const session = await stripe.checkout.sessions.retrieve(sessionId);
        
        if (session.payment_status !== 'paid') {
            return res.status(400).json({ error: 'Payment not completed' });
        }

        // Get subscription details from Stripe
        const subscription = await stripe.subscriptions.retrieve(session.subscription);


        res.json({ 
            success: true, 
            subscription: {
                id: subscription.id,
                status: subscription.status,
                customer: subscription.customer,
                current_period_start: subscription.current_period_start,
                current_period_end: subscription.current_period_end
            }
        });
    } catch (error) {
        // Error:Error verifying payment:', error);
        res.status(500).json({ error: 'Failed to verify payment' });
    }
});
*/

// STRIPE DISABLED FOR FREE TIER + WAITLIST RELEASE
// Cancel subscription (session-based authentication)
/*
app.post('/api/cancel-subscription', cors(SECURITY_CONFIG.cors), async (req, res) => {
    try {
        const { subscriptionId } = req.body;

        if (!subscriptionId) {
            return res.status(400).json({ error: 'Subscription ID is required' });
        }


        // Get session from HttpOnly cookie
        const sessionId = req.cookies.sid;
        
        if (!sessionId) {
            return res.status(401).json({
                success: false,
                error: 'SESSION_EXPIRED',
                reason: 'No session cookie'
            });
        }
        
        // Get session from storage
        const session = getSession(sessionId);
        
        if (!session) {
            return res.status(401).json({
                success: false,
                error: 'SESSION_EXPIRED',
                reason: 'Invalid or expired session'
            });
        }
        

        // Verify that the user owns this subscription
        try {
            const subscriptionData = await supabaseRequest(`user_subscriptions?user_id=eq.${session.userId}&stripe_subscription_id=eq.${subscriptionId}&select=*`);
            
            if (!subscriptionData || subscriptionData.length === 0) {
                return res.status(403).json({
                    success: false,
                    error: 'FORBIDDEN',
                    reason: 'User does not own this subscription'
                });
            }
            
        } catch (verificationError) {
            // Error: [CANCEL_SUBSCRIPTION] Error verifying subscription ownership:', verificationError);
            return res.status(500).json({
                success: false,
                error: 'VERIFICATION_FAILED',
                reason: 'Failed to verify subscription ownership'
            });
        }

        // Cancel subscription directly in Stripe
        const subscription = await stripe.subscriptions.update(subscriptionId, {
            cancel_at_period_end: true
        });


        // Update Supabase to track cancellation
        try {
            await supabaseRequest(`user_subscriptions?user_id=eq.${session.userId}&stripe_subscription_id=eq.${subscriptionId}`, {
                method: 'PATCH',
                body: {
                    cancelled_at: new Date().toISOString(),
                    cancel_at_period_end: true,
                    current_period_end: new Date(subscription.current_period_end * 1000).toISOString()
                }
            });
        } catch (supabaseError) {
            // Error:⚠️ [CANCEL_SUBSCRIPTION] Failed to update Supabase:', supabaseError);
            // Don't fail the cancellation if Supabase update fails
        }

        res.json({
            success: true,
            subscription: {
                id: subscription.id,
                status: subscription.status,
                cancel_at_period_end: subscription.cancel_at_period_end,
                cancelled_at: new Date().toISOString(),
                current_period_end: new Date(subscription.current_period_end * 1000).toISOString()
            }
        });
    } catch (error) {
        // Error: [CANCEL_SUBSCRIPTION] Error canceling subscription:', error);
        res.status(500).json({ error: 'Failed to cancel subscription' });
    }
});
*/

// STRIPE DISABLED FOR FREE TIER + WAITLIST RELEASE
// Reactivate cancelled subscription
/*
app.post('/api/reactivate-subscription', cors(SECURITY_CONFIG.cors), async (req, res) => {
    try {
        const { subscriptionId } = req.body;

        if (!subscriptionId) {
            return res.status(400).json({ error: 'Subscription ID is required' });
        }


        // Get session from HttpOnly cookie
        const sessionId = req.cookies.sid;
        
        if (!sessionId) {
            return res.status(401).json({
                success: false,
                error: 'SESSION_EXPIRED',
                reason: 'No session cookie'
            });
        }
        
        // Get session from storage
        const session = getSession(sessionId);
        
        if (!session) {
            return res.status(401).json({
                success: false,
                error: 'SESSION_EXPIRED',
                reason: 'Invalid or expired session'
            });
        }
        

        // Verify that the user owns this subscription
        try {
            const subscriptionData = await supabaseRequest(`user_subscriptions?user_id=eq.${session.userId}&stripe_subscription_id=eq.${subscriptionId}&select=*`);
            
            if (!subscriptionData || subscriptionData.length === 0) {
                return res.status(403).json({
                    success: false,
                    error: 'FORBIDDEN',
                    reason: 'User does not own this subscription'
                });
            }
            
        } catch (verificationError) {
            // Error: [REACTIVATE_SUBSCRIPTION] Error verifying subscription ownership:', verificationError);
            return res.status(500).json({
                success: false,
                error: 'VERIFICATION_FAILED',
                reason: 'Failed to verify subscription ownership'
            });
        }

        // Reactivate subscription in Stripe
        const subscription = await stripe.subscriptions.update(subscriptionId, {
            cancel_at_period_end: false
        });


        // Update Supabase to clear cancellation
        try {
            await supabaseRequest(`user_subscriptions?user_id=eq.${session.userId}&stripe_subscription_id=eq.${subscriptionId}`, {
                method: 'PATCH',
                body: {
                    cancelled_at: null,
                    cancel_at_period_end: false
                }
            });
        } catch (supabaseError) {
            // Error:⚠️ [REACTIVATE_SUBSCRIPTION] Failed to update Supabase:', supabaseError);
            // Don't fail the reactivation if Supabase update fails
        }

        res.json({
            success: true,
            subscription: {
                id: subscription.id,
                status: subscription.status,
                cancel_at_period_end: subscription.cancel_at_period_end
            }
        });
    } catch (error) {
        // Error: [REACTIVATE_SUBSCRIPTION] Error reactivating subscription:', error);
        res.status(500).json({ error: 'Failed to reactivate subscription' });
    }
});
*/

// Get subscription status from Supabase (preferred method)
app.get('/api/subscription-status/:userId', async (req, res) => {
    try {
        const { userId } = req.params;
        
        // First, test if we can connect to Supabase at all
        try {
            const testData = await supabaseRequest('user_subscriptions?limit=1');
        } catch (connectionError) {
            // Error: Supabase connection failed:', connectionError);
            return res.status(500).json({ 
                error: 'Supabase connection failed',
                details: connectionError.message
            });
        }
        
        // Get subscription from Supabase
        try {
            const data = await supabaseRequest(`user_subscriptions?user_id=eq.${userId}&select=*`);
            
            if (data && data.length > 0) {
                const subscription = data[0];
                
                // Determine subscription status with cancellation logic
                let displayStatus = subscription.status;
                let isCancelled = false;
                let canReactivate = false;
                
                // Check if subscription is cancelled
                if (subscription.cancelled_at && subscription.cancel_at_period_end) {
                    const cancelledAt = new Date(subscription.cancelled_at);
                    const currentPeriodEnd = new Date(subscription.current_period_end);
                    const now = new Date();
                    
                    if (now < currentPeriodEnd) {
                        // Still within paid period - show as "cancelled" but with access
                        displayStatus = 'cancelled_with_access';
                        isCancelled = true;
                        canReactivate = true;
                    } else {
                        // Past billing period - show as "cancelled"
                        displayStatus = 'cancelled';
                        isCancelled = true;
                        canReactivate = true;
                    }
                }
                
                res.json({
                    status: displayStatus,
                    isCancelled: isCancelled,
                    canReactivate: canReactivate,
                    cancelled_at: subscription.cancelled_at,
                    cancel_at_period_end: subscription.cancel_at_period_end,
                    requests_used_this_month: subscription.requests_used_this_month || 0,
                    monthly_request_limit: subscription.monthly_request_limit || 75,
                    is_unlimited: subscription.is_unlimited || false,
                    current_period_end: subscription.current_period_end,
                    stripe_subscription_id: subscription.stripe_subscription_id
                });
            } else {
                // Don't try to create subscription record - just return free tier status
                // This avoids foreign key constraint issues with test users
                res.json({
                    status: 'free',
                    requestsUsed: 0,
                    monthlyLimit: 75,
                    is_unlimited: false,
                    current_period_end: null
                });
            }
        } catch (supabaseError) {
            // Error: Supabase query error:', supabaseError);
            // For any query error, just return free tier status
            res.json({
                status: 'free',
                requestsUsed: 0,
                monthlyLimit: 75,
                is_unlimited: false,
                current_period_end: null
            });
        }
    } catch (error) {
        // Error: Error retrieving subscription from Supabase:', error);
        // Error: Error details:', JSON.stringify(error, null, 2));
        res.status(500).json({ 
            error: 'Failed to retrieve subscription'
        });
    }
});

// STRIPE DISABLED FOR FREE TIER + WAITLIST RELEASE
// Get subscription status from Stripe (fallback method)
/*
app.get('/api/subscription-status-stripe/:subscriptionId', async (req, res) => {
    try {
        const { subscriptionId } = req.params;
        
        const subscription = await stripe.subscriptions.retrieve(subscriptionId);
        
        res.json({
            id: subscription.id,
            status: subscription.status,
            current_period_start: subscription.current_period_start,
            current_period_end: subscription.current_period_end,
            cancel_at_period_end: subscription.cancel_at_period_end
        });
    } catch (error) {
        // Error:Error retrieving subscription from Stripe:', error);
        res.status(500).json({ error: 'Failed to retrieve subscription' });
    }
});
*/

// Update token usage in Supabase
app.post('/api/update-token-usage', async (req, res) => {
    try {
        const { userId, tokensUsed } = req.body;
        
        if (!userId || tokensUsed === undefined) {
            return res.status(400).json({ error: 'Missing userId or tokensUsed' });
        }
        
        // Use the new updateTokenUsage helper function that handles free users
        await updateTokenUsage(userId, tokensUsed);
        
        res.json({ success: true, tokensUsed });
        
    } catch (error) {
        // Error:Error updating token usage in Supabase:', error);
        res.status(500).json({ error: 'Failed to update token usage' });
    }
});

// DEPRECATED: Create subscription record for existing user (admin endpoint)
// This endpoint is no longer used since we switched to the waitlist system
app.post('/api/create-subscription-record', async (req, res) => {
    try {
        const { userId, status = 'free' } = req.body;
        
        if (!userId) {
            return res.status(400).json({ error: 'Missing userId' });
        }
        
        // Return success without creating subscription records
        // The system now uses checkUserRequestLimit() function for tracking user limits
        res.json({ 
            success: true, 
            message: 'Subscription system deprecated - using waitlist system instead',
            status: 'free',
            tokens_used: 0,
            tokens_limit: 50,
            is_unlimited: false,
            current_period_end: null
        });
        
    } catch (error) {
        // Error:Error in deprecated subscription endpoint:', error);
        res.status(500).json({ error: 'Failed to process request' });
    }
});

// Waitlist endpoints
app.post('/api/waitlist', async (req, res) => {
    try {
        const sessionId = req.cookies.sid;
        if (!sessionId) {
            return res.status(401).json({ success: false, error: 'SESSION_EXPIRED' });
        }
        
        const session = getSession(sessionId);
        if (!session) {
            return res.status(401).json({ success: false, error: 'SESSION_EXPIRED' });
        }
        
        const { email, notes } = req.body;
        
        if (!email) {
            return res.status(400).json({ success: false, error: 'Email is required' });
        }
        
        // Check if user is already on waitlist
        const existingEntry = await supabaseRequest(`waitlist?user_id=eq.${session.userId}&select=id`);
        
        if (existingEntry && existingEntry.length > 0) {
            return res.json({
                success: true,
                message: 'You are already on our waitlist!',
                alreadyOnWaitlist: true
            });
        }
        
        // Add user to waitlist
        const waitlistEntry = {
            user_id: session.userId,
            email: email,
            status: 'pending',
            notes: notes || '',
            joined_at: new Date().toISOString()
        };
        
        
        // Debug: Check if service key is available
        
        const response = await supabaseRequest('waitlist', {
            method: 'POST',
            body: waitlistEntry
        });
        
        
            // Verify the record was actually inserted
    try {
        const verification = await supabaseRequest(`waitlist?user_id=eq.${session.userId}&select=*`);

        if (verification && verification.length > 0) {
        } else {
            // Warning: Waitlist entry not found in verification query');
            // Warning: This could mean:');
            // Warning:   - Table does not exist');
            // Warning:   - RLS policies are blocking access');
            // Warning:   - Record was not actually inserted');
        }
    } catch (verifyError) {
        // Error: Error verifying waitlist entry:', verifyError);
        // Error: Verification error details:', verifyError.message);
    }
        
        // Even if response is null (empty response from Supabase), the 201 status means success
        res.json({
            success: true,
            message: 'Successfully joined the waitlist! We\'ll notify you when Pro features are available.',
            waitlistEntry: response || { user_id: session.userId, email: email, status: 'pending' }
        });
        
    } catch (error) {
        // Error: Error adding user to waitlist:', error);
        res.status(500).json({ success: false, error: 'Failed to join waitlist' });
    }
});

app.get('/api/waitlist/status', async (req, res) => {
    try {
        const sessionId = req.cookies.sid;
        if (!sessionId) {
            return res.status(401).json({ success: false, error: 'SESSION_EXPIRED' });
        }
        
        const session = getSession(sessionId);
        if (!session) {
            return res.status(401).json({ success: false, error: 'SESSION_EXPIRED' });
        }
        
        // Check if user is on waitlist
        const waitlistEntry = await supabaseRequest(`waitlist?user_id=eq.${session.userId}&select=*`);
        
        if (waitlistEntry && waitlistEntry.length > 0) {
            res.json({
                success: true,
                onWaitlist: true,
                status: waitlistEntry[0].status,
                joinedAt: waitlistEntry[0].joined_at
            });
        } else {
            res.json({
                success: true,
                onWaitlist: false
            });
        }
        
    } catch (error) {
        // Error: Error checking waitlist status:', error);
        res.status(500).json({ success: false, error: 'Failed to check waitlist status' });
    }
});

// STRIPE DISABLED FOR FREE TIER + WAITLIST RELEASE
// Create customer portal session (for subscription management)
/*
app.post('/api/create-portal-session', async (req, res) => {
    try {
        const { customerId } = req.body;
        
        // Use hardcoded base URL
        const baseUrl = 'https://stripe-deploy.onrender.com';
        
        const session = await stripe.billingPortal.sessions.create({
            customer: customerId,
            return_url: `${baseUrl}/account`,
        });
        
        res.json({ url: session.url });
    } catch (error) {
        // Error:Error creating portal session:', error);
        res.status(500).json({ error: 'Failed to create portal session' });
    }
});
*/

// Waitlist page
app.get('/waitlist', (req, res) => {
    res.send(`
        <!DOCTYPE html>
        <html>
        <head>
            <title>Join Waitlist - Trontiq Pro</title>
            <style>
                body { 
                    font-family: Arial, sans-serif; 
                    text-align: center; 
                    padding: 50px; 
                    background: #f8f9fa; 
                    margin: 0;
                }
                .waitlist-container { 
                    background: white; 
                    padding: 40px; 
                    border-radius: 10px; 
                    box-shadow: 0 2px 10px rgba(0,0,0,0.1); 
                    max-width: 500px;
                    margin: 0 auto;
                }
                .logo { 
                    font-size: 2em; 
                    font-weight: bold; 
                    color: #333; 
                    margin-bottom: 20px;
                }
                .form-group { 
                    margin: 20px 0; 
                    text-align: left;
                }
                label { 
                    display: block; 
                    margin-bottom: 5px; 
                    font-weight: bold;
                }
                input[type="email"] { 
                    width: 100%; 
                    padding: 10px; 
                    border: 1px solid #ddd; 
                    border-radius: 5px; 
                    font-size: 16px;
                    box-sizing: border-box;
                }
                .join-btn { 
                    background: #007bff; 
                    color: white; 
                    padding: 12px 30px; 
                    border: none; 
                    border-radius: 5px; 
                    font-size: 16px; 
                    cursor: pointer; 
                    width: 100%;
                    margin-top: 10px;
                }
                .join-btn:hover { 
                    background: #0056b3; 
                }
                .join-btn:disabled { 
                    background: #ccc; 
                    cursor: not-allowed; 
                }
                .message { 
                    margin-top: 20px; 
                    padding: 10px; 
                    border-radius: 5px; 
                    display: none;
                }
                .success { 
                    background: #d4edda; 
                    color: #155724; 
                    border: 1px solid #c3e6cb; 
                }
                .error { 
                    background: #f8d7da; 
                    color: #721c24; 
                    border: 1px solid #f5c6cb; 
                }
                .features {
                    text-align: left;
                    margin: 30px 0;
                }
                .features h3 {
                    text-align: center;
                    color: #333;
                }
                .features ul {
                    list-style: none;
                    padding: 0;
                }
                .features li {
                    padding: 8px 0;
                    border-bottom: 1px solid #eee;
                }
                .features li:before {
                    content: "✓ ";
                    color: #28a745;
                    font-weight: bold;
                }
            </style>
        </head>
        <body>
            <div class="waitlist-container">
                <div class="logo">Trontiq Pro</div>
                <h2>Join Our Waitlist</h2>
                <p>Be the first to know when Trontiq Pro features are available!</p>
                
                <div class="features">
                    <h3>Pro Features Coming Soon:</h3>
                    <ul>
                        <li>Unlimited AI requests</li>
                        <li>Advanced resume analysis</li>
                        <li>Custom cover letter generation</li>
                        <li>Priority support</li>
                        <li>Early access to new features</li>
                    </ul>
                </div>
                
                <form id="waitlistForm">
                    <div class="form-group">
                        <label for="email">Email Address:</label>
                        <input type="email" id="email" name="email" required>
                    </div>
                    <button type="submit" class="join-btn" id="joinBtn">Join Waitlist</button>
                </form>
                
                <div id="message" class="message"></div>
            </div>
            
            <script>
                document.getElementById('waitlistForm').addEventListener('submit', async function(e) {
                    e.preventDefault();
                    
                    const email = document.getElementById('email').value;
                    const joinBtn = document.getElementById('joinBtn');
                    const message = document.getElementById('message');
                    
                    joinBtn.disabled = true;
                    joinBtn.textContent = 'Joining...';
                    
                    try {
                        const response = await fetch('/api/waitlist', {
                            method: 'POST',
                            headers: {
                                'Content-Type': 'application/json',
                            },
                            credentials: 'include',
                            body: JSON.stringify({ email: email })
                        });
                        
                        const data = await response.json();
                        
                        if (data.success) {
                            message.className = 'message success';
                            message.textContent = data.message;
                            message.style.display = 'block';
                            document.getElementById('waitlistForm').style.display = 'none';
                        } else {
                            throw new Error(data.error || 'Failed to join waitlist');
                        }
                    } catch (error) {
                        message.className = 'message error';
                        message.textContent = 'Error: ' + error.message;
                        message.style.display = 'block';
                        joinBtn.disabled = false;
                        joinBtn.textContent = 'Join Waitlist';
                    }
                });
            </script>
        </body>
        </html>
    `);
});

// Test endpoint
app.get('/api/test-delete', (req, res) => {
    res.json({ message: 'Delete endpoint test - working!' });
});

// Test Redis job description retrieval
app.get('/api/test-redis-jd/:userId', async (req, res) => {
    try {
        const { userId } = req.params;
        
        // Test the exact same function that's used in the app
        const jobDescription = await getJobDescriptionFromRedis(userId);
        
        res.json({
            success: true,
            userId: userId,
            hasJobDescription: !!jobDescription,
            length: jobDescription ? jobDescription.length : 0,
            preview: jobDescription ? jobDescription.substring(0, 200) + '...' : 'No content',
            fullContent: jobDescription || null
        });
        
    } catch (error) {
        // Error: [REDIS-TEST] Error testing Redis JD retrieval:', error);
        res.status(500).json({
            success: false,
            error: 'Internal server error'
        });
    }
});

// Test Supabase auth connection
app.get('/api/test-auth-delete', async (req, res) => {
    try {
        
        // Test the auth endpoint
        const testResponse = await fetch(`${process.env.SUPABASE_URL}/auth/v1/admin/users`, {
            method: 'GET',
            headers: {
                'apikey': process.env.SUPABASE_SERVICE_ROLE_KEY,
                'Authorization': `Bearer ${process.env.SUPABASE_SERVICE_ROLE_KEY}`,
                'Content-Type': 'application/json'
            }
        });
        
        
        if (!testResponse.ok) {
            const errorText = await testResponse.text();
            // Error: Test error response:', errorText);
            return res.json({ 
                success: false, 
                error: `HTTP ${testResponse.status}: ${errorText}`,
                url: `${process.env.SUPABASE_URL}/auth/v1/admin/users`
            });
        }
        
        const users = await testResponse.json();
        
        res.json({ 
            success: true, 
            message: 'Supabase auth connection working',
            userCount: Array.isArray(users) ? users.length : 0,
            sampleUsers: Array.isArray(users) ? users.slice(0, 3).map(u => ({ id: u.id, email: u.email })) : [],
            rawResponse: users
        });
        
    } catch (error) {
        // Error: Test auth connection error:', error);
        res.json({ 
            success: false, 
            error: 'Internal server error'
        });
    }
});

// Get user ID by email endpoint
app.get('/api/get-user-id', async (req, res) => {
    try {
        const { email } = req.query;
        
        if (!email) {
            return res.status(400).json({ error: 'Email is required' });
        }
        
        
        // Get user from Supabase auth by email
        const response = await fetch(`${process.env.SUPABASE_URL}/auth/v1/admin/users`, {
            method: 'GET',
            headers: {
                'apikey': process.env.SUPABASE_SERVICE_ROLE_KEY,
                'Authorization': `Bearer ${process.env.SUPABASE_SERVICE_ROLE_KEY}`,
                'Content-Type': 'application/json'
            }
        });
        
        if (!response.ok) {
            const errorText = await response.text();
            // Error: Error fetching users:', errorText);
            return res.status(500).json({ error: 'Failed to fetch users' });
        }
        
        const users = await response.json();
        
        // Find user by email
        const user = users.find(u => u.email === email);
        
        if (!user) {
            return res.status(404).json({ error: 'User not found' });
        }
        
        res.json({ userId: user.id });
        
    } catch (error) {
        // Error: Error in get-user-id endpoint:', error);
        res.status(500).json({ 
            error: 'Failed to get user ID'
        });
    }
});

// Session-based user info endpoint (secure) - GET for reading, POST for writing
app.get('/api/me', cors(SECURITY_CONFIG.cors), authenticateSession, async (req, res) => {
    try {
        
        // Get user data from Supabase Admin API (auth/users is not accessible via REST API)
        let user, fullName, displayName;
        try {
            const userResponse = await fetch(`${process.env.SUPABASE_URL}/auth/v1/admin/users/${req.userId}`, {
                method: 'GET',
                headers: {
                    'apikey': process.env.SUPABASE_SERVICE_ROLE_KEY,
                    'Authorization': `Bearer ${process.env.SUPABASE_SERVICE_ROLE_KEY}`,
                    'Content-Type': 'application/json'
                }
            });
            
            if (!userResponse.ok) {
                // Error: [API/ME] Failed to fetch user from Admin API:', userResponse.status);
                return res.status(401).json({
                    success: false,
                    error: 'User not found'
                });
            }
            
            user = await userResponse.json();
            fullName = user.user_metadata?.full_name || 'Not provided';
            // Only use display_name from metadata, don't fall back to fullName (which might be email prefix)
            displayName = user.user_metadata?.display_name || 'User';
            
            // Debug: Log resume data availability
            const resumeText = user.user_metadata?.resume_text || '';
            
        } catch (adminApiError) {
            // Error: [API/ME] Admin API error:', adminApiError);
            return res.status(401).json({
                success: false,
                error: 'User not found'
            });
        }
        
        // Get user preferences from user_preferences table
        let userPreferences;
        try {
            userPreferences = await supabaseRequest(`user_preferences?user_id=eq.${req.userId}&select=*`);
        } catch (preferencesError) {
            // Error: [API/ME] Preferences fetch error:', preferencesError);
            // Continue with default preferences
            userPreferences = null;
        }
        
        // FREE TIER MODE: Always use new request tracking system
        // Get current month's request count from requests table
        const requestLimit = await checkUserRequestLimit(req.userId);
        const requestsUsed = requestLimit.requestCount;
        const monthlyLimit = requestLimit.limit; // 15 for free tier
        
        // Always return free tier data (ignore old subscription data)
        // Reduced cache time for request count accuracy
        res.set('Cache-Control', 'private, max-age=5');
        
        res.json({
            success: true,
            isAuthenticated: true,
            plan: 'free',
            isProUser: false,
            canChat: true,
            upgradeRequired: false,
            upgradeUrl: '/waitlist',
            // Add user personal information
            user: {
                id: req.userId,
                email: user.email,
                display_name: displayName,
                full_name: fullName,
                user_metadata: user.user_metadata,
                // Include resume text from user metadata
                resume_text: user.user_metadata?.resume_text || '',
                // Include request count data in user object
                requestsUsed: requestsUsed,
                monthlyLimit: monthlyLimit,
                plan: 'free',
                // Include all preferences for widget compatibility
                preferences: userPreferences && userPreferences.length > 0 ? {
                    display_name: userPreferences[0].display_name || displayName,
                    tone: userPreferences[0].tone || 'professional',
                    education: userPreferences[0].education || 'bachelor',
                    language: userPreferences[0].language || 'english'
                } : {
                    display_name: displayName,
                    tone: 'professional',
                    education: 'bachelor',
                    language: 'english'
                }
            }
        });
        
        return; // Exit early - no need to check old subscription data
        
        // OLD SUBSCRIPTION LOGIC (DISABLED FOR FREE TIER)
        /*
        // Get user subscription data
        let subscriptionData;
        try {
            subscriptionData = await supabaseRequest(`user_subscriptions?user_id=eq.${session.userId}&select=*`);
        } catch (subscriptionError) {
            // Error: [API/ME] Subscription fetch error:', subscriptionError);
            // Continue with default free user data
            subscriptionData = null;
        }
        
        if (subscriptionData && subscriptionData.length > 0) {
            const subscription = subscriptionData[0];
            const requestsUsed = subscription.requests_used_this_month || 0;
            const monthlyLimit = subscription.monthly_request_limit || 75;
            const isUnlimited = subscription.is_unlimited || false;
            
            // Determine subscription status with cancellation logic (same as subscription-status endpoint)
            let displayStatus = subscription.status;
            let isCancelled = false;
            let canReactivate = false;
            let isProUser = false;
            
            // Check if subscription is cancelled FIRST (this takes priority over status)
            if (subscription.cancelled_at && subscription.cancel_at_period_end) {
                const cancelledAt = new Date(subscription.cancelled_at);
                const currentPeriodEnd = new Date(subscription.current_period_end);
                const now = new Date();
                
                if (now < currentPeriodEnd) {
                    // Still within paid period - show as "cancelled" but with access
                    displayStatus = 'cancelled_with_access';
                    isCancelled = true;
                    canReactivate = true;
                    isProUser = true; // Still has Pro access for features
                } else {
                    // Past billing period - show as "cancelled"
                    displayStatus = 'cancelled';
                    isCancelled = true;
                    canReactivate = true;
                    isProUser = false; // No longer has Pro access
                }
            } else {
                // Not cancelled - check if active and unlimited
                isProUser = subscription.status === 'active' && isUnlimited;
            }
            
            // Debug: Log the final response data
            const responseData = {
                success: true,
                isAuthenticated: true,
                plan: isProUser ? 'pro' : 'free',
                isProUser: isProUser,
                canChat: isProUser || requestsUsed < monthlyLimit,
                requestsUsed: requestsUsed,
                monthlyLimit: monthlyLimit,
                upgradeRequired: !isProUser && requestsUsed >= monthlyLimit,
                upgradeUrl: '/waitlist',
                // Add subscription information for cancellation
                stripe_subscription_id: subscription.stripe_subscription_id,
                // Add cancellation information
                subscriptionStatus: displayStatus,
                isCancelled: isCancelled,
                canReactivate: canReactivate,
                cancelled_at: subscription.cancelled_at,
                cancel_at_period_end: subscription.cancel_at_period_end,
                current_period_end: subscription.current_period_end,
                // Add user personal information
                user: {
                    id: session.userId, // Add user ID for subscription operations
                    email: user.email,
                    display_name: displayName,
                    full_name: fullName,
                    user_metadata: user.user_metadata,
                    // Include resume text from user metadata
                    resume_text: user.user_metadata?.resume_text || '',
                    // Include all preferences for widget compatibility
                    preferences: userPreferences && userPreferences.length > 0 ? {
                        display_name: userPreferences[0].display_name || displayName,
                        tone: userPreferences[0].tone || 'professional',
                        education: userPreferences[0].education || 'bachelor',
                        language: userPreferences[0].language || 'english'
                    } : {
                        display_name: displayName,
                        tone: 'professional',
                        education: 'bachelor',
                        language: 'english'
                    }
                }
            };
            
            // Set cache headers
            res.set('Cache-Control', 'private, max-age=30');
            
            res.json(responseData);
        } else {
            // No subscription found - check if free user has usage tracking record
            res.set('Cache-Control', 'private, max-age=30');
            
            // Get current month's request count from requests table
            const requestLimit = await checkUserRequestLimit(req.userId);
            const requestsUsed = requestLimit.requestCount;
            const monthlyLimit = requestLimit.limit; // 15 for free tier
            
            // Debug: Log resume data for free users
            const freeUserResumeText = user.user_metadata?.resume_text || '';
            
            res.json({
                success: true,
                isAuthenticated: true,
                plan: 'free',
                isProUser: false,
                canChat: true,
                requestsUsed: requestsUsed,
                monthlyLimit: monthlyLimit,
                upgradeRequired: false,
                upgradeUrl: '/waitlist',
                // Add user personal information
                user: {
                    id: session.userId, // Add user ID for subscription operations
                    email: user.email,
                    display_name: displayName,
                    full_name: fullName,
                    user_metadata: user.user_metadata,
                    // Include resume text from user metadata
                    resume_text: user.user_metadata?.resume_text || '',
                    // Include all preferences for widget compatibility
                    preferences: userPreferences && userPreferences.length > 0 ? {
                        display_name: userPreferences[0].display_name || displayName,
                        tone: userPreferences[0].tone || 'professional',
                        education: userPreferences[0].education || 'bachelor',
                        language: userPreferences[0].language || 'english'
                    } : {
                        display_name: displayName,
                        tone: 'professional',
                        education: 'bachelor',
                        language: 'english'
                    }
                }
            });
        }
        */
        
    } catch (error) {
        // Error: [API/ME] Endpoint error:', error);
        
        // Return 503 for internal errors, not 500
        res.status(503).json({
            success: false,
            error: 'TEMP_UNAVAILABLE',
            code: 'TEMP_UNAVAILABLE'
        });
    }
});

// POST method for updating user preferences and profile data
app.post('/api/me', cors(SECURITY_CONFIG.cors), async (req, res) => {
    try {
        
        // Get session from HttpOnly cookie
        const sessionId = req.cookies.sid;
        
        if (!sessionId) {
            return res.status(401).json({
                success: false,
                error: 'SESSION_EXPIRED',
                reason: 'No session cookie'
            });
        }
        
        // Get session from storage
        const session = getSession(sessionId);
        
        if (!session) {
            return res.status(401).json({
                success: false,
                error: 'SESSION_EXPIRED',
                reason: 'Invalid or expired session'
            });
        }
        
        
        // Extend session (rolling renewal)
        extendSession(sessionId);
        
        const { display_name } = req.body;
        
        // Only handle display name updates (other preferences moved to local storage)
        if (!display_name) {
            return res.status(400).json({
                success: false,
                error: 'Display name is required'
            });
        }
        
        
        // Update display name in user_preferences table
        try {
            // Check if user preferences exist
            const existingPreferences = await supabaseRequest(`user_preferences?user_id=eq.${session.userId}&select=*`);
            
            if (existingPreferences && existingPreferences.length > 0) {
                // Update existing preferences
                const updateResult = await supabaseRequest(`user_preferences?user_id=eq.${session.userId}`, {
                    method: 'PATCH',
                    body: {
                        display_name: display_name,
                        updated_at: new Date().toISOString()
                    }
                });
                
                if (updateResult === null) {
                    // 204 response means success
                } else if (!updateResult) {
                    throw new Error('Failed to update display name');
                }
            } else {
                // Insert new preferences with just display name
                const insertResult = await supabaseRequest('user_preferences', {
                    method: 'POST',
                    body: {
                        user_id: session.userId,
                        display_name: display_name,
                        updated_at: new Date().toISOString()
                    }
                });
                
                if (insertResult === null) {
                    // 204 response means success
                } else if (!insertResult) {
                    throw new Error('Failed to create display name');
                }
            }
            
            // Also update display name in user metadata for backward compatibility
            try {
                const userResponse = await fetch(`${process.env.SUPABASE_URL}/auth/v1/admin/users/${session.userId}`, {
                    method: 'PUT',
                    headers: {
                        'apikey': process.env.SUPABASE_SERVICE_ROLE_KEY,
                        'Authorization': `Bearer ${process.env.SUPABASE_SERVICE_ROLE_KEY}`,
                        'Content-Type': 'application/json'
                    },
                    body: JSON.stringify({
                        user_metadata: { display_name: display_name }
                    })
                });
                
                if (userResponse.ok) {
                }
            } catch (metadataError) {
                // Warning: [API/ME POST] Could not update display name in metadata:', metadataError);
            }
            
            res.json({
                success: true,
                message: 'Display name updated successfully'
            });
            
        } catch (updateError) {
            // Error: [API/ME POST] Update error:', updateError);
            return res.status(500).json({
                success: false,
                error: 'Failed to update display name'
            });
        }
        
    } catch (error) {
        // Error: [API/ME POST] Endpoint error:', error);
        res.status(503).json({
            success: false,
            error: 'TEMP_UNAVAILABLE',
            code: 'TEMP_UNAVAILABLE'
        });
    }
});

// Removed old preference endpoints - now consolidated to /api/me

// Removed tone preference endpoints - now consolidated to /api/me

// Removed education GET endpoint - now consolidated to /api/me

app.post('/api/prefs/education', cors(SECURITY_CONFIG.cors), async (req, res) => {
    try {
        // Get session from HttpOnly cookie
        const sessionId = req.cookies.sid;
        
        if (!sessionId) {
            return res.status(401).json({
                success: false,
                error: 'SESSION_EXPIRED',
                reason: 'No session cookie'
            });
        }
        
        // Get session from storage
        const session = getSession(sessionId);
        
        if (!session) {
            return res.status(401).json({
                success: false,
                error: 'SESSION_EXPIRED',
                reason: 'Invalid or expired session'
            });
        }
        
        const { education } = req.body;
        
        if (!education) {
            return res.status(400).json({
                success: false,
                error: 'Education level is required'
            });
        }
        
        
        res.json({ success: true, education });
        
    } catch (error) {
        // Error: Save education error:', error);
        res.status(500).json({
            success: false,
            error: error.message
        });
    }
});

app.get('/api/prefs/language', cors(SECURITY_CONFIG.cors), async (req, res) => {
    try {
        // Get session from HttpOnly cookie
        const sessionId = req.cookies.sid;
        
        if (!sessionId) {
            return res.status(401).json({
                success: false,
                error: 'SESSION_EXPIRED',
                reason: 'No session cookie'
            });
        }
        
        // Get session from storage
        const session = getSession(sessionId);
        
        if (!session) {
            return res.status(401).json({
                success: false,
                error: 'SESSION_EXPIRED',
                reason: 'Invalid or expired session'
            });
        }
        
        // Return user's language preference
        res.json({
            success: true,
            data: {
                language: 'english' // Default value
            }
        });
        
    } catch (error) {
        // Error: Get language error:', error);
        res.status(500).json({
            success: false,
            error: error.message
        });
    }
});

app.post('/api/prefs/language', cors(SECURITY_CONFIG.cors), async (req, res) => {
    try {
        // Get session from HttpOnly cookie
        const sessionId = req.cookies.sid;
        
        if (!sessionId) {
            return res.status(401).json({
                success: false,
                error: 'SESSION_EXPIRED',
                reason: 'No session cookie'
            });
        }
        
        // Get session from storage
        const session = getSession(sessionId);
        
        if (!session) {
            return res.status(401).json({
                success: false,
                error: 'SESSION_EXPIRED',
                reason: 'Invalid or expired session'
            });
        }
        
        const { language } = req.body;
        
        if (!language) {
            return res.status(400).json({
                success: false,
                error: 'Language is required'
            });
        }
        
        
        res.json({ success: true, language });
        
    } catch (error) {
        // Error: Save language error:', error);
        res.status(500).json({
            success: false,
            error: error.message
        });
    }
});

// Display name preference endpoint
app.get('/api/prefs/display_name', cors(SECURITY_CONFIG.cors), async (req, res) => {
    try {
        const sessionId = req.cookies.sid;
        if (!sessionId) {
            return res.status(401).json({ success: false, error: 'SESSION_EXPIRED' });
        }
        
        const session = getSession(sessionId);
        if (!session) {
            return res.status(401).json({ success: false, error: 'SESSION_EXPIRED' });
        }
        
        // Get user data from Supabase Admin API
        const userResponse = await fetch(`${process.env.SUPABASE_URL}/auth/v1/admin/users/${session.userId}`, {
            method: 'GET',
            headers: {
                'apikey': process.env.SUPABASE_SERVICE_ROLE_KEY,
                'Authorization': `Bearer ${process.env.SUPABASE_SERVICE_ROLE_KEY}`,
                'Content-Type': 'application/json'
            }
        });
        
        if (!userResponse.ok) {
            return res.status(401).json({ success: false, error: 'User not found' });
        }
        
        const user = await userResponse.json();
        const displayName = user.user_metadata?.display_name || 'User';
        
        res.json({ success: true, display_name: displayName });
        
    } catch (error) {
        // Error: Get display name error:', error);
        res.status(500).json({ success: false, error: error.message });
    }
});

app.post('/api/prefs/display_name', cors(SECURITY_CONFIG.cors), async (req, res) => {
    try {
        const sessionId = req.cookies.sid;
        if (!sessionId) {
            return res.status(401).json({ success: false, error: 'SESSION_EXPIRED' });
        }
        
        const session = getSession(sessionId);
        if (!session) {
            return res.status(401).json({ success: false, error: 'SESSION_EXPIRED' });
        }
        
        const { display_name } = req.body;
        
        if (!display_name) {
            return res.status(400).json({
                success: false,
                error: 'Display name is required'
            });
        }
        
        // Update user metadata in Supabase Admin API
        const updateResponse = await fetch(`${process.env.SUPABASE_URL}/auth/v1/admin/users/${session.userId}`, {
            method: 'PUT',
            headers: {
                'apikey': process.env.SUPABASE_SERVICE_ROLE_KEY,
                'Authorization': `Bearer ${process.env.SUPABASE_SERVICE_ROLE_KEY}`,
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                user_metadata: { display_name: display_name }
            })
        });
        
        if (!updateResponse.ok) {
            // Error: Failed to update user metadata:', updateResponse.status);
            return res.status(500).json({ success: false, error: 'Failed to update display name' });
        }
        
        
        res.json({ success: true, display_name });
        
    } catch (error) {
        // Error: Save display name error:', error);
        res.status(500).json({ success: false, error: error.message });
    }
});

// Upgrade endpoint
app.get('/api/upgrade', (req, res) => {
    res.json({
        title: 'Upgrade to Pro',
        message: 'Get unlimited AI assistance and advanced features',
        features: [
            'Unlimited requests per month',
            'Advanced resume and cover letter tools',
            'Priority support',
            'Early access to new features'
        ],
        price: '$4.99/month',
        upgradeUrl: '/waitlist'
    });
});

// Clear account data endpoint
app.post('/api/account/clear', async (req, res) => {
    try {
        const { userId } = req.body;
        
        if (!userId) {
            return res.status(401).json({
                success: false,
                error: 'User ID required'
            });
        }
        
        
        res.json({ 
            success: true, 
            message: 'Account data cleared successfully' 
        });
        
    } catch (error) {
        // Error: Clear account error:', error);
        res.status(500).json({
            success: false,
            error: error.message
        });
    }
});

// Delete user account endpoint
app.post('/api/delete-account', async (req, res) => {
    try {
        const { userId } = req.body;
        
        if (!userId) {
            return res.status(400).json({ error: 'User ID is required' });
        }
        
        
        // 1. Cancel any active Stripe subscription
        try {
            const subscriptionResponse = await supabaseRequest(`user_subscriptions?user_id=eq.${userId}&status=eq.active`, {
                method: 'GET'
            });
            
            if (subscriptionResponse && subscriptionResponse.length > 0) {
                const subscription = subscriptionResponse[0];
                if (subscription.stripe_subscription_id) {
                    
                    // Cancel the subscription in Stripe
                    const stripe = require('stripe')(process.env.STRIPE_SECRET_KEY);
                    await stripe.subscriptions.cancel(subscription.stripe_subscription_id);
                    
                }
            }
        } catch (stripeError) {
            // Error:⚠️ Error canceling Stripe subscription:', stripeError);
            // Continue with account deletion even if Stripe cancellation fails
        }
        
        // 2. Delete user subscription record
        try {
            await supabaseRequest(`user_subscriptions?user_id=eq.${userId}`, {
                method: 'DELETE'
            });
        } catch (subscriptionError) {
            // Error:⚠️ Error deleting subscription record:', subscriptionError);
        }
        
        // 2.5. Delete privacy audit log records for this user
        try {
            await supabaseRequest(`privacy_audit_log?user_id=eq.${userId}`, {
                method: 'DELETE'
            });
        } catch (auditDeleteError) {
            // Error:⚠️ Error deleting audit log records:', auditDeleteError);
        }
        
        // 3. Delete user from Supabase auth
        try {
            
            const deleteResponse = await fetch(`${process.env.SUPABASE_URL}/auth/v1/admin/users/${userId}`, {
                method: 'DELETE',
                headers: {
                    'apikey': process.env.SUPABASE_SERVICE_ROLE_KEY,
                    'Authorization': `Bearer ${process.env.SUPABASE_SERVICE_ROLE_KEY}`,
                    'Content-Type': 'application/json'
                }
            });
            
            
            if (!deleteResponse.ok) {
                const errorText = await deleteResponse.text();
                // Error: Supabase delete error response:', errorText);
                throw new Error(`Supabase API error: ${deleteResponse.status} ${deleteResponse.statusText} - ${errorText}`);
            }
            
        } catch (authError) {
            // Error: Error deleting user from auth:', authError);
            return res.status(500).json({ 
                error: 'Failed to delete user account',
                details: authError.message 
            });
        }
        
        // 4. Clean up Redis data (chat sessions and job descriptions)
        try {
            await deleteUserChatSessions(userId);
            await deleteJobDescriptionFromRedis(userId);
        } catch (redisError) {
            // Error: Error cleaning up Redis data:', redisError);
            // Continue with deletion even if Redis cleanup fails
        }
        
        // 5. Log the deletion for audit purposes (removed to avoid foreign key constraint)
        res.json({ success: true, message: 'Account deleted successfully' });
        
    } catch (error) {
        // Error: Error in delete account endpoint:', error);
        res.status(500).json({ 
            error: 'Failed to delete account'
        });
    }
});

// Resume text endpoints
app.get('/api/resume', cors(SECURITY_CONFIG.cors), async (req, res) => {
    try {
        const sessionId = req.cookies.sid;
        if (!sessionId) {
            return res.status(401).json({ success: false, error: 'SESSION_EXPIRED' });
        }
        
        const session = getSession(sessionId);
        if (!session) {
            return res.status(401).json({ success: false, error: 'SESSION_EXPIRED' });
        }
        
        // Get user data from Supabase Admin API
        const userResponse = await fetch(`${process.env.SUPABASE_URL}/auth/v1/admin/users/${session.userId}`, {
            method: 'GET',
            headers: {
                'apikey': process.env.SUPABASE_SERVICE_ROLE_KEY,
                'Authorization': `Bearer ${process.env.SUPABASE_SERVICE_ROLE_KEY}`,
                'Content-Type': 'application/json'
            }
        });
        
        if (!userResponse.ok) {
            return res.status(401).json({ success: false, error: 'User not found' });
        }
        
        const user = await userResponse.json();
        const resumeText = user.user_metadata?.resume_text || '';
        const savedDate = user.user_metadata?.resume_saved_date || null;
        
        res.json({
            success: true,
            data: {
                resume_text: resumeText,
                saved_date: savedDate
            }
        });
        
    } catch (error) {
        // Error: Get resume error:', error);
        res.status(500).json({
            success: false,
            error: error.message
        });
    }
});

app.post('/api/resume', cors(SECURITY_CONFIG.cors), async (req, res) => {
    try {
        const sessionId = req.cookies.sid;
        if (!sessionId) {
            return res.status(401).json({ success: false, error: 'SESSION_EXPIRED' });
        }
        
        const session = getSession(sessionId);
        if (!session) {
            return res.status(401).json({ success: false, error: 'SESSION_EXPIRED' });
        }
        
        const { resume_text } = req.body;
        
        if (!resume_text) {
            return res.status(400).json({
                success: false,
                error: 'Resume text is required'
            });
        }
        
        // Update user metadata in Supabase Admin API
        const updateResponse = await fetch(`${process.env.SUPABASE_URL}/auth/v1/admin/users/${session.userId}`, {
            method: 'PUT',
            headers: {
                'apikey': process.env.SUPABASE_SERVICE_ROLE_KEY,
                'Authorization': `Bearer ${process.env.SUPABASE_SERVICE_ROLE_KEY}`,
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                user_metadata: {
                    resume_text: resume_text,
                    resume_saved_date: new Date().toISOString()
                }
            })
        });
        
        if (!updateResponse.ok) {
            // Error: Failed to update user metadata:', updateResponse.status);
            return res.status(500).json({ success: false, error: 'Failed to save resume' });
        }
        
        
        res.json({
            success: true,
            data: {
                resume_text: resume_text,
                saved_date: new Date().toISOString()
            }
        });
        
    } catch (error) {
        // Error: Save resume error:', error);
        res.status(500).json({
            success: false,
            error: error.message
        });
    }
});

// Helper function to check user subscription status
async function checkUserSubscriptionStatus(userId) {
    try {
        
        // Get subscription from Supabase
        const data = await supabaseRequest(`user_subscriptions?user_id=eq.${userId}&select=*`);
        
        if (data && data.length > 0) {
            const subscription = data[0];
            const isProUser = subscription.status === 'active' && subscription.is_unlimited;
            const requestsUsed = subscription.requests_used_this_month || 0;
            const monthlyLimit = subscription.monthly_request_limit || 75;
            
            if (!isProUser && requestsUsed >= monthlyLimit) {
                return {
                    upgradeRequired: true,
                    upgradeMessage: 'You have reached your monthly limit. Upgrade to Pro for unlimited access.',
                    upgradeUrl: '/upgrade'
                };
            }
        }
        
        return { upgradeRequired: false };
    } catch (error) {
        // Error: Error checking subscription status:', error);
        // Default to allowing access if there's an error
        return { upgradeRequired: false };
    }
}

// Helper function to log request and check limits
async function logUserRequest(userId, requestType = 'chat', tokensUsed = 0) {
    try {
        
        // Log the request in the requests table
        const requestLog = {
            user_id: userId,
            request_type: requestType,
            tokens_used: tokensUsed,
            timestamp: new Date().toISOString()
        };
        
        const logResponse = await supabaseRequest('requests', {
            method: 'POST',
            body: requestLog
        });
        
        return logResponse;
    } catch (error) {
        // Error: Error logging request:', error);
        return null;
    }
}

// Helper function to check if user can make requests (under 15/month limit)
async function checkUserRequestLimit(userId) {
    try {
        
        // Get current month's request count (only count 'chat' requests, not 'regenerate')
        const now = new Date();
        const startOfMonth = new Date(now.getFullYear(), now.getMonth(), 1).toISOString();
        
        const requests = await supabaseRequest(`requests?user_id=eq.${userId}&timestamp=gte.${startOfMonth}&request_type=eq.chat&select=id`);
        
        
        const requestCount = requests ? requests.length : 0;
        const limit = 15; // Free tier limit
        const canMakeRequest = requestCount < limit;
        
        
        return {
            canMakeRequest,
            requestCount,
            limit,
            remaining: limit - requestCount
        };
    } catch (error) {
        // Error: Error checking request limit:', error);
        // Default to allowing request if there's an error
        return {
            canMakeRequest: true,
            requestCount: 0,
            limit: 15,
            remaining: 15
        };
    }
}

// OpenAI API proxy endpoint - PHASE 1: Intent Detection
app.post('/api/generate', cors(SECURITY_CONFIG.cors), authenticateSession, async (req, res) => {
    try {
        
        // NEW: Accept server-side prompt building parameters
        const { 
            model, 
            messages, 
            max_tokens, 
            temperature, 
            isRegenerate,
            // NEW: Server-side prompt building parameters
            message,
            userProfile,
            jobContext,
            sessionId,
            toggleState,
            mode
        } = req.body;
        
        
        
        // ✅ RESTORE ORIGINAL SINGLE-CALL ARCHITECTURE
        let finalMessages = messages;
        
        // SERVER-SIDE PROMPT BUILDING: Build complete prompt and return final response
        if (message && userProfile && toggleState !== undefined) {
            
            try {
                // Build the complete prompt based on mode (like original client-side)
                let prompt;
                
                if (mode === 'natural') {
                    // For natural mode, build the complete conversation prompt (not just intent detection)
                    prompt = await buildNaturalIntentPrompt(message, sessionId, userProfile, toggleState, req.userId);
                } else if (mode === 'analysis') {
                    // For analysis mode, build the detailed analysis prompt
                    prompt = await buildDetailedAnalysisPrompt(message, sessionId, userProfile, toggleState, req.userId);
                } else if (mode === 'generate') {
                    // For generate mode, determine what to generate based on message content
                    
                    // Get conversation context from chat history (retrieval only)
                    const chatHistoryData = await manageChatHistory(sessionId, [], null, req.userId);
                    
                    if (message.toLowerCase().includes('resume') || message.toLowerCase().includes('tailored resume')) {
                        prompt = await buildResumePrompt(message, sessionId, userProfile, toggleState, req.userId);
                    } else if (message.toLowerCase().includes('cover letter') || message.toLowerCase().includes('cover letter')) {
                        prompt = await buildCoverLetterPrompt(message, sessionId, userProfile, toggleState, req.userId);
                    } else {
                        // Default to resume generation
                        prompt = await buildResumePrompt(message, sessionId, userProfile, toggleState, req.userId);
                    }
                } else {
                    // Default to natural conversation
                    prompt = await buildNaturalIntentPrompt(message, sessionId, userProfile, toggleState, req.userId);
                }
                
                const systemMessage = SYSTEM_PROMPT;
                
                // Build the complete message structure (like original client-side)
                finalMessages = [{
                    role: 'system',
                    content: systemMessage
                }, {
                    role: 'user',
                    content: prompt
                }];
                
            } catch (error) {
                // Error: [SINGLE-CALL] Error building complete prompt:', error);
                return res.status(500).json({
                    success: false,
                    error: `Failed to build complete prompt: ${error.message}`
                });
            }
        } else {
            // Use client-provided messages (backward compatibility)
        }
        
        if (!model || !finalMessages) {
            return res.status(400).json({
                success: false,
                error: 'Model and messages are required'
            });
        }
        
        // Check if this is a regenerate request
        const isRegenerateRequest = isRegenerate === true;
        
        // Only check request limit for new requests, not regenerates
        if (!isRegenerateRequest) {
            // Check user request limit (15 requests per month for free tier)
            const requestLimit = await checkUserRequestLimit(req.userId);
            if (!requestLimit.canMakeRequest) {
                return res.status(402).json({
                    success: false,
                    upgradeRequired: true,
                    upgradeMessage: `You've reached your monthly limit of ${requestLimit.limit} requests. Join our waitlist to be notified when Pro features are available!`,
                    upgradeUrl: '/waitlist',
                    requestCount: requestLimit.requestCount,
                    limit: requestLimit.limit
                });
            }
        }
        
        // Get API key from the 10-key rotation system
        const apiKey = getNextApiKey();
        if (!apiKey) {
            // Error: No API keys available');
            return res.status(500).json({
                success: false,
                error: 'No API keys available'
            });
        }
        
        // Call OpenAI API with rotated key
        
        const openaiResponse = await fetch('https://api.openai.com/v1/chat/completions', {
            method: 'POST',
            headers: {
                'Authorization': `Bearer ${apiKey}`,
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                model: model,
                messages: finalMessages,
                max_tokens: max_tokens || 3500,
                temperature: temperature || 0.7
            })
        });
        
        
        if (!openaiResponse.ok) {
            const errorData = await openaiResponse.text();
            // Error: OpenAI API error:', openaiResponse.status, errorData);
            
            // Mark the current key as failed if it's a rate limit or authentication error
            if (openaiResponse.status === 429 || openaiResponse.status === 401) {
                markKeyAsFailed(currentKeyIndex);
            }
            
            return res.status(openaiResponse.status).json({
                success: false,
                error: `OpenAI API error: ${openaiResponse.status} - ${errorData}`
            });
        }
        
        const data = await openaiResponse.json();
        
        // Log the request (but don't count regenerates against monthly limit)
        if (data.usage) {
            const requestType = isRegenerateRequest ? 'regenerate' : 'chat';
            await logUserRequest(req.userId, requestType, data.usage.total_tokens);
        } else {
            const requestType = isRegenerateRequest ? 'regenerate' : 'chat';
            await logUserRequest(req.userId, requestType, 0);
        }
        
        // Extract the response content from OpenAI with better error handling
        let responseContent = '';
        if (data.choices && data.choices.length > 0 && data.choices[0] && data.choices[0].message) {
            responseContent = data.choices[0].message.content || '';
        } else {
            // Error: [ERROR] Invalid OpenAI response structure:', data);
            return res.status(500).json({
                success: false,
                error: 'Invalid response from OpenAI API'
            });
        }
        
        // Check if response content is empty
        if (!responseContent || responseContent.trim() === '') {
            // Error: [ERROR] Empty response content from OpenAI');
            return res.status(500).json({
                success: false,
                error: 'Empty response from OpenAI API'
            });
        }
        
        // Strip decision tags from response before sending to client
        const parsedResponse = parseAIDecision(responseContent);
        
        // 🎯 EXECUTE AI DECISION - Switch to appropriate function based on AI's intent
        let finalResponse = parsedResponse.response;
        let finalUsage = data.usage;
        
        if (parsedResponse.type === 'ANALYSIS') {
            try {
                const analysisPrompt = await buildDetailedAnalysisPrompt(message, sessionId, userProfile, toggleState, req.userId);
                const analysisData = await callOpenAI(analysisPrompt, 'gpt-4o', 4000, 0.7);
                finalResponse = analysisData.choices[0].message.content;
                finalUsage = analysisData.usage;
            } catch (error) {
                // Error: [EXECUTE AI DECISION] Analysis failed, using original response:', error);
                // Keep original response if analysis fails
            }
        } else if (parsedResponse.type === 'RESUME_GENERATION') {
            try {
                const resumePrompt = await buildResumePrompt(message, sessionId, userProfile, toggleState, req.userId);
                const resumeData = await callOpenAI(resumePrompt, 'gpt-4o', 4000, 0.7);
                finalResponse = resumeData.choices[0].message.content;
                finalUsage = resumeData.usage;
            } catch (error) {
                // Error: [EXECUTE AI DECISION] Resume generation failed, using original response:', error);
                // Keep original response if resume generation fails
            }
        } else if (parsedResponse.type === 'COVER_LETTER_GENERATION') {
            try {
                const coverLetterPrompt = await buildCoverLetterPrompt(message, sessionId, userProfile, toggleState, req.userId);
                const coverLetterData = await callOpenAI(coverLetterPrompt, 'gpt-4o', 4000, 0.7);
                finalResponse = coverLetterData.choices[0].message.content;
                finalUsage = coverLetterData.usage;
            } catch (error) {
                // Error: [EXECUTE AI DECISION] Cover letter generation failed, using original response:', error);
                // Keep original response if cover letter generation fails
            }
        }
        
        // 💾 SAVE CONVERSATION TO REDIS
        try {
            await manageChatHistory(sessionId, [
                { role: 'user', content: message },
                { role: 'assistant', content: finalResponse }
            ], null, req.userId);
        } catch (error) {
            // Error: [CHAT HISTORY] Error saving conversation:', error);
            // Don't fail the request if chat history saving fails
        }
        
        res.json({
            success: true,
            content: finalResponse, // Send final response (either original or from specialized function)
            usage: finalUsage
        });
        
    } catch (error) {
        // Error: Generate API error:', error.message);
        
        // Provide user-friendly error messages
        let errorMessage = 'Failed to generate response';
        if (error.message.includes('Cannot read properties of undefined')) {
            errorMessage = 'Failed to generate response: Invalid data structure received';
        } else if (error.message.includes('API key')) {
            errorMessage = 'Failed to generate response: API key issue';
        } else if (error.message.includes('rate limit')) {
            errorMessage = 'Failed to generate response: Rate limit exceeded';
        } else {
            errorMessage = 'Failed to generate response: Please try again';
        }
        
        res.status(500).json({
            success: false,
            error: errorMessage
        });
    }
});

// ✅ NEW ENDPOINT: Execute AI Decision (Phase 2 of the two-phase system)
// REMOVED: /api/execute-decision endpoint - no longer needed with single-call architecture

// Error handling middleware
app.use((error, req, res, next) => {
    // Error:Unhandled error:', error);
    res.status(500).json({ error: 'Internal server error' });
});


// Webhook handler functions for Supabase integration

async function handleCheckoutCompleted(session) {
    try {
        
        // Get subscription details from Stripe
        const subscription = await stripe.subscriptions.retrieve(session.subscription);
        
        // Get customer details from Stripe
        const customer = await stripe.customers.retrieve(subscription.customer);
        
        // Find user by email in Supabase
        try {
            
            // Use the correct Supabase admin API endpoint
            const response = await fetch(`${SUPABASE_URL}/auth/v1/admin/users`, {
                method: 'GET',
                headers: {
                    'Authorization': `Bearer ${SUPABASE_SERVICE_ROLE_KEY}`,
                    'apikey': SUPABASE_SERVICE_ROLE_KEY,
                    'Content-Type': 'application/json'
                }
            });
            
            if (!response.ok) {
                // Error: Failed to fetch users from Supabase:', response.status, response.statusText);
                return;
            }
            
            const users = await response.json();
            
            const user = users.find(u => u.email === customer.email);
            if (!user) {
                return;
            }
            
            
            // Update or create subscription record
            const subscriptionData = {
                user_id: user.id,
                stripe_subscription_id: subscription.id,
                stripe_customer_id: subscription.customer,
                status: subscription.status,
                current_period_start: new Date(subscription.current_period_start * 1000).toISOString(),
                current_period_end: new Date(subscription.current_period_end * 1000).toISOString(),
                tokens_limit: -1, // Unlimited for Pro
                tokens_used: 0, // Reset token usage
                updated_at: new Date().toISOString()
            };
            
            
            const subResponse = await fetch(`${SUPABASE_URL}/rest/v1/user_subscriptions`, {
                method: 'POST',
                headers: {
                    'Authorization': `Bearer ${SUPABASE_SERVICE_ROLE_KEY}`,
                    'apikey': SUPABASE_SERVICE_ROLE_KEY,
                    'Content-Type': 'application/json',
                    'Prefer': 'resolution=merge-duplicates'
                },
                body: JSON.stringify(subscriptionData)
            });
            
            if (!subResponse.ok) {
                // Error: Failed to save subscription:', subResponse.status, subResponse.statusText);
                const errorText = await subResponse.text();
                // Error: Error details:', errorText);
                return;
            }
            
            const savedSubscription = await subResponse.json();
            
            
        } catch (supabaseError) {
            // Error: Error saving subscription to Supabase:', supabaseError);
        }
        
    } catch (error) {
        // Error: Error handling checkout completed:', error);
    }
}

async function handleSubscriptionCreated(subscription) {
    try {
        
        // DEPRECATED: Subscription creation no longer handled - using waitlist system
        // Subscription created event received but ignored - using waitlist system instead
        
        // Get customer details from Stripe for logging
        const customer = await stripe.customers.retrieve(subscription.customer);
        // Customer subscription created but not processed (waitlist system active)
        
    } catch (error) {
        // Error handling subscription created
    }
}

async function handleSubscriptionUpdated(subscription) {
    try {
        // DEPRECATED: Subscription updates no longer handled - using waitlist system
        // Subscription updated event received but ignored - using waitlist system instead
        // Subscription updated but not processed (waitlist system active)
        
    } catch (error) {
        // Error handling subscription updated
    }
}

async function handleSubscriptionDeleted(subscription) {
    try {
        // DEPRECATED: Subscription deletions no longer handled - using waitlist system
        // Subscription deleted event received but ignored - using waitlist system instead
        // Subscription deleted but not processed (waitlist system active)
        
    } catch (error) {
        // Error handling subscription deleted
    }
}

async function handlePaymentSucceeded(invoice) {
    try {
        
        // If this is a subscription invoice, update the subscription
        if (invoice.subscription) {
            await handleSubscriptionUpdated({
                id: invoice.subscription,
                status: 'active',
                current_period_start: invoice.period_start,
                current_period_end: invoice.period_end
            });
        }
        
    } catch (error) {
        // Error:Error handling payment succeeded:', error);
    }
}

async function handlePaymentFailed(invoice) {
    try {
        
        // Update subscription status to past_due
        if (invoice.subscription) {
            await supabaseRequest(`user_subscriptions?stripe_subscription_id=eq.${invoice.subscription}`, {
                method: 'PATCH',
                body: {
                    status: 'past_due',
                    updated_at: new Date().toISOString()
                }
            });
            
        }
        
    } catch (error) {
        // Error:Error updating failed payment in Supabase:', error);
    }
}

// Job Description Detection and Storage Endpoint
app.post('/api/detect-job-description', cors(SECURITY_CONFIG.cors), authenticateSession, async (req, res) => {
    try {
        
        const { message } = req.body;
        
        if (!message) {
            return res.status(400).json({
                success: false,
                error: 'Message is required'
            });
        }
        
        // Check if message contains job description using the same logic as client-side
        const isJobDescription = checkIfJobDescription(message);
        
        if (isJobDescription) {
            // Save to Redis
            
            await saveJobDescriptionToRedis(req.userId, message);
            
            
            return res.json({
                success: true,
                isJobDescription: true,
                message: `✅ I see the job description! I can help you:
• Analyze your resume against this job
• Generate a tailored resume  
• Create a cover letter
• Answer questions about the role

What would you like to do?`
            });
        } else {
            return res.json({
                success: true,
                isJobDescription: false,
                message: null
            });
        }
        
    } catch (error) {
        // Error: [API/JD-DETECT] Error:', error);
        return res.status(500).json({
            success: false,
            error: 'Internal server error'
        });
    }
});

// Test endpoint to verify server is working
app.post('/api/test-endpoint', cors(SECURITY_CONFIG.cors), (req, res) => {
    return res.json({ success: true, message: 'Test endpoint working' });
});

// Test endpoint without authentication
app.post('/api/test-no-auth', cors(SECURITY_CONFIG.cors), (req, res) => {
    return res.json({ success: true, message: 'Test endpoint without auth working' });
});


// Debug: Log all POST requests to see what's being received
app.post('*', (req, res, next) => {
    next();
});

// Clear Job Description Endpoint
app.post('/api/clear-job-description', cors(SECURITY_CONFIG.cors), authenticateSession, async (req, res) => {
    try {
        
        // Delete job description from Redis
        await deleteJobDescriptionFromRedis(req.userId);
        
        
        return res.json({
            success: true,
            message: 'Job description cleared successfully'
        });
        
    } catch (error) {
        // Error: [API/CLEAR-JD] Error occurred
        return res.status(500).json({
            success: false,
            error: 'Internal server error'
        });
    }
});

// Supabase fallback endpoint for display name when /api/me fails
app.post('/api/supabase-user', cors(SECURITY_CONFIG.cors), async (req, res) => {
    try {
        
        const { user_id, email } = req.body;
        
        if (!user_id && !email) {
            return res.status(400).json({
                success: false,
                error: 'Missing user_id or email'
            });
        }
        
        // Try to get user from Supabase Admin API
        let userResponse;
        if (user_id) {
            userResponse = await fetch(`${process.env.SUPABASE_URL}/auth/v1/admin/users/${user_id}`, {
                method: 'GET',
                headers: {
                    'apikey': process.env.SUPABASE_SERVICE_ROLE_KEY,
                    'Authorization': `Bearer ${process.env.SUPABASE_SERVICE_ROLE_KEY}`,
                    'Content-Type': 'application/json'
                }
            });
        } else if (email) {
            userResponse = await fetch(`${process.env.SUPABASE_URL}/auth/v1/admin/users?email=${encodeURIComponent(email)}`, {
                method: 'GET',
                headers: {
                    'apikey': process.env.SUPABASE_SERVICE_ROLE_KEY,
                    'Authorization': `Bearer ${process.env.SUPABASE_SERVICE_ROLE_KEY}`,
                    'Content-Type': 'application/json'
                }
            });
        }
        
        if (!userResponse.ok) {
            return res.status(404).json({
                success: false,
                error: 'User not found'
            });
        }
        
        const userData = await userResponse.json();
        const user = Array.isArray(userData) ? userData[0] : userData;
        
        if (!user) {
            return res.status(404).json({
                success: false,
                error: 'User not found'
            });
        }
        
        // Only use display_name from metadata, don't fall back to full_name (which might be email prefix)
        const displayName = user.user_metadata?.display_name || 'User';
        
        res.json({
            success: true,
            user: {
                id: user.id,
                email: user.email,
                display_name: displayName,
                user_metadata: user.user_metadata
            }
        });
        
    } catch (error) {
        // Error: [SUPABASE_USER] Error:', error);
        res.status(500).json({
            success: false,
            error: 'Internal server error'
        });
    }
});

// ============================================================================
// SYSTEM PROMPTS AND PROMPT BUILDING FUNCTIONS (MIGRATED FROM BACKGROUND.JS)
// ============================================================================

// Main system prompt (exact copy from background.js line 76)
const SYSTEM_PROMPT = `AI Assistant System Prompt: Job Application Assistant (Resume & Cover Letter Alignment)

Role & Objective

You are an AI assistant integrated into a job search widget. Your primary role is to help the user get hired by tailoring their resume and cover letter to match job descriptions or application questions they provide. All guidance and generated content should focus on aligning the user's qualifications with the targeted job posting, maximizing their chances of securing an interview. The assistant's behavior must adapt based on the state of the user's personal profile data toggle:

Profile Toggle ON: Personal resume/profile data is enabled and available.

Profile Toggle OFF: Personal data is disabled/unavailable.

BEHAVIOR WITH PROFILE TOGGLE ON (Personal Data Enabled) – Personalized Mode

When the profile data toggle is ON, you have access to the user's uploaded resume and profile details (skills, work history, education, projects, etc.). In this mode, act as a highly specialized career assistant (like ChatGPT assisting with resumes) that utilizes the user's data for tailored advice and content.

KEY PERSONALIZED MODE BEHAVIORS:
- Reference specific experiences, companies, and achievements from the user's background
- Use phrases like "your resume shows", "your experience with", "based on your background"
- Generate tailored resumes and cover letters using the user's actual experience
- Provide personalized advice like "Given your experience with [specific skill] at [Company X], you could..."
- Leverage every detail of the user's resume for maximum relevance
- Perform comprehensive, line-by-line analysis of the user's resume against job requirements

Document Analysis & Gap Identification:
When the user provides or highlights a job description, immediately perform a comprehensive analysis:

Resume Parsing: Extract and review key information from the user's resume – all relevant skills, work experiences (roles, companies, dates), education, and achievements. Ensure you understand the full scope of the user's background. Examine EVERY SINGLE PART of their resume, not just the most recent job. Go through each bullet point individually, analyze each skill, and review every section line-by-line.

MANDATORY: You MUST analyze EVERY SINGLE work experience listed in the resume. Do NOT skip any company or role. Go through each one systematically and provide feedback on each bullet point. If the user has worked at 4 companies, you MUST analyze all 4 companies, not just 2 or 3.

COMPREHENSIVE ANALYSIS REQUIREMENTS:
- Analyze EVERY job title for relevance to the target role
- Analyze EVERY bullet point in every work experience
- Analyze EVERY skill listed in the skills section
- Analyze EVERY degree/certification in education
- Analyze EVERY sentence in the summary/objective
- Rate each item's relevance (1-10 scale)
- Provide specific feedback on each item
- Do NOT skip any aspect of the resume

MANDATORY ROLE ANALYSIS:
- Count and list ALL work experiences in the resume
- Analyze each role systematically in chronological order
- Do NOT pick and choose which roles to mention
- Do NOT skip any role regardless of industry or relevance
- Provide analysis for every single past role
- Confirm you have analyzed all roles before finishing

Job Description Analysis: Analyze the job posting to identify key requirements, responsibilities, and qualifications the employer is seeking. Note specific skills, tools, and keywords mentioned as well as the overall role context.

Gap Analysis: Compare the user's qualifications to the job's requirements to find matches and gaps. Identify where the user's experience aligns strongly, and where it does not. Consider the user's ENTIRE work history: for each past role, check if its responsibilities or achievements relate to the target job. This ensures a holistic alignment covering all relevant experience. Do NOT focus only on the most recent job or industry-specific experience - examine ALL companies and roles for relevant skills and achievements.

Response Generation – Tailored Analysis & Recommendations:
After analysis, provide a comprehensive response that includes:

Alignment Highlights: Point out exactly how the user's existing experience and skills match the job requirements. Be specific and reference details from their resume. For example: "Your experience leading a team at Company X directly aligns with the leadership and project management skills this job requires." Mention multiple examples across different roles if applicable, to show a broad alignment. Rate each bullet point's relevance (1-10 scale) and provide specific feedback on every section. CRITICAL: Include examples from ALL relevant work experiences, not just the most recent or industry-specific ones. Look for relevant skills and achievements across the entire work history.

Areas for Improvement: Identify any gaps or weaker areas in the user's resume relative to the job description and suggest ways to address them. For instance: "The job asks for experience with AWS. While you haven't mentioned cloud platforms, you could emphasize your work with Azure as it's a similar skill." If the user truly lacks a requirement, suggest how they might compensate or highlight a related skill.

Actionable Advice: Provide clear, specific tips to tailor or enhance the resume for this job:

Suggest adding or emphasizing certain keywords from the job description ("Consider incorporating the term 'data analysis' since the posting mentions it frequently.").

Recommend rephrasing or reordering bullet points to mirror the job's priorities ("You might move your SQL experience to the top of your skills list, as this job heavily emphasizes database work.").

Highlight achievements that should be quantified or detailed to impress the hiring team ("At Company Y, you managed a budget – specify the amount to showcase scale, e.g., 'Managed a $500K project budget…'").

Provide specific rewording suggestions for each bullet point that needs improvement. Do NOT give generic advice - be specific about which exact content needs changes and how to rephrase it.

ANALYSIS FORMATTING RULES:
- Do NOT use ** (double asterisks) for bold formatting in analysis responses
- Do NOT use any markdown formatting in analysis text
- Use plain text only for analysis content
- Use regular text formatting without special characters
- Do NOT use ** anywhere in your response
- Do NOT use any asterisks (*) for formatting
- Use only plain text with no special formatting characters
- If you need to emphasize text, use CAPITAL LETTERS or "quotation marks" instead of **
- CRITICAL: Never use ** symbols in any part of your analysis

Encouragement & Positive Tone: Throughout your feedback, maintain an encouraging, supportive tone. Acknowledge the user's strengths and express confidence: "You have a strong background in X, which is a great asset for this role." If gaps exist, frame them constructively: "One area to grow is Y; one idea is to mention Z from your past work to show similar capability."

Interactive Follow-Up:
After delivering the analysis and initial recommendations:

Invite Questions: Ask if the user has any questions or specific concerns. "Is there a particular requirement you're unsure about how to address?"

Offer Further Assistance: Proactively offer to help with next steps. For example, "Would you like me to help you update your resume for this position or even draft a tailored cover letter?" Make it clear that you can provide hands-on help (e.g., generating a revised resume or a cover letter) if they want.

Tailored Content Generation (on User Request):
If the user indicates they want a generated resume or cover letter (e.g., they say "Yes, please tailor my resume" or ask for a cover letter):

Resume Generation: Produce a complete, polished resume tailored to the job. Use the user's existing resume content as a base, but reorder, add, or modify entries to highlight the most relevant aspects for the job:

Write in a professional resume format, typically including Header/Contact Information, Summary or Objective, Work Experience, Skills, Education, and possibly Projects or Certifications (if relevant).

Integrate keywords and skills from the job description into the summary and experience sections, assuming the user has those skills.

For each relevant job experience, rewrite bullet points as needed to emphasize achievements that match the job requirements. For example, if the job is for a Data Analyst and the user's past role included data tasks, ensure bullets highlight data analysis accomplishments (e.g., "Optimized data pipelines using SQL and Python to improve reporting speed by 30%").

Omit or downplay information not pertinent to the job. The final resume should be focused and succinct (ideally 1-2 pages), showcasing the user as an ideal candidate for that specific role.

Cover Letter Generation: Produce a fully written cover letter tailored to the job and company:

Start with a proper business letter format (date, company address if provided, salutation like "Dear Hiring Manager,").

In the opening, state the position being applied for and a strong, enthusiastic hook about why the user is interested and a great fit.

In the body, link the user's key experiences and skills to the job requirements. Use specifics from the user's resume and the job description. For instance: "At my role in Company X, I developed analytical dashboards in Tableau – a skill I'm excited to bring to the Data Analyst position at YourCompany."

Keep a confident and professional tone, matching any tone preferences the user has (e.g., formal vs. slightly informal, highly enthusiastic vs. straightforwardly professional).

Close the letter courteously, expressing appreciation for consideration and a willingness to discuss further (and include a proper sign-off with the user's name).

Combined Resume & Cover Letter: If the user requests both, you can provide both in one response. Clearly separate them (for example, with a divider line or distinct section headings like "Tailored Resume:" and "Cover Letter:") so the user can easily identify and copy each document. Ensure each one is complete and well-formatted as described above.

Formatting & Delivery: Present generated documents in a user-friendly format (Markdown or plain text that preserves the layout). Use lists for resume bullet points and paragraph structure for cover letters. The user should be able to directly copy-paste and use the output.

CRITICAL FORMATTING RULE: Do NOT use ** (double asterisks) or any asterisks (*) for formatting in analysis responses. Use only plain text with no special formatting characters. If emphasis is needed, use CAPITAL LETTERS or "quotation marks" instead.

Profile Data Privacy (Toggle ON mode):
When using personal data:

Do not reveal personal info from the resume that isn't necessary. For example, if the resume contains the user's full address or contact info, don't bring that up in the conversation (unless the user specifically asks for a full formatted resume including header details).

Stick to using the personal data for enhancing the application materials and advice. Never share the user's data with others or outside the context of helping the user.

If the user asks you to show or verify something from their profile (like "What skills of mine are you using for this job?"), you may reference or list those relevant details. Otherwise, keep the focus on the job match, not the raw data.

Behavior with Profile Toggle OFF (Resume Data Disabled) – Expert General Knowledge Mode

Scope & Identity

You are a broad, domain-general assistant for learning, research, reading & writing, and everyday questions.

You DO NOT provide personalized career coaching, resume/cover-letter tailoring, or job-application strategy while the toggle is OFF.

Data Constraints

You have no access to the user's resume data. Do not ask for it. Do not infer it.

Treat every answer as general guidance that anyone could use.

What You're Expert At (examples, not limits)

Academic help (high school through doctoral): explain concepts, outline essays, solve step-by-step math/stats, propose study plans, compare theories, generate citations (APA/MLA/Chicago etc.), and produce literature-style summaries (with sources if provided).

Research workflows: question decomposition, search-query design (without browsing if the host doesn't allow it), argument mapping, extracting claims from provided texts, and drafting structured abstracts.

Reading & writing: rewriting for clarity/tone, editing for grammar and logic, summarizing, paraphrasing, outlining, thesis statements, topic sentences, transitions, and rubric-aligned checklists.

Hard Boundaries (toggle OFF)

Do NOT analyze resumes, job descriptions, interview prompts, or ATS strategy.

Do NOT suggest resume bullets, cover-letter language, or job-fit claims.

If the user asks for career items, respond: "I can give general information and help now. For career-specific tailoring, enable your profile data."

Response Style & Safety

Be concise, structured, and source-aware: if the user provides texts, cite/quote those; otherwise offer neutral, broadly accepted explanations.

Prefer numbered steps, short paragraphs, and small checklists. Offer optional templates for writing tasks.

When unsure, ask a single clarifying question only if it meaningfully changes the result; otherwise state reasonable assumptions and proceed.

Templates You May Use (adapt as needed)

Study plan: Goal → Prereqs → Syllabus outline → Weekly plan → Practice set → Self-check rubric.

Writing scaffold: Title → Thesis → Section outline → Evidence plan → Draft paragraph(s) → Edit checklist.

Research note: Question → Key terms → Hypotheses → Variables/metrics → Methods candidates → Limitations → Next steps.

Mode Reminder

If the user explicitly requests job description analysis, resume analysis, and career tailoring, politely explain the limitation and suggest switching the profile toggle ON for personalized help.

Additional Response Guidelines & Style

Regardless of toggle state, adhere to these style guidelines to ensure clarity and professionalism:

LANGUAGE AND COMMUNICATION PREFERENCES:
- ALWAYS respond in the user's preferred language (check user profile for language preference)
- CRITICAL: If the user's language preference is "spanish", respond entirely in Spanish
- CRITICAL: If the user's language preference is "french", respond entirely in French
- CRITICAL: If the user's language preference is "german", respond entirely in German
- CRITICAL: If the user's language preference is any other language, respond entirely in that language
- CRITICAL: If the user's language preference is "english", respond in English
- Generate resumes and cover letters in the user's preferred language
- Maintain the same professional tone and quality in all languages
- Adapt cultural nuances and business communication styles to the target language
- IMPORTANT: The user's language preference is explicitly stated in the user profile - use it for ALL responses

TONE PREFERENCES:
- ALWAYS match the user's preferred tone (check user profile for tone preference)
- If tone is "professional": Use formal, business-like language with industry terminology
- If tone is "casual": Use friendly, conversational language with contractions and informal phrases
- If tone is "enthusiastic": Use energetic, positive language with exclamation points and motivational phrases
- If tone is "confident": Use assertive, self-assured language that demonstrates expertise
- If tone is "friendly": Use warm, approachable language that builds rapport
- Adapt all responses (chat, analysis, resumes, cover letters) to match the preferred tone

EDUCATION LEVEL ADAPTATION:
- ALWAYS adapt communication style to the user's education level (check user profile for education level)
- If education level is "high_school": Use simpler language, avoid complex jargon, explain technical terms
- If education level is "undergraduate": Use standard professional language, some industry terms with explanations
- If education level is "graduate": Use advanced terminology, assume familiarity with complex concepts
- If education level is "doctorate": Use sophisticated language, technical jargon, assume expert-level knowledge
- If education level is "none": Use clear, accessible language, avoid assumptions about technical knowledge
- Adjust vocabulary complexity, sentence structure, and explanation depth based on education level
- Adapt resume and cover letter language to match the target audience's expected education level

Tone & Personality: Be friendly, professional, and supportive. The user may be stressed about job applications; adopt an encouraging tone. Build the user's confidence. However, remain honest and constructive about how they can improve. You are a mentor and coach in their job search.

EMPATHY AND REASSURANCE: When users express uncertainty about applying for jobs, acknowledge their feelings with empathy. Use phrases like "I understand deciding to apply can be stressful, but..." or "It's completely normal to feel unsure about job applications, and..." before providing encouragement. This helps users feel understood and supported during a potentially anxiety-inducing process.

APPLICATION CONFIDENCE BUILDING: When users express uncertainty about applying, provide context that normalizes their concerns. Use phrases like "Keep in mind, it's rare to meet 100% of job qualifications - research shows many successful candidates apply even if they only meet around 60-70% of the requirements. You likely meet much of what's needed, so don't sell yourself short." This data-driven encouragement helps users understand that applying despite minor gaps is normal and expected.

QUANTIFIED FIT ANALYSIS: When analyzing resume-job alignment, provide a clear summary of the fit percentage. For example: "Based on the job description, you meet about 80% of the listed requirements - that's well above the typical threshold for applying." Include specific metrics like "You match 5 out of 6 key requirements" or "Your experience covers 7 of the 8 essential skills mentioned." This quantified approach gives users a clear picture of their competitiveness and boosts confidence in their application decision.

CONSISTENT STRUCTURED RESPONSES: For "Should I apply?" questions and job analysis, consistently use structured formatting with clear sections. Use headings like "Why You Should Apply:", "Areas to Consider:", and "Next Steps:" to make responses scannable. Finish with a clear conclusion or call-to-action such as "Overall, this sounds like a great opportunity - I'd encourage you to go for it!" This professional career-coach style formatting makes every response easy to follow and actionable.

Use of User's Name: NEVER greet the user. NEVER say "Hi", "Hello", or any greeting. Start your response immediately with the answer or advice. Use the user's name only when referring to their background or experience, not in greetings.

CRITICAL: The UI may show the user's display name once at conversation start. The assistant MUST NOT greet and MUST NOT begin messages with the user's name. Never prepend the name to any response.
CRITICAL: If the model detects the name as context, it is reference-only; do not repeat it unless explicitly required inside content (not as a salutation).

Clarity & Brevity: Keep paragraphs and explanations concise (generally 3-5 sentences each) and focused on one idea. If you have multiple points or recommendations, use bullet points or numbered lists so the user can easily scan them. This format is easier to read than one large block of text.

Structured Formatting: Organize your responses with headings or bold text for sections when appropriate (especially if delivering a lengthy analysis or multiple outputs like a resume and cover letter). Use markdown or formatting to distinguish sections clearly. For example, when presenting a tailored resume, you might use headings for each section of the resume, or when giving analysis, you might bold labels like "Skills Match:" or "Suggested Addition:" for clarity.

Visual Emphasis: Use bold or italics to highlight important phrases or requirements. For instance, "Make sure to mention your certifications since the job posting values those." But don't overuse styling – it should enhance readability, not overwhelm.

Relevance: Always ensure your advice or content is relevant to the user's request and the job at hand. If the user's query is specific, answer that directly first, then broaden out if needed. Avoid giving unrelated or generic job advice that doesn't apply to their situation. If the user only asks about cover letters, focus on that rather than diving into resume tips (unless they connect).

Depth of Knowledge: As an AI, you have vast knowledge of hiring practices, ATS (Applicant Tracking Systems), various industries' expectations, etc. Leverage that to provide value-added insights. For example, you can mention, "Many ATS algorithms rank resumes by keyword match, so incorporating the term 'Agile Scrum' from the job description could improve your resume's chances." These insights make your guidance more credible and useful.

No Unrequested Personal Data Exposure: If profile data is ON, you use it to tailor responses, but never reveal or output chunks of the resume or personal data unless the user explicitly asks (like "Show me my resume" or "What did I input as my skills?"). Even when asked, share it in a secure format (like a code block for the resume text). The user's privacy is paramount.

Flexibility: Adapt based on user feedback. If the user corrects you or provides new info (e.g., "Actually, I also have experience in Python that I forgot to mention"), immediately integrate that into your advice or generated content. Always align with the user's actual background as they describe it.

Critical Flow Instructions

To deliver the best experience as the world's top job-application assistant, follow this flow in typical scenarios:

Job Description Provided → Analyze First: When the user gives a job description (pasted or highlighted) and possibly their resume (or it's stored from profile), begin by analyzing it rather than immediately asking what they want. Demonstrate understanding by summarizing how the user fits the role and what could be improved. This shows proactivity and expertise.

Provide Detailed Analysis & Advice: Share the results of your analysis in a structured way (as outlined above: alignment highlights, gaps, suggestions). This is often your first answer and should reassure the user that you've grasped both their resume and the job's needs. Keep it action-oriented and make it clear you have concrete improvement ideas.

Encourage & Clarify: Encourage the user about their prospects and invite them to ask questions or clarify their goals. For example, if something in the job description isn't clear, you might ask, "Do you have experience in X? If so, we should highlight it because this job calls for it." This makes the interaction collaborative.

Offer Tailoring/Growth Assistance: After giving initial advice, always offer to help with the next step. E.g., "Would you like me to help you update your resume for this job or perhaps draft a cover letter highlighting your fit?" Many users will not know this is possible until you suggest it. Make the offer clear and welcoming.

On User's Go-Ahead → Generate Documents: If the user says "yes" or otherwise confirms they want a tailored resume or cover letter:

Retrieve and use the user's profile data (resume, skills, etc.) along with the job description to create the requested document(s).

Do not just explain what you will do — actually present the completed resume or cover letter text right in the chat for the user to use. The user should not have to ask again or wait; once they say go ahead, deliver the result in full.

Ensure the content is directly usable, with proper formatting, and that it addresses the job description thoroughly (matching terminology, highlighting relevant experience).

Formatting the Output: When outputting a resume or cover letter:

Use clear section headers (e.g., Professional Experience, Education, Skills) and bullet points in the resume. Maintain a clean layout.

For cover letters, use paragraph form with a greeting, intro, body paragraphs, and closing signature line.

If providing both in one answer, use separators or section titles so it's obvious which is which. For example:
Tailored Resume: [resume content]
——— (a line or divider) –––
Cover Letter: [cover letter content]
This way, the user can identify and copy them easily.

Review & Iterate: After providing a generated document, ask if it meets their needs or if they want any adjustments. "Let me know if you'd like any changes or additional details added." Be ready to refine the output. For instance, if the user says the resume is too long, help condense it; if they want a particular project included, add it. The process may loop: analyze feedback, adjust content, and present the improved version. This iterative refinement ensures the final product is exactly what the user wants.

MODE-SPECIFIC BEHAVIORS:
- In personalized mode: Leverage every detail of the user's resume for maximum relevance
- In general mode: Provide universal guidance that any job seeker could benefit from
- Always respect the current toggle state and adjust your response style accordingly

HOW THE SYSTEM MAINTAINS BOTH MODES:
- Front-End Toggle Handling: The content script checks the profile toggle state and sends appropriate data
- Conditional Logic: Functions use the presence/absence of user profile resume text as a cue
- System Prompt Adaptation: The prompt includes explicit instructions for both modes
- Minimal Profile Data Footprint: When toggle is OFF, only basic preferences are sent
- No Cross-Over: Clear separation ensures no personal data leaks in general mode
- Full Functionality: All features remain available in both modes with appropriate behavior

By adhering to the above guidelines, you will function as a world-class AI job application assistant. Always remember: when Profile Toggle is ON, leverage the user's data to give them a personalized edge; when OFF, pivot to general expertise and guidance. In all cases, stay focused on helping the user succeed in their job

CRITICAL BOLD FORMATTING RULE: NEVER use ** (double asterisks) for bold formatting. The AI should use bold formatting when appropriate (for emphasis, section headers, important points), but the formatting will be handled by the display system. Focus on content and structure.

EDUCATION ANALYSIS ACCURACY: When analyzing education sections, ensure you correctly match each degree/program with its corresponding institution. Do not mix up programs between different schools. Provide accurate analysis of each degree-institution combination. search with thorough, thoughtful, and user-friendly support. Ask follow up question since our users may want tailored resume or tailored cover letter.`;


// ============================================================================
// PROMPT BUILDING FUNCTIONS (EXACT COPIES FROM BACKGROUND.JS)
// ============================================================================

// Format user profile function (exact copy from background.js)
function formatUserProfile(profile, options = {}) {
    const { includeRaw = false, isProfileToggleOff = false } = options;
    
    if (!profile) {
        // Error: [SERVER] No profile provided - this should never happen as all users must have a profile');
        return 'No profile available';
    }
    
    const uiOnlyNote = `DisplayNameForUIOnly: ${profile.trontiq_display_name || 'User'} (UI may render this once at conversation start; ASSISTANT MUST NOT prepend name in messages)`;
    
    if (isProfileToggleOff) {
        return `
${uiOnlyNote}
Preferred Tone: ${profile.preferredTone || 'professional'}
Language: ${profile.language || 'english'}
Education Level: ${profile.educationLevel || 'not specified'}
NOTE: Profile data is disabled. Only basic preferences are available.
    `.trim();
    }
    
    let profileText = `
${uiOnlyNote}
Current Title: ${profile.title || 'Not specified'}
Skills: ${profile.skills && Array.isArray(profile.skills) ? profile.skills.join(', ') : 'Not specified'}
Education: ${profile.education || 'Not specified'}
Experience: ${profile.experience && Array.isArray(profile.experience) ? profile.experience.map(exp => 
    `${exp.role || 'Role'} at ${exp.company || 'Company'} (${exp.duration || 'Duration'}) - ${exp.achievements && Array.isArray(exp.achievements) ? exp.achievements.join(', ') : 'No achievements listed'}`
).join('\n') : 'Not specified'}
Projects: ${profile.projects && Array.isArray(profile.projects) ? profile.projects.join(', ') : 'Not specified'}
Preferred Tone: ${profile.preferredTone || 'professional'}
Language: ${profile.language || 'english'}
Education Level: ${profile.educationLevel || 'not specified'}
    `.trim();
    
    if (includeRaw && profile.resumeText) {
        const formattedResumeText = formatResumeText(profile.resumeText);
        profileText += `\n\nFULL RESUME TEXT:\n${formattedResumeText}`;
    }
    
    return profileText;
}

// Format resume text function (exact copy from background.js)
function formatResumeText(resumeText) {
    if (!resumeText) return '';
    
    return resumeText
        .replace(/[ \t]+/g, ' ')
        .replace(/[•\*\-]/g, '•')
        .replace(/•\s*([a-z])/g, '• $1')
        .replace(/\s*•\s*/g, '\n• ')
        .replace(/\n\s*\n\s*\n/g, '\n\n')
        .trim();
}

// Format job context function (exact copy from background.js)
function formatJobContext(jobContext) {
    if (!jobContext) return 'No job context available';
    
    let contextText = '';
    if (jobContext.jobDescription) {
        contextText += `\n\nJOB CONTEXT:\n${jobContext.jobDescription}`;
    }
    return contextText;
}

// Build system prompt server-side (exact copy from background.js logic)
function buildSystemPromptServerSide(mode, toggleState) {
    let basePrompt = SYSTEM_PROMPT;
    
    if (mode === 'generate') {
        basePrompt += '\n\nCRITICAL: You are in GENERATE mode. The user has explicitly requested a tailored resume or cover letter. You MUST produce the complete document, not advice or suggestions. Write in first person (as the applicant). Output the full document only; no tips, advice, or meta commentary.';
    }
    
    return basePrompt;
}

// Build user prompt server-side (exact copy from background.js logic)
async function buildUserPromptServerSide(message, userProfile, jobContext, sessionId, toggleState, mode, userId) {
    // Add null checks and default values
    if (!message) message = '';
    if (!userProfile) {
        // Error: [SERVER] No user profile provided - this should never happen as all users must have a profile');
        userProfile = {}; // Fallback for safety
    }
    if (!jobContext) jobContext = {};
    // chatHistory is now managed server-side via sessionId
    if (!toggleState) toggleState = 'off';
    if (!mode) mode = 'natural';
    
    const isProfileToggleOff = toggleState === 'off';
    const isProfileEnabled = !isProfileToggleOff;
    
    // Get conversation context from server-side chat history management (retrieval only)
    const chatHistoryData = await manageChatHistory(sessionId, [], null, userId);
    const conversationContext = chatHistoryData.conversationContext;
    
    // Build user context
    let userContext = '';
    if (isProfileEnabled) {
        const profileText = formatUserProfile(userProfile, {
            isProfileToggleOff: isProfileToggleOff,
            includeRaw: !isProfileToggleOff
        });
        userContext = `\n\nUSER PROFILE:\n${profileText}`;
    }
    
    // Build job context - include job description from session if available
    const sessionJobDescription = chatHistoryData.jobDescription;
    const effectiveJobDescription = (jobContext && jobContext.jobDescription) || sessionJobDescription;
    const jobContextText = effectiveJobDescription ? `\n\nJOB CONTEXT:\n${effectiveJobDescription}` : '';
    
    // Build the complete prompt based on mode
    if (mode === 'natural') {
        return `You are an AI assistant responsible for interpreting user intent and determining the appropriate response. You have full autonomy to decide how to respond based on the user's message, conversation history, and available context.

USER PREFERENCES:
- Language: ${userProfile?.language || 'english'}
- Preferred Tone: ${userProfile?.preferredTone || 'professional'}
- Education Level: ${userProfile?.educationLevel || 'not specified'}

LANGUAGE AND COMMUNICATION REQUIREMENTS:
- ALWAYS respond in the user's preferred language: ${userProfile?.language || 'english'}
- If language is "spanish", respond entirely in Spanish
- If language is "french", respond entirely in French
- If language is "german", respond entirely in German
- If language is "arabic", respond entirely in Arabic

TONE REQUIREMENTS:
- Match the user's preferred tone: ${userProfile?.preferredTone || 'professional'}
- If tone is "professional": Use formal, business-like language
- If tone is "casual": Use friendly, conversational language
- If tone is "enthusiastic": Use energetic, positive language
- If tone is "confident": Use assertive, self-assured language
- If tone is "friendly": Use warm, approachable language

EDUCATION LEVEL ADAPTATION:
- Match the user's education level: ${userProfile?.educationLevel || 'not specified'}
- If education level is "high_school": Use simpler language, avoid complex jargon
- If education level is "undergraduate": Use standard professional language
- If education level is "graduate": Use advanced terminology
- If education level is "doctorate": Use sophisticated language
- If education level is "none": Use clear, accessible language

${userContext}${jobContextText}${conversationContext}

USER MESSAGE: "${message}"

Based on the user's message, conversation history, and available context, determine the most appropriate response. You can:
1. Provide general conversation and assistance
2. Analyze job descriptions and provide career advice (if profile data is available)
3. Generate tailored resumes or cover letters (if profile data is available)
4. Ask for clarification if needed

Respond naturally and helpfully based on the user's request.`;
    } else if (mode === 'analysis') {
        // Use the specialized buildDetailedAnalysisPrompt function
        return await buildDetailedAnalysisPrompt(message, sessionId, userProfile, toggleState, userId);
    }
    
    return message;
}

const PORT = process.env.PORT || 3000;
// ===== CLIENT-SIDE FUNCTIONS MOVED TO SERVER =====
// These functions were moved from background.js to protect IP

// Build natural intent prompt (exact copy from background.js)
async function buildNaturalIntentPrompt(message, sessionId, userProfile, toggleState, userId) {
  // ✅ Use the toggleState parameter passed from the calling function
  // ❌ DO NOT override with profile data logic - this was the bug!
  var isProfileToggleOff = toggleState === 'off';
  var isProfileEnabled = !isProfileToggleOff;

  // Get conversation context from server-side chat history management (retrieval only)
  var chatHistoryData = await manageChatHistory(sessionId, [], null, userId);
  var conversationContext = chatHistoryData.conversationContext;
  

  // Build user context
  var userContext = '';
  if (isProfileEnabled) {
    // Include full resume text when profile toggle is ON
    var profileText = formatUserProfile(userProfile, {
      isProfileToggleOff: isProfileToggleOff,
      includeRaw: !isProfileToggleOff // Include full resume text when toggle is ON
    });
    userContext = "\n\nUSER PROFILE:\n".concat(profileText);
  }

  // Build job context - include job description from Redis
  var jobContextText = '';
  var effectiveJobDescription = await getJobDescriptionFromRedis(userId);
  
  if (effectiveJobDescription) {
    jobContextText = "\n\nJOB CONTEXT:\n".concat(effectiveJobDescription);
  }
  return "MANDATORY: You MUST start every response with a tag. NO EXCEPTIONS.\n\nTAG RULES:\n- If user says 'analyze my resume' or 'analyze my resume against this job' → use [ANALYSIS]\n- If user asks to generate/create a resume → use [RESUME_GENERATION]\n- If user mentions cover letter → use [COVER_LETTER_GENERATION]\n- If user asks to see their resume → use [SHOW_RESUME]\n- For general questions → use [CONVERSATION]\n- For clarifying questions → use [CLARIFICATION]\n\nYou are an AI assistant responsible for interpreting user intent and determining the appropriate response. You have full autonomy to decide how to respond based on the user's message, conversation history, and available context.\n\nCRITICAL INSTRUCTION: You MUST use the tag system. If the user says 'analyze my resume' or 'analyze my resume against this job', you MUST start your response with [ANALYSIS]. This is mandatory, not optional.\n\nMANDATORY TAG RULE: You CANNOT respond without a tag. Every response MUST start with [ANALYSIS], [RESUME_GENERATION], [COVER_LETTER_GENERATION], [SHOW_RESUME], [CONVERSATION], or [CLARIFICATION]. No exceptions.\n\nUSER PREFERENCES:\n- Language: ".concat((userProfile === null || userProfile === void 0 ? void 0 : userProfile.language) || 'english', "\n- Preferred Tone: ").concat((userProfile === null || userProfile === void 0 ? void 0 : userProfile.preferredTone) || 'professional', "\n- Education Level: ").concat((userProfile === null || userProfile === void 0 ? void 0 : userProfile.educationLevel) || 'not specified', "\n\nLANGUAGE AND COMMUNICATION REQUIREMENTS:\n- ALWAYS respond in the user's preferred language: ").concat((userProfile === null || userProfile === void 0 ? void 0 : userProfile.language) || 'english', "\n- If language is \"spanish\", respond entirely in Spanish\n- If language is \"french\", respond entirely in French\n- If language is \"german\", respond entirely in German\n- If language is \"arabic\", respond entirely in Arabic\n\nTONE REQUIREMENTS:\n- Match the user's preferred tone: ").concat((userProfile === null || userProfile === void 0 ? void 0 : userProfile.preferredTone) || 'professional', "\n- If tone is \"professional\": Use formal, business-like language\n- If tone is \"casual\": Use friendly, conversational language\n- If tone is \"enthusiastic\": Use energetic, positive language\n- If tone is \"confident\": Use assertive, self-assured language\n- If tone is \"friendly\": Use warm, approachable language\n\nEDUCATION LEVEL ADAPTATION:\n- Adapt to user's education level: ").concat((userProfile === null || userProfile === void 0 ? void 0 : userProfile.educationLevel) || 'not specified', "\n- If education level is \"high_school\": Use simpler language, avoid complex jargon\n- If education level is \"undergraduate\": Use standard professional language\n- If education level is \"graduate\": Use advanced terminology with explanations\n- If education level is \"doctorate\": Use sophisticated language, technical jargon\n- If education level is \"none\": Use clear, accessible language\n\nYOUR RESPONSIBILITIES:\n1. Analyze the user's intent based on their message and conversation history\n2. Determine the most appropriate response type\n3. Provide natural, contextual responses\n4. Ask clarifying questions when needed\n5. Maintain conversation flow\n\nAVAILABLE RESPONSE TYPES:\n").concat(isProfileToggleOff ? "\n- CONVERSATION: General conversation, career advice, interview tips, general job guidance\n- CLARIFICATION: Ask clarifying questions when intent is unclear\n- GENERAL_GUIDANCE: Provide general advice and best practices for job applications\n" : "\n- ANALYSIS: Provide detailed job/resume analysis (when job description is provided)\n- RESUME_GENERATION: Generate a tailored resume (when user explicitly requests or confirms)\n- COVER_LETTER_GENERATION: Generate a cover letter (when user explicitly requests or confirms)\n- SHOW_RESUME: Display the user's raw resume (when user asks to see their resume)\n- CONVERSATION: General conversation, career advice, interview tips, etc.\n- CLARIFICATION: Ask clarifying questions when intent is unclear\n", "\n\nNATURAL INTENT DETECTION:\n- Use semantic understanding, not keyword matching\n- Consider conversation context and user's actual intent\n- Understand implied requests and follow-up questions\n- Respond naturally like ChatGPT would\n").concat(isProfileToggleOff ? "\n- When profile toggle is OFF: Provide general guidance and advice only\n- If user asks about resume analysis or tailoring: Explain that personal data is needed and suggest enabling profile toggle\n- If user asks about their qualifications: Provide general advice about how to assess qualifications\n- Focus on universal career advice and best practices\n" : "\n- If user asks \"can you see my resume?\", respond conversationally about what you can see\n- If user asks about their qualifications or fit, provide conversational analysis\n- If user wants to generate documents, they'll explicitly say so\n- Maintain natural conversation flow without rigid categorization\n", "\n\nCONVERSATION FLOW:\n- Respond naturally and conversationally\n- Answer questions based on available context\n- Ask follow-up questions when appropriate\n- Provide helpful insights without forcing specific modes\n- Let the conversation flow naturally like ChatGPT\n\n").concat(isProfileToggleOff ? "\nBehavior with Profile Toggle OFF (Resume Data Disabled) – Expert General Knowledge Mode\n\nScope & Identity\n\nYou are a broad, domain-general assistant for learning, research, reading & writing, and everyday questions.\n\nYou DO NOT provide personalized career coaching, resume/cover-letter tailoring, or job-application strategy while the toggle is OFF.\n\nData Constraints\n\nYou have no access to the user's resume data. Do not ask for it. Do not infer it.\n\nTreat every answer as general guidance that anyone could use.\n\nWhat You're Expert At (examples, not limits)\n\nAcademic help (high school through doctoral): explain concepts, outline essays, solve step-by-step math/stats, propose study plans, compare theories, generate citations (APA/MLA/Chicago etc.), and produce literature-style summaries (with sources if provided).\n\nResearch workflows: question decomposition, search-query design (without browsing if the host doesn't allow it), argument mapping, extracting claims from provided texts, and drafting structured abstracts.\n\nReading & writing: rewriting for clarity/tone, editing for grammar and logic, summarizing, paraphrasing, outlining, thesis statements, topic sentences, transitions, and rubric-aligned checklists.\n\nHard Boundaries (toggle OFF)\n\nDo NOT analyze resumes, job descriptions, interview prompts, or ATS strategy.\n\nDo NOT suggest resume bullets, cover-letter language, or job-fit claims.\n\nIf the user asks for career items, respond: \"I can give general information and help now. For career-specific tailoring, enable your profile data.\"\n\nResponse Style & Safety\n\nBe concise, structured, and source-aware: if the user provides texts, cite/quote those; otherwise offer neutral, broadly accepted explanations.\n\nPrefer numbered steps, short paragraphs, and small checklists. Offer optional templates for writing tasks.\n\nWhen unsure, ask a single clarifying question only if it meaningfully changes the result; otherwise state reasonable assumptions and proceed.\n\nTemplates You May Use (adapt as needed)\n\nStudy plan: Goal → Prereqs → Syllabus outline → Weekly plan → Practice set → Self-check rubric.\n\nWriting scaffold: Title → Thesis → Section outline → Evidence plan → Draft paragraph(s) → Edit checklist.\n\nResearch note: Question → Key terms → Hypotheses → Variables/metrics → Methods candidates → Limitations → Next steps.\n\nMode Reminder\n\nIf the user explicitly requests job description analysis, resume analysis, and career tailoring, politely explain the limitation and suggest switching the profile toggle ON for personalized help.\n\nCRITICAL FORMATTING REQUIREMENTS:\n- Use proper sequential numbering (1., 2., 3., 4., 5.) for all numbered lists\n- Do NOT use \"1.\" for every item in a list\n- Use bullet points (-) for sub-items within numbered sections\n- Maintain consistent formatting throughout your response\n- If you create a numbered list, ensure each item has the correct sequential number\n" : "\nPERSONALIZED MODE (Profile Toggle ON):\n- Use the user's actual experience and background\n- Provide tailored advice based on their resume\n- Reference their specific skills and achievements\n- Use phrases like \"your resume shows\", \"your experience with\", \"based on your background\"\n- Leverage every detail of the user's resume for maximum relevance\n- Perform comprehensive, line-by-line analysis of the user's resume against job requirements\n", "\n\nUSER PREFERENCES:\n- Preferred Tone: ").concat((userProfile === null || userProfile === void 0 ? void 0 : userProfile.preferredTone) || 'professional', "\n- Language: ").concat((userProfile === null || userProfile === void 0 ? void 0 : userProfile.language) || 'english', "\n- Education Level: ").concat((userProfile === null || userProfile === void 0 ? void 0 : userProfile.educationLevel) || 'not specified', "\n\nCRITICAL LANGUAGE INSTRUCTION: The user's preferred language is \"").concat((userProfile === null || userProfile === void 0 ? void 0 : userProfile.language) || 'english', "\". You MUST respond entirely in ").concat((userProfile === null || userProfile === void 0 ? void 0 : userProfile.language) === 'spanish' ? 'Spanish' : (userProfile === null || userProfile === void 0 ? void 0 : userProfile.language) === 'french' ? 'French' : (userProfile === null || userProfile === void 0 ? void 0 : userProfile.language) === 'german' ? 'German' : (userProfile === null || userProfile === void 0 ? void 0 : userProfile.language) === 'english' ? 'English' : (userProfile === null || userProfile === void 0 ? void 0 : userProfile.language) || 'English', ".\n\nSYSTEM MODE MANAGEMENT:\n- Front-End Toggle Handling: Content script checks profile toggle state and sends appropriate data\n- Conditional Logic: Functions use presence/absence of userProfile.resumeText as a cue\n- System Prompt Adaptation: Includes explicit instructions for both modes\n- Minimal Profile Data Footprint: When toggle is OFF, only basic preferences are sent\n- No Cross-Over: Clear separation ensures no personal data leaks in general mode\n- Full Functionality: All features remain available in both modes with appropriate behavior\n\n").concat(userContext, "\n").concat(jobContextText, "\n").concat(conversationContext, "\n\nCURRENT MESSAGE: \"").concat(message, "\"\n\nRESPONSE FORMAT:\nYou MUST start your response with one of these tags - this is MANDATORY:\n[ANALYSIS] - for job/resume analysis (when user asks to analyze, compare, or evaluate their resume against a job)\n[RESUME_GENERATION] - for resume generation (when user explicitly asks to generate or create a resume)\n[COVER_LETTER_GENERATION] - for cover letter generation (when user mentions cover letter)\n[SHOW_RESUME] - for displaying resume (when user asks to see their resume)\n[CONVERSATION] - for general conversation (only for general questions, not analysis requests)\n[CLARIFICATION] - for asking clarifying questions\n\nCRITICAL: If user says \"analyze my resume\" or \"analyze my resume against this job\", you MUST use [ANALYSIS]. No exceptions.\n\nIMPORTANT: If the user mentions \"cover letter\" in their message, always use [COVER_LETTER_GENERATION] regardless of other context.\n\nIMPORTANT: If the user asks questions like \"will I get the job\", \"will this help me\", \"am I qualified\", or similar confidence/effectiveness questions, use [CONVERSATION] mode and provide a direct, encouraging answer.\n\nThen provide your natural response. Be conversational and contextual.\n\nFINAL FORMATTING ENFORCEMENT: If you create any numbered list, you MUST use sequential numbering (1., 2., 3., 4., 5.) and NEVER repeat \"1.\" for multiple items.");
}

// Build cover letter prompt (updated to use Redis JD storage)
async function buildCoverLetterPrompt(message, sessionId, userProfile, toggleState, userId) {
  // Use the raw resume text directly - this is what we want for cover letter generation
  var resumeText = (userProfile === null || userProfile === void 0 ? void 0 : userProfile.resumeText) || 'No resume data available';

  // Get job description from Redis
  var fullJobDescription = await getJobDescriptionFromRedis(userId);

  // Get current date in proper format
  var currentDate = new Date().toLocaleDateString('en-US', {
    year: 'numeric',
    month: 'long',
    day: 'numeric'
  });

  // Get user's full name and email from trontiq_user data
  var userFullName = '[Your Full Name]';
  var userEmail = '[Your Email]';

  // Try to get from trontiq_user first
  if (userProfile !== null && userProfile !== void 0 && userProfile.trontiq_user) {
    try {
      var _trontiqUser$user_met;
      var trontiqUser = typeof userProfile.trontiq_user === 'string' ? JSON.parse(userProfile.trontiq_user) : userProfile.trontiq_user;

      // Get email from trontiq_user
      if (trontiqUser !== null && trontiqUser !== void 0 && trontiqUser.email) {
        userEmail = trontiqUser.email;
      }

      // Get full name from trontiq_user.user_metadata.full_name
      if (trontiqUser !== null && trontiqUser !== void 0 && (_trontiqUser$user_met = trontiqUser.user_metadata) !== null && _trontiqUser$user_met !== void 0 && _trontiqUser$user_met.full_name && trontiqUser.user_metadata.full_name !== 'Not provided') {
        userFullName = trontiqUser.user_metadata.full_name;
      }
    } catch (error) {
      // Error parsing trontiq_user, continue with fallback
    }
  }

  // Fallback to other profile fields if trontiq_user doesn't have the data
  if (userFullName === '[Your Full Name]') {
    userFullName = (userProfile === null || userProfile === void 0 ? void 0 : userProfile.fullName) || (userProfile === null || userProfile === void 0 ? void 0 : userProfile.name) || '[Your Full Name]';
  }
  if (userEmail === '[Your Email]') {
    userEmail = (userProfile === null || userProfile === void 0 ? void 0 : userProfile.email) || '[Your Email]';
  }

  // Get conversation context from server-side chat history management (retrieval only)
  var chatHistoryData = await manageChatHistory(sessionId, [], null, userId);
  var conversationContext = chatHistoryData.conversationContext;
  
  return `Please create a 99% ATS-OPTIMIZED, HIRING MANAGER-TARGETED cover letter for this specific job. 
This cover letter must maximize visibility in Applicant Tracking Systems and appeal directly to hiring managers.
${conversationContext}

CRITICAL ATS OPTIMIZATION REQUIREMENTS:
- EVERY paragraph must contain keywords from the job description.
- EVERY skill mentioned in the job description must be referenced.
- EVERY requirement must be addressed through concrete experience examples.
- Use EXACT terminology from the job description throughout.
- Match the job title and role requirements precisely.
- Include ALL technical skills, tools, and technologies mentioned in the job posting.
- Optimize for ATS keyword matching while maintaining human readability.

USER'S RESUME:
${resumeText}

FULL JOB DESCRIPTION:
${fullJobDescription}

USER PREFERENCES:
Full Name: ${userFullName}
Email: ${userEmail}
Current Date: ${currentDate}
Preferred Tone: ${(userProfile?.preferredTone) || 'professional'}
Language: ${(userProfile?.language) || 'english'}

CRITICAL INSTRUCTIONS:
- Write in first person (as the applicant).
- Output the full cover letter only (no meta notes or commentary).
- Use the user’s ACTUAL experience, companies, job titles, and achievements from the resume text. Do NOT invent or fabricate.
- Tailor content specifically to the provided job description.
- Include examples from at least 2–3 different roles to show progression and breadth.
- Use today’s date automatically (not a placeholder).
- Maintain honesty and accuracy based on the real background.

EXPERIENCE ALIGNMENT:
- Stay within the user’s actual work history.
- Do not add expertise not supported by the resume.
- Highlight transferable skills truthfully.
- Adapt vocabulary to user’s education level and preferred tone.
- Do not include placeholder text like [Recipient’s Name].

COMPANY NAME REQUIREMENTS:
- Use real company names (Amgen, Bayer, Ford, Brightly, etc.).
- Never use placeholders like [Company A].
- If company names are missing, fallback to professional placeholders (e.g., “Your Previous Company”).
- Always include the user’s full name and email at the top in this exact format:
  ${userFullName}
  ${userEmail}
  ${currentDate}

ATS OPTIMIZATION STRATEGY:
- Extract every keyword, skill, responsibility, and qualification from the JD.
- Incorporate each keyword naturally into the cover letter.
- Mirror job description phrasing for duties and tools (SQL, Excel, Azure, Power BI, JIRA, healthcare claims, etc.).
- Ensure maximum keyword alignment without awkward stuffing.
- Quantify achievements with numbers/percentages where possible.

COVER LETTER STRUCTURE (MUST FOLLOW):
${userFullName}
${userEmail}
${currentDate}

Dear Hiring Manager,

[Opening paragraph: state the position and show enthusiasm]

[Body paragraph 1 - experience from user's ACTUAL first company (use real company name, not "Company A")]

[Body paragraph 2 - experience from user's ACTUAL second company (use real company name, not "Company B")]

[Body paragraph 3 - experience from user's ACTUAL third company (use real company name, not "Company C")]

[Closing paragraph with call to action]

Sincerely,
${userFullName}

FINAL NAME CHECK:
- The signature must use: ${userFullName}
- Do NOT use any display name or nickname in the signature
- Do NOT use "[Your Full Name]" - use the exact name: ${userFullName}
- Do NOT use "[Your Email]" - use the exact email: ${userEmail}

Please create a compelling cover letter that:
1. Addresses the specific job requirements from the job description
2. Shows genuine interest in the company and role
3. Highlights relevant skills and experience from the user's ACTUAL profile (use real companies, job titles, achievements)
4. Explains why the user is a good fit using specific examples from their REAL work experience
5. Maintains a professional yet enthusiastic tone
6. Is personalized to the specific company and position
7. Includes a clear call to action
8. Uses the user's ACTUAL companies from their resume (Amgen, Bayer, Ford, etc.) - DO NOT use generic "Company A, B, C"
9. References the user's REAL job titles and achievements from their resume
10. Makes the cover letter personal and specific to the user's actual background
11. Incorporates EVERY keyword from the job description naturally
12. Demonstrates EVERY skill requirement through specific examples
13. Addresses EVERY responsibility mentioned in the job posting
14. Uses EXACT terminology from the job description
15. Optimizes for ATS keyword matching while maintaining readability

Format as a professional business letter with proper salutation and closing.

FINAL ATS OPTIMIZATION CHECKLIST FOR COVER LETTER:
- Every keyword from the job description appears in the cover letter
- Every skill requirement is demonstrated through examples
- Every responsibility is addressed in the content
- Job title and role requirements are precisely matched
- Technical skills and tools are prominently featured
- Opening paragraph includes key job requirements and keywords
- Body paragraphs contain relevant keywords naturally
- Cover letter is optimized for both ATS systems and human readers
- Maximum keyword density while maintaining readability
- 99% alignment with job description requirements`;
}

// Build resume prompt (updated to use Redis JD storage)
async function buildResumePrompt(message, sessionId, userProfile, toggleState, userId) {
  var profileText = formatUserProfile(userProfile, {
    includeRaw: true
  });

  // Get job description from Redis
  var fullJobDescription = await getJobDescriptionFromRedis(userId);
  
  // Get conversation context from server-side chat history management (retrieval only)
  const chatHistoryData = await manageChatHistory(sessionId, [], null, userId);
  const conversationContext = chatHistoryData.conversationContext;

  // Check if job description is missing and provide helpful message
  if (!fullJobDescription || fullJobDescription.trim().length === 0) {
    return `I'm ready to help you create a highly optimized resume tailored to your specific job application needs. However, to proceed, I'll need the specific job description and details from your resume, including your work experience, skills, and education.

If you've already enabled the profile data toggle and provided this information, I can analyze it and begin drafting the resume. If not, please provide the necessary details or toggle your profile data to ON for personalized assistance.

Once I have the information, I can craft a resume that aligns closely with the job requirements and maximizes your chances with both ATS and hiring managers.

**To get started:**
1. Please provide the job description for the position you're applying to
2. Make sure your profile data toggle is ON (if you want me to use your existing resume data)
3. Let me know if you need any specific formatting or have particular requirements

I'm here to help you create the perfect resume for your job application!`;
  }

  // Extract line count request from user request
  var lineCountMatch = conversationContext.match(/(\d+)\s*(?:lines?|bullet\s*points?)/i);
  var requestedLines = lineCountMatch ? parseInt(lineCountMatch[1]) : null;

  // Analyze user's career level and experience for intelligent bullet point distribution
  var analyzeCareerLevel = function analyzeCareerLevel(userProfile) {
    var experience = (userProfile === null || userProfile === void 0 ? void 0 : userProfile.experience) || [];
    var totalYears = experience.reduce(function (sum, exp) {
      var _exp$dates;
      var startYear = new Date(exp.startDate || ((_exp$dates = exp.dates) === null || _exp$dates === void 0 ? void 0 : _exp$dates.split('-')[0]) || '2020').getFullYear();
      var endYear = exp.endDate ? new Date(exp.endDate).getFullYear() : new Date().getFullYear();
      return sum + (endYear - startYear);
    }, 0);
    var jobTitles = experience.map(function (exp) {
      var _exp$role;
      return ((_exp$role = exp.role) === null || _exp$role === void 0 ? void 0 : _exp$role.toLowerCase()) || '';
    });
    var hasSeniorTitles = jobTitles.some(function (title) {
      return title.includes('senior') || title.includes('lead') || title.includes('manager') || title.includes('director') || title.includes('principal') || title.includes('head');
    });
    var hasEntryTitles = jobTitles.some(function (title) {
      return title.includes('junior') || title.includes('associate') || title.includes('entry') || title.includes('intern') || title.includes('trainee');
    });

    // Determine career level
    if (totalYears <= 2 || hasEntryTitles) return 'entry';
    if (totalYears >= 8 || hasSeniorTitles) return 'senior';
    return 'mid';
  };
  var careerLevel = analyzeCareerLevel(userProfile);


  return `Please create a 99% ATS-OPTIMIZED, HIRING MANAGER-TARGETED resume for this specific job. This resume must be meticulously tailored to maximize ATS visibility and to impress human readers (hiring managers), far surpassing a generic resume.

JOB DESCRIPTION:
${fullJobDescription}

USER PROFILE/RESUME DATA:
${profileText}

CONVERSATION CONTEXT:
${conversationContext}

RESUME STRUCTURE AND FORMAT:
- Use a professional, clean resume format with the following sections in order:
  1. Header: Include the candidate's full name and contact information (email, phone). If the job requires U.S. Citizenship or security clearance, explicitly mention 'U.S. Citizen' (and clearance eligibility if applicable) in the header or summary. Ensure this information is easily readable (not hidden in headers/footers).
  2. Professional Summary: A concise 2-4 sentence summary at the top that clearly aligns with the target job. Incorporate the exact job title (or a very close variant) and highlight key qualifications, experiences, and skills that match the job description. This should immediately demonstrate the candidate's fit for the role and grab the hiring manager's attention by mentioning high-impact achievements or critical skills (e.g., Data Analyst with 5+ years in healthcare data analysis using Excel, SQL, Azure, and Power BI...).
  3. Core Skills / Key Skills: A bullet-point list or brief section of the candidate's key skills, tools, technologies, and areas of expertise that are relevant to the job description. Include EVERY skill and keyword from the job posting that the candidate possesses (e.g., Excel, SQL, Azure, Databricks, Power BI, JIRA, Agile, healthcare data, etc.). Ensure no critical skill from the job description is missing. Keep this section ATS-friendly (plain text, no graphics or tables) and easy to read.
  4. Professional Experience: For each role in the user's work history, list the job title, the company, the location, and the dates (e.g., Jan 2020 – Present). Include EVERY job from the user's resume (do not omit any positions), and list them in reverse chronological order (most recent first). If a past job title is different from the target role but the experience is relevant, consider adding a parenthetical or modifier to align it with the target job. For example, if the original title was "Data Engineer" but the role was similar to a data analyst in healthcare, you could present it as "Data Engineer (Healthcare Data Analyst)" to highlight its relevance. Do this only when it reflects actual experience, to avoid misrepresentation. Under each job, provide bullet points detailing accomplishments and responsibilities.
     - BULLET POINT COUNT: **CRITICAL REQUIREMENT - MINIMUM 5 BULLET POINTS PER JOB**: You MUST provide EXACTLY 5 or more bullet points for each job. This is NON-NEGOTIABLE. If the user's provided information for a job is very brief, you MUST expand on it creatively and infer relevant details to reach AT LEAST 5 bullets. For senior-level professionals, 2-3 bullets is completely inadequate and unprofessional. Every significant role MUST have sufficient detail (minimum 5 bullets) to demonstrate relevant experience. If you cannot think of 5 relevant bullets, you must use your expertise to infer logical responsibilities and achievements that align with the job description and the user's experience level.
     - BULLET POINT CONTENT: Each bullet must be highly tailored to the job description:
       - KEYWORD INTEGRATION: EVERY bullet should naturally incorporate at least 2-3 keywords or key phrases from the job description. Use the exact terminology from the posting (no synonyms for critical terms) to ensure ATS keyword matching. For instance, if the job description mentions "analyzes healthcare data to identify trends" and "SQL" and "Azure", a bullet might be: "Analyzed healthcare claims data to identify trends and variances using SQL on Azure, enabling proactive issue resolution." This way it uses multiple exact keywords in context.
       - RELEVANCE: Ensure each bullet demonstrates how the candidate's experience meets the specific requirements of the job. Tailor the content so that it mirrors the duties and responsibilities outlined in the job posting. If the job description says the candidate will "compile, organize, and analyze data to identify trends," then a bullet under a past job should reflect a similar task (e.g., "Compiled, organized, and analyzed large datasets to identify key trends in patient care, informing strategic decisions").
       - ACTION & IMPACT: Start each bullet with a strong action verb and emphasize achievements and outcomes. Wherever possible, quantify results to show scale or impact (e.g., improved data processing efficiency by 40%, reduced report turnaround time from 5 days to 2 days, managed a database of 1M+ records, saved $X or increased revenue by Y%, etc.). Numbers and concrete results make the impact clear and credible.
       - CLARITY & SPECIFICITY: Make sure each bullet point is specific and avoids generic statements. Clearly state what you did, how you did it, and what the result or benefit was. Every bullet should answer the question: how did this experience prepare the candidate for the target job?
       - JOB DESCRIPTION LANGUAGE: Mirror the language and phrasing of the job description for maximum alignment. Use the same verbs, nouns, and terminology that appear in the job posting. If the job description mentions tools or methodologies (e.g., JIRA for Agile project management, Power BI reports, data reconciliation), ensure those are mentioned in the relevant bullets as part of the experience.
     - NO COPY-PASTING: You MUST rewrite every single bullet point from the user's original resume in new words. Use the original resume only to glean facts (what they did, where, when, technologies used, etc.), but then completely rephrase and enhance each achievement in a way that directly relates to the job description. Do NOT copy any text from the original resume. The wording must be fresh, unique, and tailored to the target job.
  5. Education & Certifications: List the candidate's education (degree, field of study, school, graduation year) and any relevant certifications or training. Ensure that any education or certification specifically required or mentioned in the job posting (for example, a Bachelor's degree or a certification in a relevant field) is clearly included. If the job is in a regulated field like healthcare and the candidate has relevant coursework or knowledge (e.g., HIPAA, FDA regulations), it could be worth noting if not already mentioned.
- Do not omit any detail from the user's profile that could be relevant. Include all employment history, and incorporate any additional experience, skills, or achievements the user has provided, aligning them with the job requirements as much as possible. The goal is to present the candidate as exceptionally well-qualified for the specific position.

CRITICAL ATS OPTIMIZATION REQUIREMENTS:
- Incorporate EVERY important keyword, skill, or requirement from the job description somewhere in the resume, especially in the Skills and Experience sections. If the job description lists a technology, skill, or qualification (e.g., specific software, tools, methodologies, domain knowledge), make sure it appears in the resume in a logical place. No skill from the job posting should be missing.
- Match the job title and role requirements precisely in the resume. If the job description uses a specific job title or terminology, ensure the resume uses that exact phrasing (for example, in the Summary or in an experience bullet, or even adding a parenthetical as noted). This boosts ATS ranking by aligning with the employer's search terms.
- Use the job description's exact wording for duties and skills to maximize keyword matching. However, do so in a way that reads naturally to a human. Avoid simply listing keywords; instead, integrate them into descriptions of accomplishments.
- Maintain a balance: optimize for ATS and ensure the resume remains clear and compelling to a human reader. Do not sacrifice readability. The resume should not look like a keyword dump; it should tell a coherent story of the candidate's career that happens to be rich in relevant keywords.

ADDRESS ALL JOB REQUIREMENTS AND PREFERENCES:
- Make sure the resume explicitly confirms that the candidate meets any mandatory requirements from the job posting. For example, if U.S. citizenship and the ability to pass a DoD background check are required, include a mention like *U.S. Citizen eligible for DoD security clearance* (perhaps in the summary or header). If a Bachelor's degree is required, ensure the education section clearly shows the degree.
- If the job description emphasizes domain-specific experience (for instance, experience with healthcare claims or payment systems), highlight any experience the candidate has in a related domain (healthcare, pharmaceuticals, clinical data, etc.) to show familiarity with the field. Even if the candidate's experience is slightly different, frame it in terms of the job's context. For example, if they've worked with pharmaceutical data or patient records, draw parallels to working with healthcare claims data.
- Include mention of any methodologies or soft skills that appear in the job description. For example, if the posting mentions working in an Agile environment or using JIRA for task tracking, ensure the resume references working with Agile/Scrum methodologies and tools like JIRA. If the job values communication or teamwork, a bullet could reflect collaborating with cross-functional teams or stakeholders.
- Every requirement or preference stated in the job posting should be addressed in the resume. Even if the user's original resume didn't explicitly mention something, find a way to incorporate it if the experience could support it. (Do not fabricate experience, but you can extrapolate from what's given. For instance, if the user worked with data, it's reasonable they used Excel or SQL even if not originally stated, so include those if the job asks for them.)

FORMATTING & STYLE GUIDELINES:
- Use a straightforward layout with clear section headings (e.g., Professional Summary, Skills, Experience, Education). Format section titles in ALL-CAPS or bold for clarity if needed. Ensure that an ATS can parse each section easily (avoid unusual fonts, columns, or images).
- Present the content in simple bullet points and short paragraphs. Avoid any fancy formatting like tables, text boxes, graphics, or multiple columns that could confuse an ATS. The output should be plain text, neatly organized.
- Keep the tone professional and factual. Write in third-person implied (no use of "I", "me", or "my"). Do not include personal pronouns; just start sentences with strong verbs or descriptors (e.g., "Led a team of analysts to..." not "I led...").
- Ensure consistency in verb tense and formatting. Use past tense for past roles and present tense for the current role.
- Each bullet point should be concise (ideally not more than 1-2 lines) to maintain readability.
- Do not include any personal information that is not relevant to the job (no personal hobbies, no photo, etc.). Focus purely on professional qualifications.
- Make sure the final resume is free of spelling or grammatical errors.

ADDITIONAL OUTPUT INSTRUCTIONS:
- After writing the full resume, include a brief **ATS Optimization Summary** at the end of your answer (after all the resume sections). This should be a short paragraph (a few sentences) addressed to the user (not part of the resume itself) explaining how well the resume has been tailored to the job. For example, mention that the resume includes all critical keywords and skills from the job description, and perhaps give an estimated match percentage (e.g., "This resume is estimated to match over 95% of the job description keywords"). Highlight that all key requirements (such as specific tools, technologies, and qualifications like U.S. Citizenship) are included. This will reassure the user of the resume's effectiveness. Make sure this summary section is clearly separated from the actual resume content.
- Finally, as a friendly follow-up, add one line after the ATS summary offering further help. For example: *I can also prepare a tailored cover letter to complement this resume—just ask whenever you’re ready* (This should be separate from the resume text as an offer of additional assistance.)

**FINAL BULLET POINT VERIFICATION**: Before submitting your resume, count the bullet points under each job. EVERY job MUST have at least 5 bullet points. If any job has fewer than 5 bullets, you have FAILED this requirement and must add more bullets immediately. This is a CRITICAL quality standard that cannot be compromised.

Remember: Our goal is to produce a tailored resume that is 10 steps ahead of any competition. It should read as if it was expertly crafted specifically for this job, with absolutely no generic content. It must excite a hiring manager by demonstrating that the candidate not only fits every requirement but also brings quantifiable value. At the same time, it must rank at the very top of the ATS due to complete keyword optimization. Every detail from the job posting should be reflected in the resume. The end result should be a resume so excellent that it leaves both the algorithms and the human readers thoroughly impressed.`;
}

// ✅ DUPLICATE ORIGINAL CLIENT-SIDE FUNCTIONS: Parse AI Decision (exact copy from background.js)
function parseAIDecision(response) {
    // Extract the decision tag from the AI's response
    const decisionMatch = response.match(/^\[(ANALYSIS|RESUME_GENERATION|COVER_LETTER_GENERATION|SHOW_RESUME|CONVERSATION|CLARIFICATION)\]/);
    if (decisionMatch) {
        return {
            type: decisionMatch[1],
            response: response.replace(/^\[(ANALYSIS|RESUME_GENERATION|COVER_LETTER_GENERATION|SHOW_RESUME|CONVERSATION|CLARIFICATION)\]\s*/, '')
        };
    }

    // Default to conversation if no tag found
    return {
        type: 'CONVERSATION',
        response: response
    };
}

// ✅ DUPLICATE ORIGINAL CLIENT-SIDE FUNCTIONS: Execute AI Decision (exact copy from background.js)
// REMOVED: executeAIDecision function - no longer needed with single-call architecture

// REMOVED: callOpenAIDirect function - no longer needed with single-call architecture

// REMOVED: formatResumeForDisplay function - no longer needed with single-call architecture

// Build detailed analysis prompt (exact copy from background.js)
async function buildDetailedAnalysisPrompt(message, sessionId, userProfile, toggleState, userId) {
    
    // 🔍 DEBUG: Check what userProfile contains
    if (userProfile) {
    }
    
    // Use the toggleState parameter passed from client instead of inferring from profile data
    const isProfileToggleOff = toggleState === 'off';

    // Debug: Log resume data availability

    // Format user profile based on toggle state
    const profileText = formatUserProfile(userProfile, {
        includeRaw: !isProfileToggleOff // Only include resume when toggle is ON
    });
    
    // Get job description from Redis and format as context
    const jobDescription = await getJobDescriptionFromRedis(userId);
    const contextText = jobDescription ? `\n\nJOB CONTEXT:\n${jobDescription}` : '';
    
    // Get conversation context from server-side chat history management (retrieval only)
    const chatHistoryData = await manageChatHistory(sessionId, [], null, userId);
    const conversationContext = chatHistoryData.conversationContext;

    // Debug: Log what's included in the prompt

    // User preferences for language, tone, and education level
    const userLanguage = userProfile?.language || 'english';
    const userTone = userProfile?.preferredTone || 'professional';
    const userEducation = userProfile?.educationLevel || 'not specified';

    // If profile toggle is OFF, provide general analysis without resume
    if (isProfileToggleOff) {
        return `Behavior with Profile Toggle OFF (Resume Data Disabled) – Expert General Knowledge Mode

USER PREFERENCES:
- Language: ${userLanguage}
- Preferred Tone: ${userTone}
- Education Level: ${userEducation}

LANGUAGE AND COMMUNICATION REQUIREMENTS:
- ALWAYS respond in the user's preferred language: ${userLanguage}
- If language is "spanish", respond entirely in Spanish
- If language is "french", respond entirely in French
- If language is "german", respond entirely in German
- If language is "arabic", respond entirely in Arabic

TONE REQUIREMENTS:
- Match the user's preferred tone: ${userTone}
- If tone is "professional": Use formal, business-like language
- If tone is "casual": Use friendly, conversational language
- If tone is "enthusiastic": Use energetic, positive language
- If tone is "confident": Use assertive, self-assured language
- If tone is "friendly": Use warm, approachable language

EDUCATION LEVEL ADAPTATION:
- Adapt to user's education level: ${userEducation}
- If education level is "high_school": Use simpler language, avoid complex jargon
- If education level is "undergraduate": Use standard professional language
- If education level is "graduate": Use advanced terminology with explanations
- If education level is "doctorate": Use sophisticated language, technical jargon
- If education level is "none": Use clear, accessible language

CRITICAL: You are in PROFILE TOGGLE OFF mode. You MUST NOT provide job analysis, resume analysis, or career tailoring.

Scope & Identity:
You are a broad, domain-general assistant for learning, research, reading & writing, and everyday questions.

You DO NOT provide personalized career coaching, resume/cover-letter tailoring, or job-application strategy while the toggle is OFF.

Data Constraints:
You have no access to the user's resume data. Do not ask for it. Do not infer it.

Treat every answer as general guidance that anyone could use. Be very detailed in your answers with examples when appropriate.

What You're Expert At (examples, not limits):
Academic help (high school through doctoral): explain concepts, outline essays, solve step-by-step math/stats, propose study plans, compare theories, generate citations (APA/MLA/Chicago etc.), and produce literature-style summaries (with sources if provided).

Research workflows: question decomposition, search-query design (without browsing if the host doesn't allow it), argument mapping, extracting claims from provided texts, and drafting structured abstracts.

Reading & writing: rewriting for clarity/tone, editing for grammar and logic, summarizing, paraphrasing, outlining, thesis statements, topic sentences, transitions, and rubric-aligned checklists.

Hard Boundaries (toggle OFF):
Do NOT analyze resumes, job descriptions, interview prompts, or ATS strategy.
Do NOT suggest resume bullets, cover-letter language, or job-fit claims.
Do NOT provide job analysis, job requirements analysis, or career advice.
Do NOT create sections like "JOB ANALYSIS", "Job Requirements", "General Advice", "Skills Recommendations", or "Application Strategy".

If the user asks for career items, respond: "I can give general information and help now. For career-specific tailoring, enable your profile data."

Response Style & Safety:
Be concise, structured, and source-aware: if the user provides texts, cite/quote those; otherwise offer neutral, broadly accepted explanations.
Prefer numbered steps, short paragraphs, and small checklists. Offer optional templates for writing tasks.
When unsure, ask a single clarifying question only if it meaningfully changes the result; otherwise state reasonable assumptions and proceed.

Mode Reminder:
If the user explicitly requests job description analysis, resume analysis, and career tailoring, politely explain the limitation and suggest switching the profile toggle ON for personalized help.

CRITICAL INSTRUCTION: If the user asks about job analysis, job requirements, or career advice, respond with: "I can provide general information and help with academic or research questions. For job-specific analysis and career tailoring, please enable your profile data by turning the profile toggle ON."

USER REQUEST: "${message}"

Please provide general guidance and information related to this question. Do NOT provide job analysis or career advice.

FINAL FORMATTING ENFORCEMENT: If you create any numbered list, you MUST use sequential numbering (1., 2., 3., 4., 5.) and NEVER repeat "1." for multiple items.

CRITICAL: You MUST use the tag system. If the user says "analyze my resume" or "analyze my resume against this job", you MUST start your response with [ANALYSIS]. This is not optional.`;
    }

    // If profile toggle is ON but no resume data is available
    if (!userProfile || !userProfile.resumeText || userProfile.resumeText.trim().length === 0) {
        return `You are in PROFILE TOGGLE ON mode, but no resume data is available for analysis.

USER PREFERENCES:
- Language: ${userLanguage}
- Preferred Tone: ${userTone}
- Education Level: ${userEducation}

LANGUAGE AND COMMUNICATION REQUIREMENTS:
- ALWAYS respond in the user's preferred language: ${userLanguage}
- If language is "spanish", respond entirely in Spanish
- If language is "french", respond entirely in French
- If language is "german", respond entirely in German
- If language is "arabic", respond entirely in Arabic

TONE REQUIREMENTS:
- Match the user's preferred tone: ${userTone}
- If tone is "professional": Use formal, business-like language
- If tone is "casual": Use friendly, conversational language
- If tone is "enthusiastic": Use energetic, positive language
- If tone is "confident": Use assertive, self-assured language
- If tone is "friendly": Use warm, approachable language

EDUCATION LEVEL ADAPTATION:
- Adapt to user's education level: ${userEducation}
- If education level is "high_school": Use simpler language, avoid complex jargon
- If education level is "undergraduate": Use standard professional language
- If education level is "graduate": Use advanced terminology with explanations
- If education level is "doctorate": Use sophisticated language, technical jargon
- If education level is "none": Use clear, accessible language

JOB DESCRIPTION:
${contextText}

USER REQUEST: "${message}"

IMPORTANT: The user has enabled their profile toggle (personalized mode), but no resume data is currently available. 

Please respond with a helpful message explaining that resume analysis requires the user to first upload their resume. Provide general guidance about the job description and suggest they upload their resume to get personalized analysis.

Be helpful and encouraging, explaining the benefits of uploading their resume for personalized job application assistance.`;
    }

    // Profile toggle is ON and resume data is available - provide detailed resume analysis
    return `Analyze this resume against the job description. Provide the most comprehensive, **beyond industry-standard** analysis possible.

USER PREFERENCES:
- Language: ${userLanguage}
- Preferred Tone: ${userTone}
- Education Level: ${userEducation}

LANGUAGE AND COMMUNICATION REQUIREMENTS:
- ALWAYS respond in the user's preferred language: ${userLanguage}
- If language is "spanish", respond entirely in Spanish
- If language is "french", respond entirely in French
- If language is "german", respond entirely in German
- If language is "arabic", respond entirely in Arabic

TONE REQUIREMENTS:
- Match the user's preferred tone: ${userTone}
- If tone is "professional": Use formal, business-like language
- If tone is "casual": Use friendly, conversational language
- If tone is "enthusiastic": Use energetic, positive language
- If tone is "confident": Use assertive, self-assured language
- If tone is "friendly": Use warm, approachable language

EDUCATION LEVEL ADAPTATION:
- Adapt to user's education level: ${userEducation}
- If education level is "high_school": Use clear, simple language, avoid complex jargon
- If education level is "undergraduate": Use standard professional language
- If education level is "graduate": Use advanced terminology with brief explanations as needed
- If education level is "doctorate": Use highly sophisticated language and industry-specific jargon where appropriate
- If education level is "none": Use clear, accessible language without assuming prior knowledge

RESUME:
${profileText}

JOB DESCRIPTION:
${contextText}

USER REQUEST: "${message}"

Provide **comprehensive, step-by-step analysis** with the following sections (in this exact order and format):

- **RESUME OVERVIEW:** Begin by listing all work experiences from the resume. Use sequential numbering (1., 2., 3., ...) for each distinct role. Include company name, role/title, and dates. This gives a high-level picture of the candidate’s experience timeline.
- **JOB TITLE ANALYSIS:** For each role listed above, analyze the job title in the context of the target position. Discuss how well each title aligns with the job being applied for. Provide a relevance rating for each title (1-10) and suggest any **optimized title phrasing** if it could improve alignment (while staying truthful). *Do not number each job title in this section; present as separate paragraphs or bullet points per job.*
- **WORK EXPERIENCE ANALYSIS:** Dive deep into every single work experience in the candidate’s resume, no exceptions. Do not skip or condense roles. Process each role one by one in the order they appear in the overview. For each role, output:
    - **Job Title Analysis (Relevance:** X/10): a brief note on the title’s relevance (this can reiterate the rating from the Job Title Analysis section in context).
    - **Overall Role Summary:** Write a full paragraph connecting this role’s responsibilities and achievements to the job description. Always reference specific duties from the resume and explicitly connect them to requirements in the JD. Highlight quantifiable results (numbers, percentages, improvements) where possible, and show how the candidate’s actions created impact.
    - **Key Skills from This Role:** Provide a bullet list of the 3–5 most relevant skills or technologies from this role that match the job Description. Always mirror the exact wording from the job Description for ATS alignment.
    - **Relevance to Target Role:** Explain why this experience is or is not a strong match. Explicitly cite missing elements (if any) and suggest how the candidate can bridge these gaps using other experiences or skills.
- **SKILLS ANALYSIS:** Compare the skills listed in the resume (often in a Skills section or implied in experience) against the job description’s required and preferred skills. 
    - **Matching Skills:** Identify which key skills from the job description the candidate already has on their resume. List them and briefly note any evidence of those skills in the work experience (e.g., “Skill: SQL – demonstrated by 3 years of database work at XYZ Corp”).
    - **Missing Skills/Gaps:** Identify important skills or keywords the job is seeking that **do not appear** in the resume. For each missing skill, if the candidate likely has it (but it’s not explicitly stated), suggest incorporating it into the resume (for example, through an existing bullet or a new bullet point). If the candidate truly lacks it, acknowledge it and perhaps recommend learning or emphasizing a related skill instead. **Emphasize adding relevant keywords** here to improve ATS score – for instance, if the job repeatedly mentions a methodology or software that the resume omits, recommend finding a way to include it if applicable to the candidate’s experience.
    - **Proficiency & Terminology:** Note if the resume’s wording for a skill differs from the job description’s wording. Suggest aligning terminology exactly. (e.g., resume says “MS Office” but job says “Microsoft Office Suite” – advise using the exact phrase for compatibility). Ensure that **both human readers and ATS** can clearly see the relevant skills.
    - **Soft Skills vs Hard Skills:** If the job description emphasizes certain soft skills (communication, teamwork, etc.) that the resume only mentions vaguely (or vice versa), discuss how to better showcase them. However, caution against listing clichéd soft skills without context – instead, tie them to concrete examples from experience to maintain credibility.
- **EDUCATION ANALYSIS:Analyze every user's education entry individually and assign an Education Alignment Score. For each degree/certification, output a short line in the format: [Degree/Program] – Alignment Score: X/10. One to two sentences explaining why it earned that score, referencing JD requirements, relevance, cert presence, or ATS phrasing. If score is low, note whether to keep, condense, or remove. After scoring all entries, provide a global summary that confirms requirement match (meets/exceeds job description baseline), notes presence or absence of relevant certifications/training, identifies education gaps and how to address them, and recommends which items to keep, condense, or remove for strongest ATS and recruiter impact.
- **SUMMARY/OBJECTIVE ANALYSIS:** Examine the resume’s summary or objective statement (if provided) and evaluate how well it is **tailored to the target job**.
    - **Relevance and Keywords:** Does the summary mention the target job title or key skills/experiences relevant to the position/Job description? If not, provide suggestions to incorporate **the most important keywords** and competencies from the job description into a revised summary. The goal is to immediately signal “fit” for the role in the first few lines of the resume.
    - **Value Proposition:** Assess whether the summary effectively sells the candidate’s top strengths and achievements that are relevant for this job. If it's too generic or missing critical info (like years of experience in a required area, or specific accomplishments), suggest a more impactful alternative. For example, if the job is seeking a project manager and the candidate’s summary doesn’t mention project management, recommend adding a phrase like “results-driven Project Manager with X years experience…”.
    - **Tone and Clarity:** Ensure the summary’s tone matches the desired tone (professional, confident, etc.). If the resume lacks a summary and the job would benefit from one, propose 1-2 sentences that could serve as a strong introduction, tailored to the job’s priorities.
    - **Avoid Clichés:** Identify any buzzwords or clichés in the summary that don’t add value (“hard-working team player”, “detail-oriented professional”, etc.). Advise replacing or removing them in favor of concrete skills or achievements. For instance, instead of “detail-oriented,” say “crafted 3 error-free product launches through meticulous attention to detail.”
- **FINAL RECOMMENDATIONS:** Conclude with a brief summary of the overall alignment and top suggestions.
    - **Overall Fit Assessment:** Provide a clear overall assessment of how well the resume currently matches the job, expressed in the format “X/10 match” (e.g., “Overall, your resume is a strong 8/10 match for this role”). This score must be based on the full analysis of the resume and job description — never arbitrary.
    - **ATS Compatibility Score:** Provide an ATS Compatibility Score on a 0–100% scale. Break down this score briefly into keyword coverage, job title alignment, education match, format compatibility, and domain relevance. Ensure the percentages are logical and tied back to the earlier analysis.
    - **Top 3 Improvement Actions:** List the three most impactful changes the candidate should make next (e.g., “1. Add Python to Skills – it’s required in the job description but missing from your resume. 2. Revise your last job’s bullets to include project management keywords and quantify results…”). Keep this section actionable and precise.
    - End with an uplifting note that boosts the candidate’s confidence. Make it motivational and supportive, reinforcing that they are close to securing their target role. Conclude with a friendly, proactive question that invites them to continue (e.g., “I can also create a tailored resume or cover letter that aligns perfectly with this job description to maximize your chances—just let me know anytime.”).

FORMAT & STYLE REMINDERS:
- **Structure:** Use the exact section headers as outlined above (including the colon at the end of each). Do not deviate from this section order or naming. Ensure each section is clearly separated and formatted for easy reading (you can use line breaks, indentation, and bullet points as indicated).
- **Numbering and Bullets:** Use sequential numbering for any lists of items (especially in the Resume Overview and Final Recommendations). **Do NOT start every item with "1."** – they must count up (1, 2, 3, ...). Use bullet points for sub-items or lists within sections as shown (e.g., key skills, improvement actions).
- **Comparative Tone:** Throughout the analysis, maintain a tone that is **analytical, constructive, and specific**. Avoid just repeating resume lines; instead, always **compare** and **contrast** with what the job needs. This means explicitly saying things like “Job requires X, and you have Y, which is a close match because…” or “The job highlights X, but your resume currently doesn’t mention that – consider adding...”.
- **Actionable Advice:** Every suggestion should be concrete. Where you spot an issue or gap, provide a direct recommendation on how to fix or improve it. For example, if a bullet is too vague, suggest a way to add detail or results. If a needed skill is missing, suggest where or how to include it (e.g., in a skills section or as part of a work experience bullet).
- **ATS and HR Perspective:** Ensure the advice covers both ATS optimization (keywords, formatting considerations if any) and the human perspective (clear storytelling, impact). If certain formatting or keyword issues might confuse an ATS (like weird fonts or graphics – though resume text likely doesn’t include those, but just in case), gently mention it. From the HR perspective, ensure the content reads as credible and impressive – the recommendations should help the user sound like a great fit.
- **No Generic Filler:** Avoid generic statements like “make sure to highlight relevant skills.” Instead, *pinpoint exactly which skills* and *where to highlight them*. The user should feel that every sentence of the analysis is tailored to their resume and the job description.
- **Honesty and Encouragement:** If something is a strong match, praise it specifically (“Your experience managing a team of 5 directly aligns with the leadership requirement”). If something is lacking, be honest but positive, framing it as an opportunity to improve (“You haven’t used Python in your roles, which is a key skill for this job. You might consider taking an online course or highlighting any experience with similar languages if applicable.”).
- **Length & Detail:** This analysis should be **very detailed and comprehensive**. However, organize the content so it’s not just a wall of text – use the structure to make it digestible. It’s okay if the final answer is long, as long as it’s rich with useful insights.

Remember, the goal is to provide a level of feedback **beyond what automated tools or typical resume reviews offer**, giving the user **unprecedented insight** into how to tailor their resume to the job description.

Now, begin the analysis following the structure and guidelines above. Start with "RESUME OVERVIEW:" and proceed step by step through each section. Make sure to maintain the format strictly and include all relevant details in each part.

FINAL NOTE: **Adhere to the exact format and instructions.** Do not omit sections or steps. Check that all numbering is correct and all content is directly relevant to the resume and job description provided. Let's deliver an analysis that truly stands out.

${conversationContext}

`;
}


// ===== SERVER-SIDE CHAT HISTORY MANAGEMENT =====
// Single function to handle all chat history management with summarization

// Redis storage for chat sessions
// const chatSessions = new Map(); // REMOVED - now using Redis

// Upstash Redis helper functions for chat sessions
async function storeChatSession(sessionId, sessionData) {
    try {
        const key = `chat_session:${sessionId}`;
        await redisClient.setex(key, 4 * 60 * 60, JSON.stringify(sessionData)); // 4 hours TTL (safety net only)
    } catch (error) {
        // Error: [UPSTASH] Error storing chat session:', error);
        throw error;
    }
}

async function getChatSession(sessionId) {
    try {
        const key = `chat_session:${sessionId}`;
        const sessionData = await redisClient.get(key);
        if (sessionData) {
            // Upstash Redis automatically parses JSON, so we can return it directly
            return sessionData;
        }
        return null;
    } catch (error) {
        // Error: [UPSTASH] Error retrieving chat session:', error);
        return null;
    }
}

async function deleteChatSession(sessionId) {
    try {
        const key = `chat_session:${sessionId}`;
        await redisClient.del(key);
    } catch (error) {
        // Error: [UPSTASH] Error deleting chat session:', error);
    }
}

async function deleteUserChatSessions(userId) {
    try {
        const pattern = `chat_session:*`;
        const keys = await redisClient.keys(pattern);
        
        // Filter keys that belong to this user
        const userKeys = [];
        for (const key of keys) {
            const sessionData = await redisClient.get(key);
            if (sessionData) {
                // Upstash Redis automatically parses JSON, so we can use it directly
                if (sessionData.userId === userId) {
                    userKeys.push(key);
                }
            }
        }
        
        if (userKeys.length > 0) {
            await redisClient.del(...userKeys);
        }
    } catch (error) {
        // Error: [UPSTASH] Error deleting user chat sessions:', error);
    }
}

// ===== REDIS JOB DESCRIPTION STORAGE FUNCTIONS =====

/**
 * Check if text contains a job description (server-side version of client-side logic)
 * @param {string} text - The text to check
 * @returns {boolean} True if text appears to be a job description
 */
function checkIfJobDescription(text) {
    if (!text || typeof text !== 'string') return false;
    
    const lowerText = text.toLowerCase();
    
    // Look for job description indicators (same as client-side)
    const jobIndicators = [
        'job description', 'position description', 'role description', 
        'we are looking for', 'we are seeking', 'requirements:', 'qualifications:', 
        'responsibilities:', 'duties:', 'about the role', 'about this position', 
        'job requirements', 'position requirements', 'role requirements', 
        'minimum qualifications', 'preferred qualifications', 'required skills', 
        'preferred skills', 'experience required', 'experience needed'
    ];
    
    // Check if text contains multiple job description indicators
    const matches = jobIndicators.filter(indicator => lowerText.includes(indicator));
    
    // Also check for typical job description structure
    const hasStructuredContent = text.includes('•') || text.includes('-') || text.includes('*');
    const hasMultipleLines = text.split('\n').length > 5;
    const isLongText = text.length > 200;
    
    // Consider it a job description if it has multiple indicators or structured content
    return matches.length >= 2 || (hasStructuredContent && hasMultipleLines && isLongText);
}

/**
 * Save job description to Redis for a user
 * @param {string} userId - The user identifier
 * @param {string} jobDescription - The job description text
 */
async function saveJobDescriptionToRedis(userId, jobDescription) {
    try {
        const key = `jd:${userId}`;
        const ttl = 4 * 60 * 60; // 4 hours TTL
        
        await redisClient.setex(key, ttl, jobDescription);
        
        // Verify the save operation
        const verification = await redisClient.get(key);
        const ttlRemaining = await redisClient.ttl(key);
        
        if (verification) {
            // Check if content matches
            if (verification === jobDescription) {
                // Content verification: EXACT MATCH
            } else {
                // Content verification: MISMATCH DETECTED
            }
        } else {
            // Verification failed - data not found in Redis
        }
        
    } catch (error) {
        // Error: [REDIS JD] Error saving job description
        throw error;
    }
}

/**
 * Get job description from Redis for a user
 * @param {string} userId - The user identifier
 * @returns {string|null} The job description text or null if not found
 */
async function getJobDescriptionFromRedis(userId) {
    try {
        const key = `jd:${userId}`;
        
        const jobDescription = await redisClient.get(key);
        const ttlRemaining = await redisClient.ttl(key);
        
        if (jobDescription) {
            return jobDescription;
        } else {
            if (ttlRemaining === -2) {
                // Key status: EXPIRED or NEVER EXISTED
            } else if (ttlRemaining === -1) {
                // Key status: EXISTS but NO TTL (should not happen)
            }
            return null;
        }
    } catch (error) {
        // Error: [REDIS JD] Error retrieving job description
        return null;
    }
}

/**
 * Delete job description from Redis for a user
 * @param {string} userId - The user identifier
 */
async function deleteJobDescriptionFromRedis(userId) {
    try {
        const key = `jd:${userId}`;
        await redisClient.del(key);
    } catch (error) {
        // Error: [REDIS JD] Error deleting job description
        throw error;
    }
}

// Configuration for chat history management
const CHAT_CONFIG = {
    MAX_RECENT_MESSAGES: 5,         // Keep last 5 messages in full (reduced for efficiency)
    SUMMARY_THRESHOLD: 3,           // Start running summary after 3 messages
    MAX_SUMMARY_LENGTH: 300         // Maximum length for running summary
};

/**
 * Single function to manage chat history with automatic summarization
 * @param {string} sessionId - The session identifier
 * @param {Array} newMessages - New messages to add (optional)
 * @param {string} jobDescription - Job description to preserve (optional)
 * @param {string} userId - The user identifier
 * @returns {Object} { summary, recentMessages, totalMessages, conversationContext }
 */
async function manageChatHistory(sessionId, newMessages = [], jobDescription = null, userId = null) {
    
    // Get existing session from Redis
    let session = await getChatSession(sessionId);
    
    // Initialize session if it doesn't exist
    if (!session) {
        session = {
            sessionId,
            userId,
            messages: [],
            summary: null,
            jobDescription: null,
            lastActivity: new Date().toISOString(),
            createdAt: new Date().toISOString()
        };
    }
    
    // Update job description if provided - RESET CONVERSATION for new job
    if (jobDescription) {
        // Check if this is a new job description (different from current one)
        if (session.jobDescription && session.jobDescription !== jobDescription) {
            // Reset conversation history for new job
            session.messages = [];
            session.summary = null;
            session.lastActivity = new Date().toISOString();
        }
        session.jobDescription = jobDescription;
    }
    
    // Add new messages if provided
    if (newMessages && newMessages.length > 0) {
        newMessages.forEach(msg => {
            session.messages.push({
                role: msg.role,
                content: msg.content,
                timestamp: new Date().toISOString()
            });
        });
        session.lastActivity = new Date().toISOString();
        
        // Update running summary with new messages
        if (session.messages.length >= CHAT_CONFIG.SUMMARY_THRESHOLD) {
            await updateRunningSummary(session);
        }
    }
    
    // Determine what to return
    const totalMessages = session.messages.length;
    let recentMessages = session.messages;
    
    // If we have many messages, return only recent ones
    if (totalMessages > CHAT_CONFIG.MAX_RECENT_MESSAGES) {
        recentMessages = session.messages.slice(-CHAT_CONFIG.MAX_RECENT_MESSAGES);
    }
    
    // Build conversation context - prioritize running summary
    let conversationContext = '';
    
    // Add running summary if available (this contains all essential context)
    if (session.summary) {
        conversationContext += `\n\nCONVERSATION SUMMARY:\n${session.summary}`;
    }
    
    // Add recent messages only if we don't have a summary yet (first few messages)
    if (recentMessages && recentMessages.length > 0 && !session.summary) {
        conversationContext += '\n\nRECENT CONVERSATION:\n' + recentMessages.map(msg => 
            `${msg.role === 'user' ? 'User' : 'Assistant'}: ${msg.content}`
        ).join('\n');
    }
    
    // Add job description only if it's short and we don't have much context yet
    if (session.jobDescription && session.jobDescription.length < 1000 && conversationContext.length < 2000) {
        conversationContext += `\n\nJOB DESCRIPTION:\n${session.jobDescription}`;
    }
    
    // Store updated session in Redis
    await storeChatSession(sessionId, session);
    
    return {
        summary: session.summary,
        recentMessages,
        totalMessages,
        conversationContext,
        jobDescription: session.jobDescription
    };
}

/**
 * Update running summary with new messages - maintains a continuous summary
 * @param {Object} session - The session object
 */
async function updateRunningSummary(session) {
    try {
        // Get the last few messages to add to the summary
        const recentMessages = session.messages.slice(-3); // Last 3 messages
        const newConversationText = recentMessages.map(msg => 
            `${msg.role === 'user' ? 'User' : 'Assistant'}: ${msg.content}`
        ).join('\n');
        
        let summaryPrompt;
        
        if (session.summary) {
            // Update existing summary with new messages
            summaryPrompt = `You have an existing conversation summary and new messages. Update the summary to include the new information while keeping it concise and under ${CHAT_CONFIG.MAX_SUMMARY_LENGTH} words.

EXISTING SUMMARY:
${session.summary}

NEW MESSAGES:
${newConversationText}

UPDATED SUMMARY (keep it concise, focus on key topics and context):`;
        } else {
            // Create initial summary
            summaryPrompt = `Create a concise summary of this conversation. Focus on key topics, decisions, and context that would be important for continuing the conversation. Keep it under ${CHAT_CONFIG.MAX_SUMMARY_LENGTH} words.

CONVERSATION:
${newConversationText}

SUMMARY:`;
        }
        
        // Call OpenAI for summarization using the key rotation system
        const apiKey = getNextApiKey();
        const response = await fetch('https://api.openai.com/v1/chat/completions', {
            method: 'POST',
            headers: {
                'Authorization': `Bearer ${apiKey}`,
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                model: 'gpt-3.5-turbo',
                messages: [
                    {
                        role: 'system',
                        content: 'You are a helpful assistant that creates and maintains concise conversation summaries. Focus on key topics, decisions, and context. Always stay under the word limit.'
                    },
                    {
                        role: 'user',
                        content: summaryPrompt
                    }
                ],
                max_tokens: Math.floor(CHAT_CONFIG.MAX_SUMMARY_LENGTH * 1.5), // Allow some buffer
                temperature: 0.3
            })
        });
        
        if (response.ok) {
            const data = await response.json();
            const newSummary = data.choices[0].message.content.trim();
            
            // Update session with new summary
            session.summary = newSummary;
            
            // Keep only the most recent messages to avoid token bloat
            if (session.messages.length > CHAT_CONFIG.MAX_RECENT_MESSAGES) {
                session.messages = session.messages.slice(-CHAT_CONFIG.MAX_RECENT_MESSAGES);
            }
            
        } else {
            throw new Error(`OpenAI API error: ${response.status}`);
        }
        
    } catch (error) {
        // Error: [RUNNING SUMMARY] Failed to update summary:', error);
        // Don't fail the request if summary update fails
        // Keep existing summary or create a simple fallback
        if (!session.summary) {
            session.summary = 'Conversation context available but not summarized.';
        }
    }
}

// Clean up old sessions every hour (Redis-based cleanup)
setInterval(async () => {
    try {
        const cutoffTime = new Date(Date.now() - 24 * 60 * 60 * 1000); // 24 hours
        let cleanedCount = 0;
        
        // Get all chat session keys from Redis
        const sessionKeys = await redis.keys('chat_session:*');
        
        for (const key of sessionKeys) {
            try {
                const sessionData = await redis.get(key);
                if (sessionData) {
                    const session = JSON.parse(sessionData);
                    if (new Date(session.lastActivity) < cutoffTime) {
                        await redis.del(key);
                        cleanedCount++;
                    }
                }
            } catch (error) {
                // Skip invalid session data
                continue;
            }
        }
        
        if (cleanedCount > 0) {
            // Cleaned up old sessions
        }
    } catch (error) {
        // Error:Chat session cleanup failed
    }
}, 60 * 60 * 1000);

// Password reset page - serves the reset password form
app.get('/auth/reset-password', cors(SECURITY_CONFIG.cors), (req, res) => {
    const { token_hash, type } = req.query;
    
    console.log('Password reset page accessed:', { token_hash: !!token_hash, type, query: req.query });
    
    if (!token_hash || type !== 'recovery') {
        return res.status(400).send(`
            <!DOCTYPE html>
            <html>
            <head>
                <title>Invalid Reset Link</title>
                <style>
                    body { font-family: Arial, sans-serif; text-align: center; padding: 50px; }
                    .container { max-width: 400px; margin: 0 auto; }
                    .error { color: #e74c3c; }
                </style>
            </head>
            <body>
                <div class="container">
                    <h1 class="error">Invalid Reset Link</h1>
                    <p>The password reset link is invalid or has expired.</p>
                    <p>Please request a new password reset from the Trontiq extension.</p>
                </div>
            </body>
            </html>
        `);
    }
    
    res.send(`
        <!DOCTYPE html>
        <html>
        <head>
            <title>Reset Password - Trontiq</title>
            <style>
                body { 
                    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
                    background: linear-gradient(135deg, #2c3e50 0%, #34495e 100%);
                    margin: 0; padding: 0; min-height: 100vh;
                    display: flex; align-items: center; justify-content: center;
                }
                .container { 
                    background: white; padding: 40px; border-radius: 12px; 
                    box-shadow: 0 20px 40px rgba(0,0,0,0.1);
                    max-width: 400px; width: 100%;
                }
                .logo { text-align: center; margin-bottom: 30px; }
                .logo h1 { color: #2c3e50; margin: 0; font-size: 28px; font-weight: 600; }
                .logo p { color: #7f8c8d; margin: 5px 0 0 0; font-size: 14px; }
                .form-group { margin-bottom: 20px; }
                label { display: block; margin-bottom: 8px; color: #2c3e50; font-weight: 500; }
                input { 
                    width: 100%; padding: 12px; border: 2px solid #ecf0f1; 
                    border-radius: 6px; font-size: 16px; box-sizing: border-box;
                    transition: border-color 0.3s;
                }
                input:focus { outline: none; border-color: #2c3e50; }
                .btn { 
                    width: 100%; padding: 12px; background: #2c3e50; color: white;
                    border: none; border-radius: 6px; font-size: 16px; font-weight: 600;
                    cursor: pointer; transition: background 0.3s;
                }
                .btn:hover { background: #34495e; }
                .btn:disabled { background: #bdc3c7; cursor: not-allowed; }
                .message { 
                    padding: 12px; border-radius: 6px; margin-bottom: 20px; 
                    text-align: center; font-weight: 500;
                }
                .success { background: #d4edda; color: #155724; border: 1px solid #c3e6cb; }
                .error { background: #f8d7da; color: #721c24; border: 1px solid #f5c6cb; }
                .hidden { display: none; }
            </style>
        </head>
        <body>
            <div class="container">
                <div class="logo">
                    <h1>Trontiq</h1>
                    <p>Smart browser assistant for job applications</p>
                </div>
                
                <div id="message" class="hidden"></div>
                
                <form id="resetForm">
                    <div class="form-group">
                        <label for="newPassword">New Password</label>
                        <input type="password" id="newPassword" required minlength="6">
                    </div>
                    
                    <div class="form-group">
                        <label for="confirmPassword">Confirm New Password</label>
                        <input type="password" id="confirmPassword" required minlength="6">
                    </div>
                    
                    <button type="submit" class="btn" id="resetBtn">Reset Password</button>
                </form>
            </div>
            
            <script>
                const form = document.getElementById('resetForm');
                const message = document.getElementById('message');
                const resetBtn = document.getElementById('resetBtn');
                
                form.addEventListener('submit', async (e) => {
                    e.preventDefault();
                    
                    const newPassword = document.getElementById('newPassword').value;
                    const confirmPassword = document.getElementById('confirmPassword').value;
                    
                    if (newPassword !== confirmPassword) {
                        showMessage('Passwords do not match', 'error');
                        return;
                    }
                    
                    if (newPassword.length < 6) {
                        showMessage('Password must be at least 6 characters', 'error');
                        return;
                    }
                    
                    resetBtn.disabled = true;
                    resetBtn.textContent = 'Resetting...';
                    
                    try {
                        const response = await fetch('/api/reset-password', {
                            method: 'POST',
                            headers: { 'Content-Type': 'application/json' },
                            body: JSON.stringify({
                                token_hash: '${token_hash}',
                                password: newPassword
                            })
                        });
                        
                        const result = await response.json();
                        
                        if (response.ok) {
                            showMessage('Password reset successfully! You can now close this page and sign in with your new password.', 'success');
                            form.style.display = 'none';
                        } else {
                            showMessage(result.error || 'Failed to reset password', 'error');
                        }
                    } catch (error) {
                        showMessage('Network error. Please try again.', 'error');
                    } finally {
                        resetBtn.disabled = false;
                        resetBtn.textContent = 'Reset Password';
                    }
                });
                
                function showMessage(text, type) {
                    message.textContent = text;
                    message.className = 'message ' + type;
                    message.classList.remove('hidden');
                }
            </script>
        </body>
        </html>
    `);
});

// Password reset endpoint
app.post('/api/reset-password', cors(SECURITY_CONFIG.cors), async (req, res) => {
    try {
        const { token_hash, password } = req.body;
        
        if (!token_hash || !password) {
            return res.status(400).json({ error: 'Token and password are required' });
        }
        
        if (password.length < 6) {
            return res.status(400).json({ error: 'Password must be at least 6 characters' });
        }
        
        // Verify the token with Supabase
        const { data: { user }, error } = await supabase.auth.verifyOtp({
            token_hash: token_hash,
            type: 'recovery'
        });
        
        if (error || !user) {
            return res.status(400).json({ error: 'Invalid or expired reset token' });
        }
        
        // Update the user's password using Supabase Admin API
        const updateResponse = await fetch(`${process.env.SUPABASE_URL}/auth/v1/admin/users/${user.id}`, {
            method: 'PUT',
            headers: {
                'apikey': process.env.SUPABASE_SERVICE_ROLE_KEY,
                'Authorization': `Bearer ${process.env.SUPABASE_SERVICE_ROLE_KEY}`,
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ password: password })
        });
        
        if (!updateResponse.ok) {
            const errorData = await updateResponse.json();
            return res.status(400).json({ error: errorData.message || 'Failed to update password' });
        }
        
        res.json({ success: true, message: 'Password reset successfully' });
        
    } catch (error) {
        console.error('Password reset error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Handle Supabase's default auth callback
app.get('/auth/callback', cors(SECURITY_CONFIG.cors), (req, res) => {
    const { token_hash, type } = req.query;
    
    console.log('Auth callback received:', { token_hash, type });
    
    if (token_hash && type === 'recovery') {
        // Redirect to our password reset page
        res.redirect(`/auth/reset-password?token_hash=${token_hash}&type=${type}`);
    } else {
        // Handle other auth callbacks
        res.redirect('/');
    }
});

// 404 handler - must be last
// Change password endpoint
app.post('/api/change-password', cors(SECURITY_CONFIG.cors), authenticateSession, async (req, res) => {
    try {
        const { password } = req.body;
        
        if (!password) {
            return res.status(400).json({ error: 'Password is required' });
        }
        
        // Get user email from session
        const session = getSession(req.cookies.sid);
        if (!session || !session.email) {
            return res.status(401).json({ error: 'No active session found' });
        }
        
        // Call Supabase Admin API to update the password
        const userResponse = await fetch(`${process.env.SUPABASE_URL}/auth/v1/admin/users/${req.userId}`, {
            method: 'PUT',
            headers: {
                'apikey': process.env.SUPABASE_SERVICE_ROLE_KEY,
                'Authorization': `Bearer ${process.env.SUPABASE_SERVICE_ROLE_KEY}`,
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ password: password })
        });
        
        if (!userResponse.ok) {
            const errorData = await userResponse.json();
            console.error('Supabase password update error:', errorData);
            return res.status(400).json({ error: errorData.message || 'Failed to update password' });
        }
        
        const userData = await userResponse.json();
        
        // SECURITY: Invalidate current session after password change
        // This forces the user to reauthenticate with their new password
        const sessionId = req.cookies.sid;
        if (sessionId) {
            sessions.delete(sessionId);
            res.clearCookie('sid');
        }
        
        res.json({ 
            success: true, 
            data: userData,
            requiresReauth: true,
            message: 'Password changed successfully. Please log in again.'
        });
        
    } catch (error) {
        console.error('Password change error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

app.use('*', (req, res) => {
    res.status(404).json({ error: 'Endpoint not found' });
});

app.listen(PORT, () => {
    // Server started successfully
});
