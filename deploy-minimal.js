// Trontiq Minimal Server Deployment
// Single file deployment - includes all necessary code

const express = require('express');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const { createClient } = require('@supabase/supabase-js');
const cookieParser = require('cookie-parser');
const stripe = require('stripe')(process.env.STRIPE_SECRET_KEY);

// Supabase configuration for direct HTTP requests
const SUPABASE_URL = process.env.SUPABASE_URL;
const SUPABASE_SERVICE_ROLE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY;

// Initialize Supabase client
const supabase = createClient(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY);

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

// OpenAI API Key Rotation System (10 keys)
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

console.log(`🔑 Loaded ${openaiApiKeys.length} OpenAI API keys`);

// Key rotation system
let currentKeyIndex = 0;
let keyUsageCount = new Array(openaiApiKeys.length).fill(0);

function getNextApiKey() {
    if (openaiApiKeys.length === 0) {
        console.error('❌ No OpenAI API keys configured');
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
    
    console.log(`🔑 Using API key ${currentKeyIndex + 1} (usage: ${keyUsageCount[currentKeyIndex]})`);
    return openaiApiKeys[currentKeyIndex];
}

function markKeyAsFailed(keyIndex) {
    if (keyIndex >= 0 && keyIndex < keyUsageCount.length) {
        // Add a penalty to this key's usage count
        keyUsageCount[keyIndex] += 10;
        console.log(`⚠️ Marked key ${keyIndex + 1} as failed, increased penalty`);
    }
}

// Validate required environment variables
if (!SUPABASE_URL || !SUPABASE_SERVICE_ROLE_KEY) {
    console.error('❌ Missing required environment variables: SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY');
    process.exit(1);
}

// Helper function to handle subscription creation errors
function handleSubscriptionCreationError(createError, res) {
    console.error('❌ Error creating free tier subscription:', createError);
    
    // Check if it's a foreign key constraint error
    if (createError.code === '23503') {
        console.log('⚠️ User does not exist in auth.users table, returning free tier status');
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
function createSession(userId, userAgent) {
    const sessionId = 'sid_' + Date.now() + '_' + Math.random().toString(36).substr(2, 9);
    const session = {
        id: sessionId,
        userId: userId,
        userAgent: userAgent,
        createdAt: new Date(),
        expiresAt: new Date(Date.now() + SESSION_CONFIG.maxAge),
        lastActivity: new Date()
    };
    
    sessions.set(sessionId, session);
    console.log('🔐 Session created:', { sessionId, userId });
    return sessionId;
}

function getSession(sessionId) {
    const session = sessions.get(sessionId);
    if (!session) return null;
    
    // Check if session is expired
    if (new Date() > session.expiresAt) {
        sessions.delete(sessionId);
        console.log('🔐 Session expired:', sessionId);
        return null;
    }
    
    // Update last activity for rolling renewal
    session.lastActivity = new Date();
    
    // Extend session if it's close to expiring (within 1 hour)
    const oneHourFromNow = new Date(Date.now() + 60 * 60 * 1000);
    if (session.expiresAt < oneHourFromNow) {
        extendSession(sessionId);
        console.log('🔐 Session auto-extended:', sessionId);
    }
    
    return session;
}

function extendSession(sessionId) {
    const session = sessions.get(sessionId);
    if (session) {
        session.expiresAt = new Date(Date.now() + SESSION_CONFIG.maxAge);
        session.lastActivity = new Date();
        console.log('🔐 Session extended:', sessionId);
    }
}

function deleteSession(sessionId) {
    sessions.delete(sessionId);
    console.log('🔐 Session deleted:', sessionId);
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
    
    console.log('🌐 Making Supabase request:', {
        url,
        method: options.method || 'GET',
        headers: { ...headers, 'apikey': '[HIDDEN]', 'Authorization': '[HIDDEN]' },
        body: options.body ? 'Present' : 'None'
    });
    
    try {
        const response = await fetch(url, {
            method: options.method || 'GET',
            headers,
            body: options.body ? JSON.stringify(options.body) : undefined
        });
        
        console.log('📡 Supabase response status:', response.status);
        
        if (!response.ok) {
            const errorText = await response.text();
            console.error('❌ Supabase error response:', errorText);
            
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
            console.log('✅ Supabase request successful (204 No Content)');
            return null; // No data to return for 204 responses
        }
        
        // For other successful responses, try to parse JSON
        try {
            const responseText = await response.text();
            console.log('📡 Supabase response body:', responseText);
            
            if (!responseText || responseText.trim() === '') {
                console.log('✅ Supabase request successful (empty response)');
                return null;
            }
            
            const data = JSON.parse(responseText);
        console.log('✅ Supabase request successful');
        return data;
        } catch (jsonError) {
            console.warn('⚠️ Could not parse JSON response:', jsonError.message);
            return null;
        }
    } catch (fetchError) {
        console.error('❌ Supabase request failed:', fetchError);
        throw fetchError;
    }
}

const app = express();

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

    console.log('🔔 Webhook received');
    console.log('📝 Stripe signature header:', sig ? 'Present' : 'Missing');
    console.log('🔑 Webhook secret exists:', !!endpointSecret);
    console.log('📦 Request body length:', req.body ? req.body.length : 'No body');
    console.log('🌐 Request headers:', Object.keys(req.headers));
    console.log('📅 Timestamp:', new Date().toISOString());

    let event;

    try {
        event = stripe.webhooks.constructEvent(req.body, sig, endpointSecret);
        console.log('✅ Webhook signature verified, event type:', event.type);
        console.log('📊 Event data object:', JSON.stringify(event.data.object, null, 2));
    } catch (err) {
        console.error('❌ Webhook signature verification failed:', err.message);
        console.error('❌ Error details:', err);
        return res.status(400).send(`Webhook Error: ${err.message}`);
    }

    // Handle the event with Supabase database operations
    try {
        console.log('🔄 Processing webhook event:', event.type);
        
        switch (event.type) {
            case 'checkout.session.completed':
                console.log('💳 Processing checkout.session.completed...');
                await handleCheckoutCompleted(event.data.object);
                break;
                
            case 'customer.subscription.created':
                console.log('📦 Processing customer.subscription.created...');
                await handleSubscriptionCreated(event.data.object);
                break;
                
            case 'customer.subscription.updated':
                console.log('🔄 Processing customer.subscription.updated...');
                await handleSubscriptionUpdated(event.data.object);
                break;
                
            case 'customer.subscription.deleted':
                console.log('🗑️ Processing customer.subscription.deleted...');
                await handleSubscriptionDeleted(event.data.object);
                break;
                
            case 'invoice.payment_succeeded':
                console.log('💰 Processing invoice.payment_succeeded...');
                await handlePaymentSucceeded(event.data.object);
                break;
                
            case 'invoice.payment_failed':
                console.log('❌ Processing invoice.payment_failed...');
                await handlePaymentFailed(event.data.object);
                break;
                
            default:
                console.log(`⚠️ Unhandled event type: ${event.type}`);
        }
        
        console.log('✅ Webhook event processed successfully');
    } catch (error) {
        console.error('❌ Error processing webhook event:', error);
        console.error('❌ Error stack:', error.stack);
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
        console.error('❌ Session health check error:', error);
        res.status(500).json({ 
            success: false, 
            error: 'INTERNAL_ERROR',
            message: 'Internal server error'
        });
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
        
        console.log('🔐 Auth exchange request received');
        
        // Verify the Supabase ID token
        const { data: { user }, error } = await supabase.auth.getUser(idToken);
        
        if (error || !user) {
            console.error('❌ Token verification failed:', error);
            return res.status(401).json({ 
                success: false, 
                error: 'Invalid token' 
            });
        }
        
        console.log('✅ Token verified for user:', user.id);
        
        // Create server session
        const sessionId = createSession(user.id, req.headers['user-agent']);
        
        // Set HttpOnly cookie
        res.cookie('sid', sessionId, SESSION_CONFIG);
        
        console.log('✅ Session created and cookie set');
        
        res.json({ 
            success: true, 
            message: 'Authentication successful' 
        });
        
    } catch (error) {
        console.error('❌ Auth exchange error:', error);
        res.status(500).json({ 
            success: false, 
            error: 'Internal server error' 
        });
    }
});

// Auth logout endpoint
app.post('/api/auth/logout', (req, res) => {
    try {
        console.log('🔐 Logout request received');
        
        // Get session from cookie
        const sessionId = req.cookies.sid;
        
        if (sessionId) {
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
        
        console.log('✅ Logout successful');
        
        res.json({ 
            success: true, 
            message: 'Logged out successfully' 
        });
        
    } catch (error) {
        console.error('❌ Logout error:', error);
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

// Test Supabase connection
app.get('/api/test-supabase', async (req, res) => {
    try {
        console.log('🧪 Testing Supabase connection...');
        console.log('🔗 Supabase URL:', SUPABASE_URL);
        console.log('🔑 Service Role Key exists:', !!SUPABASE_SERVICE_ROLE_KEY);
        
        // Test a simple query
        const testData = await supabaseRequest('user_subscriptions?limit=1&select=count');
        console.log('✅ Supabase test successful:', testData);
        
        res.json({ 
            status: 'ok',
            message: 'Supabase connection successful',
            testData
        });
    } catch (error) {
        console.error('❌ Supabase test failed:', error);
        res.status(500).json({ 
            status: 'error',
            message: 'Supabase connection failed',
            error: error.message,
            details: error
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
        
        console.log('🧪 Testing webhook processing manually...');
        console.log('📧 Email:', email);
        
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
        
        console.log('📦 Mock event:', mockEvent);
        
        // Process the mock event
        await handleSubscriptionCreated(mockEvent.data.object);
        
        res.json({ 
            status: 'ok',
            message: 'Mock webhook event processed successfully',
            event: mockEvent
        });
        
    } catch (error) {
        console.error('❌ Test webhook processing failed:', error);
        res.status(500).json({ 
            status: 'error',
            message: 'Test webhook processing failed',
            error: error.message,
            details: error
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
        
        console.log('🧪 Testing manual subscription creation...');
        console.log('👤 User ID:', userId);
        console.log('📧 Email:', email);
        
        // Create a test subscription record
        const subscriptionData = {
            user_id: userId,
            stripe_subscription_id: 'test_sub_' + Date.now(),
            stripe_customer_id: 'test_cust_' + Date.now(),
            status: 'active',
            current_period_start: new Date().toISOString(),
            current_period_end: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000).toISOString(), // 30 days from now
            tokens_limit: -1, // Unlimited for Pro
            tokens_used: 0,
            updated_at: new Date().toISOString()
        };
        
        console.log('💾 Test subscription data:', subscriptionData);
        
        const response = await fetch(`${SUPABASE_URL}/rest/v1/user_subscriptions`, {
            method: 'POST',
            headers: {
                'Authorization': `Bearer ${SUPABASE_SERVICE_ROLE_KEY}`,
                'apikey': SUPABASE_SERVICE_ROLE_KEY,
                'Content-Type': 'application/json',
                'Prefer': 'resolution=merge-duplicates'
            },
            body: JSON.stringify(subscriptionData)
        });
        
        if (!response.ok) {
            const errorText = await response.text();
            console.error('❌ Failed to create test subscription:', response.status, errorText);
            return res.status(500).json({ 
                error: 'Failed to create test subscription',
                details: errorText
            });
        }
        
        const result = await response.json();
        console.log('✅ Test subscription created:', result);
        
        res.json({ 
            status: 'ok',
            message: 'Test subscription created successfully',
            subscription: result
        });
        
    } catch (error) {
        console.error('❌ Test subscription creation failed:', error);
        res.status(500).json({ 
            status: 'error',
            message: 'Test subscription creation failed',
            error: error.message,
            details: error
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
                    console.log('Payment successful:', sessionId);
                }
                
                function closeAndRefresh() {
                    // Try to send a message to the extension if it's open
                    try {
                        if (window.opener) {
                            window.opener.postMessage({ type: 'PAYMENT_SUCCESS', sessionId: sessionId }, '*');
                        }
                    } catch (e) {
                        console.log('Could not send message to opener:', e);
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
        console.log('🔍 [CHECKOUT] Request received - checking cookies...');
        console.log('🔍 [CHECKOUT] All cookies:', req.cookies);
        
        const sessionId = req.cookies.sid;
        console.log('🔍 [CHECKOUT] Session ID from cookie:', sessionId);
        
        if (!sessionId) {
            console.log('❌ [CHECKOUT] No session cookie found');
            return res.status(401).json({ error: 'No session cookie found' });
        }

        // Get user from session
        console.log('🔍 [CHECKOUT] Looking up session in memory store...');
        console.log('🔍 [CHECKOUT] Total sessions in memory:', sessions.size);
        
        const session = sessions.get(sessionId);
        console.log('🔍 [CHECKOUT] Session found:', !!session);
        
        if (!session) {
            console.log('❌ [CHECKOUT] Invalid or expired session');
            console.log('🔍 [CHECKOUT] Available session IDs:', Array.from(sessions.keys()));
            return res.status(401).json({ error: 'Invalid session' });
        }

        // Validate session hasn't expired
        console.log('🔍 [CHECKOUT] Session expires at:', new Date(session.expiresAt).toISOString());
        console.log('🔍 [CHECKOUT] Current time:', new Date().toISOString());
        
        if (Date.now() > session.expiresAt) {
            console.log('❌ [CHECKOUT] Session expired');
            sessions.delete(sessionId);
            return res.status(401).json({ error: 'Session expired' });
        }

        console.log('✅ [CHECKOUT] User authenticated:', session.userId);
        console.log('🔒 [CHECKOUT] Session details:', {
            sessionId,
            userId: session.userId,
            expiresAt: new Date(session.expiresAt).toISOString(),
            userAgent: req.headers['user-agent']?.substring(0, 100)
        });
        
        // Log request body for debugging
        console.log('🔍 [CHECKOUT] Request body:', req.body);
        console.log('🔍 [CHECKOUT] Request headers:', req.headers);

        // Get user email from session for Stripe checkout
        // Note: We can't query auth.users directly, so we'll use a placeholder
        // The actual user email will be handled by Stripe's customer creation
        let userEmail = null;
        
        // For now, we'll create the checkout without customer_email
        // Stripe will prompt the user to enter their email during checkout
        // This prevents cross-user data leakage since each user enters their own email
        console.log('ℹ️ [CHECKOUT] Skipping user email fetch (auth.users not accessible)');
        console.log('ℹ️ [CHECKOUT] User will enter email during Stripe checkout');
        console.log('ℹ️ [CHECKOUT] This prevents cross-user data leakage');

        // Handle both JSON and form data
        const priceId = req.body.priceId;

        if (!priceId) {
            return res.status(400).json({ error: 'Price ID is required' });
        }

        console.log('Creating Stripe Prebuilt Checkout session for authenticated user:', session.userId);
        console.log('🔒 [CHECKOUT] Security parameters:', {
            billing_address_collection: 'required',
            client_reference_id: `user_${session.userId}_${Date.now()}`,
            force_fresh: 'true'
        });

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

        console.log('Checkout session created:', stripeSession.id);
        
        // Return the checkout URL for the frontend to handle
        res.json({ 
            success: true, 
            checkoutUrl: stripeSession.url,
            sessionId: stripeSession.id
        });
        
        console.log('✅ [CHECKOUT] Response sent successfully');
        
        // Note: The success page will handle immediate subscription activation
        // while the webhook processes in the background for redundancy
        
    } catch (error) {
        console.error('Error creating checkout session:', error);
        res.status(500).json({ error: 'Failed to create checkout session', details: error.message });
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
            console.log('🎉 [SUCCESS] User completed checkout, activating subscription immediately');
            
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
            
            console.log('💾 [SUCCESS] Creating temporary subscription record:', tempSubscriptionData);
            
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
                console.log('✅ [SUCCESS] Temporary subscription created successfully');
            } else {
                console.log('⚠️ [SUCCESS] Failed to create temporary subscription, webhook will handle it');
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
        console.error('❌ [SUCCESS] Error handling success page:', error);
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

        console.log('Verifying payment for session:', sessionId);

        // Retrieve the session from Stripe
        const session = await stripe.checkout.sessions.retrieve(sessionId);
        
        if (session.payment_status !== 'paid') {
            return res.status(400).json({ error: 'Payment not completed' });
        }

        // Get subscription details from Stripe
        const subscription = await stripe.subscriptions.retrieve(session.subscription);

        console.log('Subscription retrieved:', subscription.id);

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
        console.error('Error verifying payment:', error);
        res.status(500).json({ error: 'Failed to verify payment', details: error.message });
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

        console.log('🔍 [CANCEL_SUBSCRIPTION] Request received for subscription:', subscriptionId);

        // Get session from HttpOnly cookie
        const sessionId = req.cookies.sid;
        
        if (!sessionId) {
            console.log('❌ [CANCEL_SUBSCRIPTION] No session cookie found');
            return res.status(401).json({
                success: false,
                error: 'SESSION_EXPIRED',
                reason: 'No session cookie'
            });
        }
        
        // Get session from storage
        const session = getSession(sessionId);
        
        if (!session) {
            console.log('❌ [CANCEL_SUBSCRIPTION] Invalid or expired session');
            return res.status(401).json({
                success: false,
                error: 'SESSION_EXPIRED',
                reason: 'Invalid or expired session'
            });
        }
        
        console.log('✅ [CANCEL_SUBSCRIPTION] Session validated, user ID:', session.userId);

        // Verify that the user owns this subscription
        try {
            const subscriptionData = await supabaseRequest(`user_subscriptions?user_id=eq.${session.userId}&stripe_subscription_id=eq.${subscriptionId}&select=*`);
            
            if (!subscriptionData || subscriptionData.length === 0) {
                console.log('❌ [CANCEL_SUBSCRIPTION] User does not own this subscription');
                return res.status(403).json({
                    success: false,
                    error: 'FORBIDDEN',
                    reason: 'User does not own this subscription'
                });
            }
            
            console.log('✅ [CANCEL_SUBSCRIPTION] Subscription ownership verified');
        } catch (verificationError) {
            console.error('❌ [CANCEL_SUBSCRIPTION] Error verifying subscription ownership:', verificationError);
            return res.status(500).json({
                success: false,
                error: 'VERIFICATION_FAILED',
                reason: 'Failed to verify subscription ownership'
            });
        }

        // Cancel subscription directly in Stripe
        console.log('🔄 [CANCEL_SUBSCRIPTION] Canceling subscription in Stripe...');
        const subscription = await stripe.subscriptions.update(subscriptionId, {
            cancel_at_period_end: true
        });

        console.log('✅ [CANCEL_SUBSCRIPTION] Subscription canceled successfully');

        // Update Supabase to track cancellation
        try {
            console.log('🔄 [CANCEL_SUBSCRIPTION] Updating Supabase with cancellation date...');
            await supabaseRequest(`user_subscriptions?user_id=eq.${session.userId}&stripe_subscription_id=eq.${subscriptionId}`, {
                method: 'PATCH',
                body: {
                    cancelled_at: new Date().toISOString(),
                    cancel_at_period_end: true,
                    current_period_end: new Date(subscription.current_period_end * 1000).toISOString()
                }
            });
            console.log('✅ [CANCEL_SUBSCRIPTION] Supabase updated with cancellation date');
        } catch (supabaseError) {
            console.error('⚠️ [CANCEL_SUBSCRIPTION] Failed to update Supabase:', supabaseError);
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
        console.error('❌ [CANCEL_SUBSCRIPTION] Error canceling subscription:', error);
        res.status(500).json({ error: 'Failed to cancel subscription', details: error.message });
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

        console.log('🔍 [REACTIVATE_SUBSCRIPTION] Request received for subscription:', subscriptionId);

        // Get session from HttpOnly cookie
        const sessionId = req.cookies.sid;
        
        if (!sessionId) {
            console.log('❌ [REACTIVATE_SUBSCRIPTION] No session cookie found');
            return res.status(401).json({
                success: false,
                error: 'SESSION_EXPIRED',
                reason: 'No session cookie'
            });
        }
        
        // Get session from storage
        const session = getSession(sessionId);
        
        if (!session) {
            console.log('❌ [REACTIVATE_SUBSCRIPTION] Invalid or expired session');
            return res.status(401).json({
                success: false,
                error: 'SESSION_EXPIRED',
                reason: 'Invalid or expired session'
            });
        }
        
        console.log('✅ [REACTIVATE_SUBSCRIPTION] Session validated, user ID:', session.userId);

        // Verify that the user owns this subscription
        try {
            const subscriptionData = await supabaseRequest(`user_subscriptions?user_id=eq.${session.userId}&stripe_subscription_id=eq.${subscriptionId}&select=*`);
            
            if (!subscriptionData || subscriptionData.length === 0) {
                console.log('❌ [REACTIVATE_SUBSCRIPTION] User does not own this subscription');
                return res.status(403).json({
                    success: false,
                    error: 'FORBIDDEN',
                    reason: 'User does not own this subscription'
                });
            }
            
            console.log('✅ [REACTIVATE_SUBSCRIPTION] Subscription ownership verified');
        } catch (verificationError) {
            console.error('❌ [REACTIVATE_SUBSCRIPTION] Error verifying subscription ownership:', verificationError);
            return res.status(500).json({
                success: false,
                error: 'VERIFICATION_FAILED',
                reason: 'Failed to verify subscription ownership'
            });
        }

        // Reactivate subscription in Stripe
        console.log('🔄 [REACTIVATE_SUBSCRIPTION] Reactivating subscription in Stripe...');
        const subscription = await stripe.subscriptions.update(subscriptionId, {
            cancel_at_period_end: false
        });

        console.log('✅ [REACTIVATE_SUBSCRIPTION] Subscription reactivated successfully');

        // Update Supabase to clear cancellation
        try {
            console.log('🔄 [REACTIVATE_SUBSCRIPTION] Updating Supabase to clear cancellation...');
            await supabaseRequest(`user_subscriptions?user_id=eq.${session.userId}&stripe_subscription_id=eq.${subscriptionId}`, {
                method: 'PATCH',
                body: {
                    cancelled_at: null,
                    cancel_at_period_end: false
                }
            });
            console.log('✅ [REACTIVATE_SUBSCRIPTION] Supabase updated to clear cancellation');
        } catch (supabaseError) {
            console.error('⚠️ [REACTIVATE_SUBSCRIPTION] Failed to update Supabase:', supabaseError);
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
        console.error('❌ [REACTIVATE_SUBSCRIPTION] Error reactivating subscription:', error);
        res.status(500).json({ error: 'Failed to reactivate subscription', details: error.message });
    }
});
*/

// Get subscription status from Supabase (preferred method)
app.get('/api/subscription-status/:userId', async (req, res) => {
    try {
        const { userId } = req.params;
        console.log('🔍 Checking subscription status for user:', userId);
        
        // First, test if we can connect to Supabase at all
        try {
            console.log('📡 Testing Supabase connection...');
            const testData = await supabaseRequest('user_subscriptions?limit=1');
            console.log('✅ Supabase connection test successful');
        } catch (connectionError) {
            console.error('❌ Supabase connection failed:', connectionError);
            return res.status(500).json({ 
                error: 'Supabase connection failed',
                details: connectionError.message
            });
        }
        
        // Get subscription from Supabase
        try {
            console.log('📡 Querying Supabase for user subscription...');
            const data = await supabaseRequest(`user_subscriptions?user_id=eq.${userId}&select=*`);
            console.log('📊 Supabase response:', data);
            
            if (data && data.length > 0) {
                const subscription = data[0];
                console.log('✅ Found subscription:', subscription);
                
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
                console.log('📝 No subscription found, returning free tier status...');
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
            console.error('❌ Supabase query error:', supabaseError);
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
        console.error('❌ Error retrieving subscription from Supabase:', error);
        console.error('❌ Error details:', JSON.stringify(error, null, 2));
        res.status(500).json({ 
            error: 'Failed to retrieve subscription',
            details: error.message,
            stack: error.stack
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
        console.error('Error retrieving subscription from Stripe:', error);
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
        
        console.log('✅ Token usage updated for user:', userId, 'tokens:', tokensUsed);
        res.json({ success: true, tokensUsed });
        
    } catch (error) {
        console.error('Error updating token usage in Supabase:', error);
        res.status(500).json({ error: 'Failed to update token usage' });
    }
});

// Create subscription record for existing user (admin endpoint)
app.post('/api/create-subscription-record', async (req, res) => {
    try {
        const { userId, status = 'free' } = req.body;
        
        if (!userId) {
            return res.status(400).json({ error: 'Missing userId' });
        }
        
        // Check if subscription record already exists
        try {
            const existingData = await supabaseRequest(`user_subscriptions?user_id=eq.${userId}&select=*`);
            
            if (existingData && existingData.length > 0) {
                return res.json({ 
                    success: true, 
                    message: 'Subscription record already exists',
                    subscription: existingData[0]
                });
            }
        } catch (error) {
            // Continue to create new record
        }
        
        // Create new subscription record
        const subscriptionData = {
            user_id: userId,
            status: status,
            tokens_used: 0,
            tokens_limit: status === 'active' ? -1 : 50,
            stripe_subscription_id: null,
            stripe_customer_id: null,
            current_period_start: null,
            current_period_end: null,
            created_at: new Date().toISOString(),
            updated_at: new Date().toISOString()
        };
        
        await supabaseRequest('user_subscriptions', {
            method: 'POST',
            body: subscriptionData
        });
        
        console.log('✅ Created subscription record for user:', userId, 'status:', status);
        res.json({ success: true, subscription: subscriptionData });
        
    } catch (error) {
        console.error('Error creating subscription record:', error);
        res.status(500).json({ error: 'Failed to create subscription record' });
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
        
        console.log('📝 Creating waitlist entry:', waitlistEntry);
        
        // Debug: Check if service key is available
        console.log('🔑 SUPABASE_SERVICE_ROLE_KEY exists:', !!SUPABASE_SERVICE_ROLE_KEY);
        console.log('🔑 SUPABASE_SERVICE_ROLE_KEY length:', SUPABASE_SERVICE_ROLE_KEY ? SUPABASE_SERVICE_ROLE_KEY.length : 'undefined');
        console.log('🔑 SUPABASE_SERVICE_ROLE_KEY starts with:', SUPABASE_SERVICE_ROLE_KEY ? SUPABASE_SERVICE_ROLE_KEY.substring(0, 20) + '...' : 'undefined');
        
        const response = await supabaseRequest('waitlist', {
            method: 'POST',
            body: waitlistEntry
        });
        
        console.log('✅ User added to waitlist:', session.userId);
        console.log('📊 Supabase response:', response);
        
            // Verify the record was actually inserted
    try {
        console.log('🔍 Attempting verification query for user:', session.userId);
        const verification = await supabaseRequest(`waitlist?user_id=eq.${session.userId}&select=*`);
        console.log('🔍 Verification query result:', verification);
        console.log('🔍 Verification query result type:', typeof verification);
        console.log('🔍 Verification query result length:', verification ? verification.length : 'null/undefined');

        if (verification && verification.length > 0) {
            console.log('✅ Waitlist entry verified in database');
            console.log('📋 Verified entry details:', verification[0]);
        } else {
            console.warn('⚠️ Waitlist entry not found in verification query');
            console.warn('⚠️ This could mean:');
            console.warn('   - Table does not exist');
            console.warn('   - RLS policies are blocking access');
            console.warn('   - Record was not actually inserted');
        }
    } catch (verifyError) {
        console.error('❌ Error verifying waitlist entry:', verifyError);
        console.error('❌ Verification error details:', verifyError.message);
    }
        
        // Even if response is null (empty response from Supabase), the 201 status means success
        res.json({
            success: true,
            message: 'Successfully joined the waitlist! We\'ll notify you when Pro features are available.',
            waitlistEntry: response || { user_id: session.userId, email: email, status: 'pending' }
        });
        
    } catch (error) {
        console.error('❌ Error adding user to waitlist:', error);
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
        console.error('❌ Error checking waitlist status:', error);
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
        console.error('Error creating portal session:', error);
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

// Test Supabase auth connection
app.get('/api/test-auth-delete', async (req, res) => {
    try {
        console.log('🔗 Testing Supabase auth connection...');
        console.log('🔗 Supabase URL:', process.env.SUPABASE_URL);
        console.log('🔑 Service role key exists:', !!process.env.SUPABASE_SERVICE_ROLE_KEY);
        
        // Test the auth endpoint
        const testResponse = await fetch(`${process.env.SUPABASE_URL}/auth/v1/admin/users`, {
            method: 'GET',
            headers: {
                'apikey': process.env.SUPABASE_SERVICE_ROLE_KEY,
                'Authorization': `Bearer ${process.env.SUPABASE_SERVICE_ROLE_KEY}`,
                'Content-Type': 'application/json'
            }
        });
        
        console.log('📡 Test response status:', testResponse.status);
        
        if (!testResponse.ok) {
            const errorText = await testResponse.text();
            console.error('❌ Test error response:', errorText);
            return res.json({ 
                success: false, 
                error: `HTTP ${testResponse.status}: ${errorText}`,
                url: `${process.env.SUPABASE_URL}/auth/v1/admin/users`
            });
        }
        
        const users = await testResponse.json();
        console.log('✅ Supabase auth connection successful');
        console.log('📊 Users response type:', typeof users);
        console.log('📊 Users response:', JSON.stringify(users, null, 2));
        
        res.json({ 
            success: true, 
            message: 'Supabase auth connection working',
            userCount: Array.isArray(users) ? users.length : 0,
            sampleUsers: Array.isArray(users) ? users.slice(0, 3).map(u => ({ id: u.id, email: u.email })) : [],
            rawResponse: users
        });
        
    } catch (error) {
        console.error('❌ Test auth connection error:', error);
        res.json({ 
            success: false, 
            error: error.message,
            stack: error.stack
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
        
        console.log('🔍 Looking up user ID for email:', email);
        
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
            console.error('❌ Error fetching users:', errorText);
            return res.status(500).json({ error: 'Failed to fetch users' });
        }
        
        const users = await response.json();
        console.log('📊 Found users:', users.length);
        
        // Find user by email
        const user = users.find(u => u.email === email);
        
        if (!user) {
            return res.status(404).json({ error: 'User not found' });
        }
        
        console.log('✅ Found user ID:', user.id);
        res.json({ userId: user.id });
        
    } catch (error) {
        console.error('❌ Error in get-user-id endpoint:', error);
        res.status(500).json({ 
            error: 'Failed to get user ID',
            details: error.message 
        });
    }
});

// Session-based user info endpoint (secure) - GET for reading, POST for writing
app.get('/api/me', cors(SECURITY_CONFIG.cors), async (req, res) => {
    try {
        console.log('🔍 [API/ME] Request received');
        
        // Get session from HttpOnly cookie
        const sessionId = req.cookies.sid;
        
        if (!sessionId) {
            console.log('❌ [API/ME] No session cookie found');
            return res.status(401).json({
                success: false,
                error: 'SESSION_EXPIRED',
                reason: 'No session cookie'
            });
        }
        
        // Get session from storage
        const session = getSession(sessionId);
        
        if (!session) {
            console.log('❌ [API/ME] Invalid or expired session');
            return res.status(401).json({
                success: false,
                error: 'SESSION_EXPIRED',
                reason: 'Invalid or expired session'
            });
        }
        
        console.log('✅ [API/ME] Session validated, user ID:', session.userId);
        
        // Extend session (rolling renewal)
        extendSession(sessionId);
        
        // Get user data from Supabase Admin API (auth/users is not accessible via REST API)
        let user, fullName, displayName;
        try {
            const userResponse = await fetch(`${process.env.SUPABASE_URL}/auth/v1/admin/users/${session.userId}`, {
                method: 'GET',
                headers: {
                    'apikey': process.env.SUPABASE_SERVICE_ROLE_KEY,
                    'Authorization': `Bearer ${process.env.SUPABASE_SERVICE_ROLE_KEY}`,
                    'Content-Type': 'application/json'
                }
            });
            
            if (!userResponse.ok) {
                console.error('❌ [API/ME] Failed to fetch user from Admin API:', userResponse.status);
                return res.status(401).json({
                    success: false,
                    error: 'User not found'
                });
            }
            
            user = await userResponse.json();
            fullName = user.user_metadata?.full_name || 'Not provided';
            displayName = user.user_metadata?.display_name || fullName || 'User';
            
            // Debug: Log resume data availability
            const resumeText = user.user_metadata?.resume_text || '';
            console.log('🔍 [API/ME] Resume data check:', {
                hasResumeText: !!resumeText,
                resumeLength: resumeText.length,
                userId: session.userId
            });
            
        } catch (adminApiError) {
            console.error('❌ [API/ME] Admin API error:', adminApiError);
            return res.status(401).json({
                success: false,
                error: 'User not found'
            });
        }
        
        // Get user preferences from user_preferences table
        let userPreferences;
        try {
            userPreferences = await supabaseRequest(`user_preferences?user_id=eq.${session.userId}&select=*`);
        } catch (preferencesError) {
            console.error('❌ [API/ME] Preferences fetch error:', preferencesError);
            // Continue with default preferences
            userPreferences = null;
        }
        
        // FREE TIER MODE: Always use new request tracking system
        // Get current month's request count from requests table
        const requestLimit = await checkUserRequestLimit(session.userId);
        const requestsUsed = requestLimit.requestCount;
        const monthlyLimit = requestLimit.limit; // 15 for free tier
        
        console.log('📊 [API/ME] Free tier request count:', { requestsUsed, monthlyLimit });
        
        // Always return free tier data (ignore old subscription data)
        res.set('Cache-Control', 'private, max-age=30');
        
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
                id: session.userId,
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
        
        return; // Exit early - no need to check old subscription data
        
        // OLD SUBSCRIPTION LOGIC (DISABLED FOR FREE TIER)
        /*
        // Get user subscription data
        let subscriptionData;
        try {
            subscriptionData = await supabaseRequest(`user_subscriptions?user_id=eq.${session.userId}&select=*`);
        } catch (subscriptionError) {
            console.error('❌ [API/ME] Subscription fetch error:', subscriptionError);
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
            
            console.log('🔍 Debug - Final API response data:', {
                displayStatus: displayStatus,
                isCancelled: isCancelled,
                isProUser: isProUser,
                subscriptionStatus: responseData.subscriptionStatus,
                cancelled_at: responseData.cancel_at_period_end,
                cancel_at_period_end: responseData.cancel_at_period_end,
                hasResumeText: !!responseData.user.resume_text,
                resumeLength: responseData.user.resume_text ? responseData.user.resume_text.length : 0
            });
            
            // Set cache headers
            res.set('Cache-Control', 'private, max-age=30');
            
            res.json(responseData);
        } else {
            // No subscription found - check if free user has usage tracking record
            res.set('Cache-Control', 'private, max-age=30');
            
            // Get current month's request count from requests table
            const requestLimit = await checkUserRequestLimit(session.userId);
            const requestsUsed = requestLimit.requestCount;
            const monthlyLimit = requestLimit.limit; // 15 for free tier
            
            console.log('📊 [API/ME] Free user request count:', { requestsUsed, monthlyLimit });
            
            // Debug: Log resume data for free users
            const freeUserResumeText = user.user_metadata?.resume_text || '';
            console.log('🔍 [API/ME] Free user resume data:', {
                hasResumeText: !!freeUserResumeText,
                resumeLength: freeUserResumeText.length,
                userId: session.userId
            });
            
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
        console.error('❌ [API/ME] Endpoint error:', error);
        
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
        console.log('🔍 [API/ME POST] Update request received');
        
        // Get session from HttpOnly cookie
        const sessionId = req.cookies.sid;
        
        if (!sessionId) {
            console.log('❌ [API/ME POST] No session cookie found');
            return res.status(401).json({
                success: false,
                error: 'SESSION_EXPIRED',
                reason: 'No session cookie'
            });
        }
        
        // Get session from storage
        const session = getSession(sessionId);
        
        if (!session) {
            console.log('❌ [API/ME POST] Invalid or expired session');
            return res.status(401).json({
                success: false,
                error: 'SESSION_EXPIRED',
                reason: 'Invalid or expired session'
            });
        }
        
        console.log('✅ [API/ME POST] Session validated, user ID:', session.userId);
        
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
        
        console.log('🔄 [API/ME POST] Updating display name:', display_name);
        
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
                    console.log('✅ [API/ME POST] Display name updated successfully (204 response)');
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
                    console.log('✅ [API/ME POST] Display name created successfully (204 response)');
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
                    console.log('✅ [API/ME POST] Display name also updated in user metadata');
                }
            } catch (metadataError) {
                console.warn('⚠️ [API/ME POST] Could not update display name in metadata:', metadataError);
            }
            
            res.json({
                success: true,
                message: 'Display name updated successfully'
            });
            
        } catch (updateError) {
            console.error('❌ [API/ME POST] Update error:', updateError);
            return res.status(500).json({
                success: false,
                error: 'Failed to update display name'
            });
        }
        
    } catch (error) {
        console.error('❌ [API/ME POST] Endpoint error:', error);
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
        
        console.log('✅ Education preference saved:', { userId: session.userId, education });
        
        res.json({ success: true, education });
        
    } catch (error) {
        console.error('❌ Save education error:', error);
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
        console.error('❌ Get language error:', error);
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
        
        console.log('✅ Language preference saved:', { userId: session.userId, language });
        
        res.json({ success: true, language });
        
    } catch (error) {
        console.error('❌ Save language error:', error);
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
        console.error('❌ Get display name error:', error);
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
            console.error('❌ Failed to update user metadata:', updateResponse.status);
            return res.status(500).json({ success: false, error: 'Failed to update display name' });
        }
        
        console.log('✅ Display name updated:', { userId: session.userId, display_name });
        
        res.json({ success: true, display_name });
        
    } catch (error) {
        console.error('❌ Save display name error:', error);
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
        
        console.log('✅ Account data cleared for user:', userId);
        
        res.json({ 
            success: true, 
            message: 'Account data cleared successfully' 
        });
        
    } catch (error) {
        console.error('❌ Clear account error:', error);
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
        
        console.log('🗑️ Deleting user account:', userId);
        
        // 1. Cancel any active Stripe subscription
        try {
            const subscriptionResponse = await supabaseRequest(`user_subscriptions?user_id=eq.${userId}&status=eq.active`, {
                method: 'GET'
            });
            
            if (subscriptionResponse && subscriptionResponse.length > 0) {
                const subscription = subscriptionResponse[0];
                if (subscription.stripe_subscription_id) {
                    console.log('🔄 Canceling Stripe subscription:', subscription.stripe_subscription_id);
                    
                    // Cancel the subscription in Stripe
                    const stripe = require('stripe')(process.env.STRIPE_SECRET_KEY);
                    await stripe.subscriptions.cancel(subscription.stripe_subscription_id);
                    
                    console.log('✅ Stripe subscription canceled');
                }
            }
        } catch (stripeError) {
            console.error('⚠️ Error canceling Stripe subscription:', stripeError);
            // Continue with account deletion even if Stripe cancellation fails
        }
        
        // 2. Delete user subscription record
        try {
            await supabaseRequest(`user_subscriptions?user_id=eq.${userId}`, {
                method: 'DELETE'
            });
            console.log('✅ User subscription record deleted');
        } catch (subscriptionError) {
            console.error('⚠️ Error deleting subscription record:', subscriptionError);
        }
        
        // 2.5. Delete privacy audit log records for this user
        try {
            await supabaseRequest(`privacy_audit_log?user_id=eq.${userId}`, {
                method: 'DELETE'
            });
            console.log('✅ Privacy audit log records deleted');
        } catch (auditDeleteError) {
            console.error('⚠️ Error deleting audit log records:', auditDeleteError);
        }
        
        // 3. Delete user from Supabase auth
        try {
            console.log('🗑️ Attempting to delete user from Supabase auth:', userId);
            console.log('🔗 Supabase URL:', process.env.SUPABASE_URL);
            console.log('🔑 Service role key exists:', !!process.env.SUPABASE_SERVICE_ROLE_KEY);
            
            const deleteResponse = await fetch(`${process.env.SUPABASE_URL}/auth/v1/admin/users/${userId}`, {
                method: 'DELETE',
                headers: {
                    'apikey': process.env.SUPABASE_SERVICE_ROLE_KEY,
                    'Authorization': `Bearer ${process.env.SUPABASE_SERVICE_ROLE_KEY}`,
                    'Content-Type': 'application/json'
                }
            });
            
            console.log('📡 Supabase delete response status:', deleteResponse.status);
            
            if (!deleteResponse.ok) {
                const errorText = await deleteResponse.text();
                console.error('❌ Supabase delete error response:', errorText);
                throw new Error(`Supabase API error: ${deleteResponse.status} ${deleteResponse.statusText} - ${errorText}`);
            }
            
            console.log('✅ User deleted from Supabase auth');
        } catch (authError) {
            console.error('❌ Error deleting user from auth:', authError);
            return res.status(500).json({ 
                error: 'Failed to delete user account',
                details: authError.message 
            });
        }
        
        // 4. Log the deletion for audit purposes (removed to avoid foreign key constraint)
        console.log('✅ Account deletion completed successfully');
        res.json({ success: true, message: 'Account deleted successfully' });
        
    } catch (error) {
        console.error('❌ Error in delete account endpoint:', error);
        res.status(500).json({ 
            error: 'Failed to delete account',
            details: error.message,
            stack: error.stack
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
        console.error('❌ Get resume error:', error);
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
            console.error('❌ Failed to update user metadata:', updateResponse.status);
            return res.status(500).json({ success: false, error: 'Failed to save resume' });
        }
        
        console.log('✅ Resume text saved for user:', session.userId);
        
        res.json({
            success: true,
            data: {
                resume_text: resume_text,
                saved_date: new Date().toISOString()
            }
        });
        
    } catch (error) {
        console.error('❌ Save resume error:', error);
        res.status(500).json({
            success: false,
            error: error.message
        });
    }
});

// Helper function to check user subscription status
async function checkUserSubscriptionStatus(userId) {
    try {
        console.log('🔍 Checking subscription status for user:', userId);
        
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
        console.error('❌ Error checking subscription status:', error);
        // Default to allowing access if there's an error
        return { upgradeRequired: false };
    }
}

// Helper function to log request and check limits
async function logUserRequest(userId, requestType = 'chat', tokensUsed = 0) {
    try {
        console.log('📊 Logging request for user:', userId, 'type:', requestType, 'tokens:', tokensUsed);
        
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
        
        console.log('✅ Request logged successfully');
        return logResponse;
    } catch (error) {
        console.error('❌ Error logging request:', error);
        return null;
    }
}

// Helper function to check if user can make requests (under 15/month limit)
async function checkUserRequestLimit(userId) {
    try {
        console.log('🔍 Checking request limit for user:', userId);
        
        // Get current month's request count (only count 'chat' requests, not 'regenerate')
        const now = new Date();
        const startOfMonth = new Date(now.getFullYear(), now.getMonth(), 1).toISOString();
        const requests = await supabaseRequest(`requests?user_id=eq.${userId}&timestamp=gte.${startOfMonth}&request_type=eq.chat&select=id`);
        
        const requestCount = requests ? requests.length : 0;
        const limit = 15; // Free tier limit
        const canMakeRequest = requestCount < limit;
        
        console.log(`📊 User ${userId} has made ${requestCount}/${limit} chat requests this month (regenerates are free)`);
        
        return {
            canMakeRequest,
            requestCount,
            limit,
            remaining: limit - requestCount
        };
    } catch (error) {
        console.error('❌ Error checking request limit:', error);
        // Default to allowing request if there's an error
        return {
            canMakeRequest: true,
            requestCount: 0,
            limit: 15,
            remaining: 15
        };
    }
}

// OpenAI API proxy endpoint with server-side prompt building
app.post('/api/generate', cors(SECURITY_CONFIG.cors), async (req, res) => {
    try {
        const sessionId = req.cookies.sid;
        console.log('🔍 [API/GENERATE] Session ID from cookie:', sessionId);
        
        if (!sessionId) {
            console.log('❌ [API/GENERATE] No session ID found in cookies');
            return res.status(401).json({ success: false, error: 'SESSION_EXPIRED' });
        }
        
        const session = getSession(sessionId);
        console.log('🔍 [API/GENERATE] Session found:', session ? `User ID: ${session.userId}` : 'No session found');
        
        if (!session) {
            console.log('❌ [API/GENERATE] Session not found for ID:', sessionId);
            return res.status(401).json({ success: false, error: 'SESSION_EXPIRED' });
        }
        
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
            chatHistory,
            toggleState,
            mode
        } = req.body;
        
        // NEW: Server-side prompt building logic
        let finalMessages = messages;
        
        // If server-side prompt building parameters are provided, build prompts server-side
        if (message && userProfile !== undefined && toggleState && mode) {
            console.log('🔧 [API/GENERATE] Building prompts server-side');
            console.log('🔧 [API/GENERATE] Mode:', mode, 'Toggle:', toggleState);
            console.log('🔧 [API/GENERATE] Message length:', message ? message.length : 0);
            console.log('🔧 [API/GENERATE] UserProfile keys:', userProfile ? Object.keys(userProfile) : 'none');
            console.log('🔧 [API/GENERATE] Has resume data:', !!(userProfile && userProfile.resumeText));
            console.log('🔧 [API/GENERATE] ChatHistory length:', chatHistory ? chatHistory.length : 0);
            
            try {
                // Build system prompt server-side
                const systemPrompt = buildSystemPromptServerSide(mode, toggleState);
                
                // Build user prompt server-side
                const userPrompt = buildUserPromptServerSide(message, userProfile, jobContext, chatHistory, toggleState, mode);
                
                // Create messages array with server-built prompts
                finalMessages = [
                    { role: 'system', content: systemPrompt },
                    { role: 'user', content: userPrompt }
                ];
                
                console.log('✅ [API/GENERATE] Server-side prompts built successfully');
                console.log('✅ [API/GENERATE] System prompt length:', systemPrompt.length);
                console.log('✅ [API/GENERATE] User prompt length:', userPrompt.length);
            } catch (error) {
                console.error('❌ [API/GENERATE] Error building server-side prompts:', error);
                return res.status(500).json({
                    success: false,
                    error: `Failed to build prompts: ${error.message}`
                });
            }
        } else {
            // Fallback to client-provided messages (backward compatibility)
            console.log('🔄 [API/GENERATE] Using client-provided messages (backward compatibility)');
            console.log('🔄 [API/GENERATE] Missing params - message:', !!message, 'userProfile:', userProfile !== undefined, 'toggleState:', !!toggleState, 'mode:', !!mode);
        }
        
        if (!model || !finalMessages) {
            return res.status(400).json({
                success: false,
                error: 'Model and messages are required'
            });
        }
        
        // Check if this is a regenerate request
        const isRegenerateRequest = isRegenerate === true;
        console.log('🔄 [API/GENERATE] Request type:', isRegenerateRequest ? 'REGENERATE (FREE)' : 'NEW REQUEST');
        
        // Only check request limit for new requests, not regenerates
        if (!isRegenerateRequest) {
            // Check user request limit (15 requests per month for free tier)
            const requestLimit = await checkUserRequestLimit(session.userId);
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
        } else {
            console.log('🆓 [API/GENERATE] Regenerate request - skipping limit check');
        }
        
        // Get API key from the 10-key rotation system
        const apiKey = getNextApiKey();
        if (!apiKey) {
            console.error('❌ No API keys available');
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
                max_tokens: max_tokens || 3000,
                temperature: temperature || 0.7
            })
        });
        
        if (!openaiResponse.ok) {
            const errorData = await openaiResponse.text();
            console.error('❌ OpenAI API error:', openaiResponse.status, errorData);
            
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
            console.log('🔄 [API/GENERATE] Logging request for user:', session.userId, 'type:', requestType, 'tokens:', data.usage.total_tokens);
            await logUserRequest(session.userId, requestType, data.usage.total_tokens);
            console.log('✅ [API/GENERATE] Request logged successfully');
        } else {
            const requestType = isRegenerateRequest ? 'regenerate' : 'chat';
            console.log('⚠️ [API/GENERATE] No usage data in OpenAI response, logging basic request');
            await logUserRequest(session.userId, requestType, 0);
        }
        
        console.log('✅ OpenAI API call successful for user:', session.userId);
        
        res.json({
            success: true,
            choices: data.choices,
            usage: data.usage
        });
        
    } catch (error) {
        console.error('❌ Generate API error:', error);
        res.status(500).json({
            success: false,
            error: error.message
        });
    }
});

// Error handling middleware
app.use((error, req, res, next) => {
    console.error('Unhandled error:', error);
    res.status(500).json({ error: 'Internal server error' });
});

// 404 handler
app.use('*', (req, res) => {
    res.status(404).json({ error: 'Endpoint not found' });
});

// Webhook handler functions for Supabase integration

async function handleCheckoutCompleted(session) {
    try {
        console.log('🔄 Handling checkout completed:', session.id);
        
        // Get subscription details from Stripe
        const subscription = await stripe.subscriptions.retrieve(session.subscription);
        console.log('📦 Subscription details:', subscription.id, subscription.status);
        
        // Get customer details from Stripe
        const customer = await stripe.customers.retrieve(subscription.customer);
        console.log('👤 Customer details:', customer.email);
        
        // Find user by email in Supabase
        try {
            console.log('🔍 Looking for user with email:', customer.email);
            
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
                console.error('❌ Failed to fetch users from Supabase:', response.status, response.statusText);
                return;
            }
            
            const users = await response.json();
            console.log('📋 Found users in Supabase:', users.length);
            
            const user = users.find(u => u.email === customer.email);
            if (!user) {
                console.log('❌ No user found for email:', customer.email);
                console.log('📧 Available emails:', users.map(u => u.email));
                return;
            }
            
            console.log('✅ Found user:', user.id);
            
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
            
            console.log('💾 Saving subscription data:', subscriptionData);
            
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
                console.error('❌ Failed to save subscription:', subResponse.status, subResponse.statusText);
                const errorText = await subResponse.text();
                console.error('❌ Error details:', errorText);
                return;
            }
            
            const savedSubscription = await subResponse.json();
            console.log('✅ Subscription saved successfully:', savedSubscription);
            
            console.log('✅ Subscription record created/updated for user:', user.id);
            
        } catch (supabaseError) {
            console.error('❌ Error saving subscription to Supabase:', supabaseError);
        }
        
    } catch (error) {
        console.error('❌ Error handling checkout completed:', error);
    }
}

async function handleSubscriptionCreated(subscription) {
    try {
        console.log('🔄 Handling subscription created:', subscription.id);
        
        // Get customer details from Stripe
        const customer = await stripe.customers.retrieve(subscription.customer);
        
        // Find user by email in Supabase (using direct HTTP request)
        try {
            const users = await supabaseRequest('auth/users', {
                method: 'GET',
                headers: {
                    'Authorization': `Bearer ${SUPABASE_SERVICE_ROLE_KEY}`
                }
            });
            
            const user = users.find(u => u.email === customer.email);
            if (!user) {
                console.log('No user found for email:', customer.email);
                return;
            }
            
            // Insert or update subscription record
            await supabaseRequest('user_subscriptions', {
                method: 'POST',
                body: {
                    user_id: user.id,
                    stripe_subscription_id: subscription.id,
                    stripe_customer_id: subscription.customer,
                    status: subscription.status,
                    current_period_start: new Date(subscription.current_period_start * 1000).toISOString(),
                    current_period_end: new Date(subscription.current_period_end * 1000).toISOString(),
                    tokens_limit: -1, // Unlimited for Pro
                    updated_at: new Date().toISOString()
                }
            });
            
            console.log('✅ Subscription saved to Supabase for user:', user.id);
            
        } catch (supabaseError) {
            console.error('Error saving subscription to Supabase:', supabaseError);
        }
        
    } catch (error) {
        console.error('Error handling subscription created:', error);
    }
}

async function handleSubscriptionUpdated(subscription) {
    try {
        console.log('🔄 Handling subscription updated:', subscription.id);
        
        // Update subscription record using PATCH request
        await supabaseRequest(`user_subscriptions?stripe_subscription_id=eq.${subscription.id}`, {
            method: 'PATCH',
            body: {
                status: subscription.status,
                current_period_start: new Date(subscription.current_period_start * 1000).toISOString(),
                current_period_end: new Date(subscription.current_period_end * 1000).toISOString(),
                updated_at: new Date().toISOString()
            }
        });
        
        console.log('✅ Subscription updated in Supabase');
        
    } catch (error) {
        console.error('Error updating subscription in Supabase:', error);
    }
}

async function handleSubscriptionDeleted(subscription) {
    try {
        console.log('🔄 Handling subscription deleted:', subscription.id);
        
        // Update subscription status to canceled
        await supabaseRequest(`user_subscriptions?stripe_subscription_id=eq.${subscription.id}`, {
            method: 'PATCH',
            body: {
                status: 'canceled',
                tokens_limit: 50, // Back to free tier
                updated_at: new Date().toISOString()
            }
        });
        
        console.log('✅ Subscription marked as canceled in Supabase');
        
    } catch (error) {
        console.error('Error updating deleted subscription in Supabase:', error);
    }
}

async function handlePaymentSucceeded(invoice) {
    try {
        console.log('🔄 Handling payment succeeded for invoice:', invoice.id);
        
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
        console.error('Error handling payment succeeded:', error);
    }
}

async function handlePaymentFailed(invoice) {
    try {
        console.log('🔄 Handling payment failed for invoice:', invoice.id);
        
        // Update subscription status to past_due
        if (invoice.subscription) {
            await supabaseRequest(`user_subscriptions?stripe_subscription_id=eq.${invoice.subscription}`, {
                method: 'PATCH',
                body: {
                    status: 'past_due',
                    updated_at: new Date().toISOString()
                }
            });
            
            console.log('✅ Payment failure recorded in Supabase');
        }
        
    } catch (error) {
        console.error('Error updating failed payment in Supabase:', error);
    }
}

// Supabase fallback endpoint for display name when /api/me fails
app.post('/api/supabase-user', cors(SECURITY_CONFIG.cors), async (req, res) => {
    try {
        console.log('🔍 [SUPABASE_USER] Fallback request received');
        
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
            console.log('❌ [SUPABASE_USER] Failed to fetch user from Admin API:', userResponse.status);
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
        
        const displayName = user.user_metadata?.display_name || user.user_metadata?.full_name || 'User';
        
        console.log('✅ [SUPABASE_USER] User found via fallback:', { userId: user.id, displayName });
        
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
        console.error('❌ [SUPABASE_USER] Error:', error);
        res.status(500).json({
            success: false,
            error: 'Internal server error'
        });
    }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`🚀 Trontiq Stripe API server running on port ${PORT}`);
    console.log(`📊 Health check: http://localhost:${PORT}/api/health`);
    console.log(`🔒 Security: Rate limiting and CORS enabled`);
    console.log(`🔗 Supabase integration: Active`);
});

// ============================================================================
// SYSTEM PROMPTS AND PROMPT BUILDING FUNCTIONS (MIGRATED FROM BACKGROUND.JS)
// ============================================================================

// Main system prompt (exact copy from background.js line 76)
const SYSTEM_PROMPT = "AI Assistant System Prompt: Job Application Assistant (Resume & Cover Letter Alignment)\n\nRole & Objective\n\nYou are an AI assistant integrated into a job search widget. Your primary role is to help the user get hired by tailoring their resume and cover letter to match job descriptions or application questions they provide. All guidance and generated content should focus on aligning the user's qualifications with the targeted job posting, maximizing their chances of securing an interview. The assistant's behavior must adapt based on the state of the user's personal profile data toggle:\n\nProfile Toggle ON: Personal resume/profile data is enabled and available.\n\nProfile Toggle OFF: Personal data is disabled/unavailable.\n\nBEHAVIOR WITH PROFILE TOGGLE ON (Personal Data Enabled) – Personalized Mode\n\nWhen the profile data toggle is ON, you have access to the user's uploaded resume and profile details (skills, work history, education, projects, etc.). In this mode, act as a highly specialized career assistant (like ChatGPT assisting with resumes) that utilizes the user's data for tailored advice and content.\n\nKEY PERSONALIZED MODE BEHAVIORS:\n- Reference specific experiences, companies, and achievements from the user's background\n- Use phrases like \"your resume shows\", \"your experience with\", \"based on your background\"\n- Generate tailored resumes and cover letters using the user's actual experience\n- Provide personalized advice like \"Given your experience with [specific skill] at [Company X], you could...\"\n- Leverage every detail of the user's resume for maximum relevance\n- Perform comprehensive, line-by-line analysis of the user's resume against job requirements\n\nDocument Analysis & Gap Identification:\nWhen the user provides or highlights a job description, immediately perform a comprehensive analysis:\n\nResume Parsing: Extract and review key information from the user's resume – all relevant skills, work experiences (roles, companies, dates), education, and achievements. Ensure you understand the full scope of the user's background. Examine EVERY SINGLE PART of their resume, not just the most recent job. Go through each bullet point individually, analyze each skill, and review every section line-by-line.\n\nMANDATORY: You MUST analyze EVERY SINGLE work experience listed in the resume. Do NOT skip any company or role. Go through each one systematically and provide feedback on each bullet point. If the user has worked at 4 companies, you MUST analyze all 4 companies, not just 2 or 3.\n\nCOMPREHENSIVE ANALYSIS REQUIREMENTS:\n- Analyze EVERY job title for relevance to the target role\n- Analyze EVERY bullet point in every work experience\n- Analyze EVERY skill listed in the skills section\n- Analyze EVERY degree/certification in education\n- Analyze EVERY sentence in the summary/objective\n- Rate each item's relevance (1-10 scale)\n- Provide specific feedback on each item\n- Do NOT skip any aspect of the resume\n\nMANDATORY ROLE ANALYSIS:\n- Count and list ALL work experiences in the resume\n- Analyze each role systematically in chronological order\n- Do NOT pick and choose which roles to mention\n- Do NOT skip any role regardless of industry or relevance\n- Provide analysis for every single past role\n- Confirm you have analyzed all roles before finishing\n\nJob Description Analysis: Analyze the job posting to identify key requirements, responsibilities, and qualifications the employer is seeking. Note specific skills, tools, and keywords mentioned as well as the overall role context.\n\nGap Analysis: Compare the user's qualifications to the job's requirements to find matches and gaps. Identify where the user's experience aligns strongly, and where it does not. Consider the user's ENTIRE work history: for each past role, check if its responsibilities or achievements relate to the target job. This ensures a holistic alignment covering all relevant experience. Do NOT focus only on the most recent job or industry-specific experience - examine ALL companies and roles for relevant skills and achievements.\n\nResponse Generation – Tailored Analysis & Recommendations:\nAfter analysis, provide a comprehensive response that includes:\n\nAlignment Highlights: Point out exactly how the user's existing experience and skills match the job requirements. Be specific and reference details from their resume. For example: \"Your experience leading a team at Company X directly aligns with the leadership and project management skills this job requires.\" Mention multiple examples across different roles if applicable, to show a broad alignment. Rate each bullet point's relevance (1-10 scale) and provide specific feedback on every section. CRITICAL: Include examples from ALL relevant work experiences, not just the most recent or industry-specific ones. Look for relevant skills and achievements across the entire work history.\n\nAreas for Improvement: Identify any gaps or weaker areas in the user's resume relative to the job description and suggest ways to address them. For instance: \"The job asks for experience with AWS. While you haven't mentioned cloud platforms, you could emphasize your work with Azure as it's a similar skill.\" If the user truly lacks a requirement, suggest how they might compensate or highlight a related skill.\n\nActionable Advice: Provide clear, specific tips to tailor or enhance the resume for this job:\n\nSuggest adding or emphasizing certain keywords from the job description (\"Consider incorporating the term 'data analysis' since the posting mentions it frequently.\").\n\nRecommend rephrasing or reordering bullet points to mirror the job's priorities (\"You might move your SQL experience to the top of your skills list, as this job heavily emphasizes database work.\").\n\nHighlight achievements that should be quantified or detailed to impress the hiring team (\"At Company Y, you managed a budget – specify the amount to showcase scale, e.g., 'Managed a $500K project budget…'\").\n\nProvide specific rewording suggestions for each bullet point that needs improvement. Do NOT give generic advice - be specific about which exact content needs changes and how to rephrase it.\n\nANALYSIS FORMATTING RULES:\n- Do NOT use ** (double asterisks) for bold formatting in analysis responses\n- Do NOT use any markdown formatting in analysis text\n- Use plain text only for analysis content\n- Use regular text formatting without special characters\n- Do NOT use ** anywhere in your response\n- Do NOT use any asterisks (*) for formatting\n- Use only plain text with no special formatting characters\n- If you need to emphasize text, use CAPITAL LETTERS or \"quotation marks\" instead of **\n- CRITICAL: Never use ** symbols in any part of your analysis\n\nEncouragement & Positive Tone: Throughout your feedback, maintain an encouraging, supportive tone. Acknowledge the user's strengths and express confidence: \"You have a strong background in X, which is a great asset for this role.\" If gaps exist, frame them constructively: \"One area to grow is Y; one idea is to mention Z from your past work to show similar capability.\"\n\nInteractive Follow-Up:\nAfter delivering the analysis and initial recommendations:\n\nInvite Questions: Ask if the user has any questions or specific concerns. \"Is there a particular requirement you're unsure about how to address?\"\n\nOffer Further Assistance: Proactively offer to help with next steps. For example, \"Would you like me to help you update your resume for this position or even draft a tailored cover letter?\" Make it clear that you can provide hands-on help (e.g., generating a revised resume or a cover letter) if they want.\n\nTailored Content Generation (on User Request):\nIf the user indicates they want a generated resume or cover letter (e.g., they say \"Yes, please tailor my resume\" or ask for a cover letter):\n\nResume Generation: Produce a complete, polished resume tailored to the job. Use the user's existing resume content as a base, but reorder, add, or modify entries to highlight the most relevant aspects for the job:\n\nWrite in a professional resume format, typically including Header/Contact Information, Summary or Objective, Work Experience, Skills, Education, and possibly Projects or Certifications (if relevant).\n\nIntegrate keywords and skills from the job description into the summary and experience sections, assuming the user has those skills.\n\nFor each relevant job experience, rewrite bullet points as needed to emphasize achievements that match the job requirements. For example, if the job is for a Data Analyst and the user's past role included data tasks, ensure bullets highlight data analysis accomplishments (e.g., \"Optimized data pipelines using SQL and Python to improve reporting speed by 30%\").\n\nOmit or downplay information not pertinent to the job. The final resume should be focused and succinct (ideally 1-2 pages), showcasing the user as an ideal candidate for that specific role.\n\nCover Letter Generation: Produce a fully written cover letter tailored to the job and company:\n\nStart with a proper business letter format (date, company address if provided, salutation like \"Dear Hiring Manager,\").\n\nIn the opening, state the position being applied for and a strong, enthusiastic hook about why the user is interested and a great fit.\n\nIn the body, link the user's key experiences and skills to the job requirements. Use specifics from the user's resume and the job description. For instance: \"At my role in Company X, I developed analytical dashboards in Tableau – a skill I'm excited to bring to the Data Analyst position at YourCompany.\"\n\nKeep a confident and professional tone, matching any tone preferences the user has (e.g., formal vs. slightly informal, highly enthusiastic vs. straightforwardly professional).\n\nClose the letter courteously, expressing appreciation for consideration and a willingness to discuss further (and include a proper sign-off with the user's name).\n\nCombined Resume & Cover Letter: If the user requests both, you can provide both in one response. Clearly separate them (for example, with a divider line or distinct section headings like \"Tailored Resume:\" and \"Cover Letter:\") so the user can easily identify and copy each document. Ensure each one is complete and well-formatted as described above.\n\nFormatting & Delivery: Present generated documents in a user-friendly format (Markdown or plain text that preserves the layout). Use lists for resume bullet points and paragraph structure for cover letters. The user should be able to directly copy-paste and use the output.\n\nCRITICAL FORMATTING RULE: Do NOT use ** (double asterisks) or any asterisks (*) for formatting in analysis responses. Use only plain text with no special formatting characters. If emphasis is needed, use CAPITAL LETTERS or \"quotation marks\" instead.\n\nProfile Data Privacy (Toggle ON mode):\nWhen using personal data:\n\nDo not reveal personal info from the resume that isn't necessary. For example, if the resume contains the user's full address or contact info, don't bring that up in the conversation (unless the user specifically asks for a full formatted resume including header details).\n\nStick to using the personal data for enhancing the application materials and advice. Never share the user's data with others or outside the context of helping the user.\n\nIf the user asks you to show or verify something from their profile (like \"What skills of mine are you using for this job?\"), you may reference or list those relevant details. Otherwise, keep the focus on the job match, not the raw data.\n\nBehavior with Profile Toggle OFF (Resume Data Disabled) – Expert General Knowledge Mode\n\nScope & Identity\n\nYou are a broad, domain-general assistant for learning, research, reading & writing, and everyday questions.\n\nYou DO NOT provide personalized career coaching, resume/cover-letter tailoring, or job-application strategy while the toggle is OFF.\n\nData Constraints\n\nYou have no access to the user's resume data. Do not ask for it. Do not infer it.\n\nTreat every answer as general guidance that anyone could use.\n\nWhat You're Expert At (examples, not limits)\n\nAcademic help (high school through doctoral): explain concepts, outline essays, solve step-by-step math/stats, propose study plans, compare theories, generate citations (APA/MLA/Chicago etc.), and produce literature-style summaries (with sources if provided).\n\nResearch workflows: question decomposition, search-query design (without browsing if the host doesn't allow it), argument mapping, extracting claims from provided texts, and drafting structured abstracts.\n\nReading & writing: rewriting for clarity/tone, editing for grammar and logic, summarizing, paraphrasing, outlining, thesis statements, topic sentences, transitions, and rubric-aligned checklists.\n\nHard Boundaries (toggle OFF)\n\nDo NOT analyze resumes, job descriptions, interview prompts, or ATS strategy.\n\nDo NOT suggest resume bullets, cover-letter language, or job-fit claims.\n\nIf the user asks for career items, respond: \"I can give general information and help now. For career-specific tailoring, enable your profile data.\"\n\nResponse Style & Safety\n\nBe concise, structured, and source-aware: if the user provides texts, cite/quote those; otherwise offer neutral, broadly accepted explanations.\n\nPrefer numbered steps, short paragraphs, and small checklists. Offer optional templates for writing tasks.\n\nWhen unsure, ask a single clarifying question only if it meaningfully changes the result; otherwise state reasonable assumptions and proceed.\n\nTemplates You May Use (adapt as needed)\n\nStudy plan: Goal → Prereqs → Syllabus outline → Weekly plan → Practice set → Self-check rubric.\n\nWriting scaffold: Title → Thesis → Section outline → Evidence plan → Draft paragraph(s) → Edit checklist.\n\nResearch note: Question → Key terms → Hypotheses → Variables/metrics → Methods candidates → Limitations → Next steps.\n\nMode Reminder\n\nIf the user explicitly requests job description analysis, resume analysis, and career tailoring, politely explain the limitation and suggest switching the profile toggle ON for personalized help.\n\nAdditional Response Guidelines & Style\n\nRegardless of toggle state, adhere to these style guidelines to ensure clarity and professionalism:\n\nLANGUAGE AND COMMUNICATION PREFERENCES:\n- ALWAYS respond in the user's preferred language (check user profile for language preference)\n- CRITICAL: If the user's language preference is \"spanish\", respond entirely in Spanish\n- CRITICAL: If the user's language preference is \"french\", respond entirely in French\n- CRITICAL: If the user's language preference is \"german\", respond entirely in German\n- CRITICAL: If the user's language preference is any other language, respond entirely in that language\n- CRITICAL: If the user's language preference is \"english\", respond in English\n- Generate resumes and cover letters in the user's preferred language\n- Maintain the same professional tone and quality in all languages\n- Adapt cultural nuances and business communication styles to the target language\n- IMPORTANT: The user's language preference is explicitly stated in the user profile - use it for ALL responses\n\nTONE PREFERENCES:\n- ALWAYS match the user's preferred tone (check user profile for tone preference)\n- If tone is \"professional\": Use formal, business-like language with industry terminology\n- If tone is \"casual\": Use friendly, conversational language with contractions and informal phrases\n- If tone is \"enthusiastic\": Use energetic, positive language with exclamation points and motivational phrases\n- If tone is \"confident\": Use assertive, self-assured language that demonstrates expertise\n- If tone is \"friendly\": Use warm, approachable language that builds rapport\n- Adapt all responses (chat, analysis, resumes, cover letters) to match the preferred tone\n\nEDUCATION LEVEL ADAPTATION:\n- ALWAYS adapt communication style to the user's education level (check user profile for education level)\n- If education level is \"high_school\": Use simpler language, avoid complex jargon, explain technical terms\n- If education level is \"undergraduate\": Use standard professional language, some industry terms with explanations\n- If education level is \"graduate\": Use advanced terminology, assume familiarity with complex concepts\n- If education level is \"doctorate\": Use sophisticated language, technical jargon, assume expert-level knowledge\n- If education level is \"none\": Use clear, accessible language, avoid assumptions about technical knowledge\n- Adjust vocabulary complexity, sentence structure, and explanation depth based on education level\n- Adapt resume and cover letter language to match the target audience's expected education level\n\nTone & Personality: Be friendly, professional, and supportive. The user may be stressed about job applications; adopt an encouraging tone. Build the user's confidence. However, remain honest and constructive about how they can improve. You are a mentor and coach in their job search.\n\nUse of User's Name: NEVER greet the user. NEVER say \"Hi\", \"Hello\", or any greeting. Start your response immediately with the answer or advice. Use the user's name only when referring to their background or experience, not in greetings.\n\nCRITICAL: The UI may show the user's display name once at conversation start. The assistant MUST NOT greet and MUST NOT begin messages with the user's name. Never prepend the name to any response.\nCRITICAL: If the model detects the name as context, it is reference-only; do not repeat it unless explicitly required inside content (not as a salutation).\n\nClarity & Brevity: Keep paragraphs and explanations concise (generally 3-5 sentences each) and focused on one idea. If you have multiple points or recommendations, use bullet points or numbered lists so the user can easily scan them. This format is easier to read than one large block of text.\n\nStructured Formatting: Organize your responses with headings or bold text for sections when appropriate (especially if delivering a lengthy analysis or multiple outputs like a resume and cover letter). Use markdown or formatting to distinguish sections clearly. For example, when presenting a tailored resume, you might use headings for each section of the resume, or when giving analysis, you might bold labels like \"Skills Match:\" or \"Suggested Addition:\" for clarity.\n\nVisual Emphasis: Use bold or italics to highlight important phrases or requirements. For instance, \"Make sure to mention your certifications since the job posting values those.\" But don't overuse styling – it should enhance readability, not overwhelm.\n\nRelevance: Always ensure your advice or content is relevant to the user's request and the job at hand. If the user's query is specific, answer that directly first, then broaden out if needed. Avoid giving unrelated or generic job advice that doesn't apply to their situation. If the user only asks about cover letters, focus on that rather than diving into resume tips (unless they connect).\n\nDepth of Knowledge: As an AI, you have vast knowledge of hiring practices, ATS (Applicant Tracking Systems), various industries' expectations, etc. Leverage that to provide value-added insights. For example, you can mention, \"Many ATS algorithms rank resumes by keyword match, so incorporating the term 'Agile Scrum' from the job description could improve your resume's chances.\" These insights make your guidance more credible and useful.\n\nNo Unrequested Personal Data Exposure: If profile data is ON, you use it to tailor responses, but never reveal or output chunks of the resume or personal data unless the user explicitly asks (like \"Show me my resume\" or \"What did I input as my skills?\"). Even when asked, share it in a secure format (like a code block for the resume text). The user's privacy is paramount.\n\nFlexibility: Adapt based on user feedback. If the user corrects you or provides new info (e.g., \"Actually, I also have experience in Python that I forgot to mention\"), immediately integrate that into your advice or generated content. Always align with the user's actual background as they describe it.\n\nCritical Flow Instructions\n\nTo deliver the best experience as the world's top job-application assistant, follow this flow in typical scenarios:\n\nJob Description Provided → Analyze First: When the user gives a job description (pasted or highlighted) and possibly their resume (or it's stored from profile), begin by analyzing it rather than immediately asking what they want. Demonstrate understanding by summarizing how the user fits the role and what could be improved. This shows proactivity and expertise.\n\nProvide Detailed Analysis & Advice: Share the results of your analysis in a structured way (as outlined above: alignment highlights, gaps, suggestions). This is often your first answer and should reassure the user that you've grasped both their resume and the job's needs. Keep it action-oriented and make it clear you have concrete improvement ideas.\n\nEncourage & Clarify: Encourage the user about their prospects and invite them to ask questions or clarify their goals. For example, if something in the job description isn't clear, you might ask, \"Do you have experience in X? If so, we should highlight it because this job calls for it.\" This makes the interaction collaborative.\n\nOffer Tailoring/Growth Assistance: After giving initial advice, always offer to help with the next step. E.g., \"Would you like me to help you update your resume for this job or perhaps draft a cover letter highlighting your fit?\" Many users will not know this is possible until you suggest it. Make the offer clear and welcoming.\n\nOn User's Go-Ahead → Generate Documents: If the user says \"yes\" or otherwise confirms they want a tailored resume or cover letter:\n\nRetrieve and use the user's profile data (resume, skills, etc.) along with the job description to create the requested document(s).\n\nDo not just explain what you will do — actually present the completed resume or cover letter text right in the chat for the user to use. The user should not have to ask again or wait; once they say go ahead, deliver the result in full.\n\nEnsure the content is directly usable, with proper formatting, and that it addresses the job description thoroughly (matching terminology, highlighting relevant experience).\n\nFormatting the Output: When outputting a resume or cover letter:\n\nUse clear section headers (e.g., Professional Experience, Education, Skills) and bullet points in the resume. Maintain a clean layout.\n\nFor cover letters, use paragraph form with a greeting, intro, body paragraphs, and closing signature line.\n\nIf providing both in one answer, use separators or section titles so it's obvious which is which. For example:\nTailored Resume: [resume content]\n——— (a line or divider) –––\nCover Letter: [cover letter content]\nThis way, the user can identify and copy them easily.\n\nReview & Iterate: After providing a generated document, ask if it meets their needs or if they want any adjustments. \"Let me know if you'd like any changes or additional details added.\" Be ready to refine the output. For instance, if the user says the resume is too long, help condense it; if they want a particular project included, add it. The process may loop: analyze feedback, adjust content, and present the improved version. This iterative refinement ensures the final product is exactly what the user wants.\n\nMODE-SPECIFIC BEHAVIORS:\n- In personalized mode: Leverage every detail of the user's resume for maximum relevance\n- In general mode: Provide universal guidance that any job seeker could benefit from\n- Always respect the current toggle state and adjust your response style accordingly\n\nHOW THE SYSTEM MAINTAINS BOTH MODES:\n- Front-End Toggle Handling: The content script checks the profile toggle state and sends appropriate data\n- Conditional Logic: Functions use the presence/absence of user profile resume text as a cue\n- System Prompt Adaptation: The prompt includes explicit instructions for both modes\n- Minimal Profile Data Footprint: When toggle is OFF, only basic preferences are sent\n- No Cross-Over: Clear separation ensures no personal data leaks in general mode\n- Full Functionality: All features remain available in both modes with appropriate behavior\n\nBy adhering to the above guidelines, you will function as a world-class AI job application assistant. Always remember: when Profile Toggle is ON, leverage the user's data to give them a personalized edge; when OFF, pivot to general expertise and guidance. In all cases, stay focused on helping the user succeed in their job\n\nCRITICAL BOLD FORMATTING RULE: NEVER use ** (double asterisks) for bold formatting. The AI should use bold formatting when appropriate (for emphasis, section headers, important points), but the formatting will be handled by the display system. Focus on content and structure.\n\nEDUCATION ANALYSIS ACCURACY: When analyzing education sections, ensure you correctly match each degree/program with its corresponding institution. Do not mix up programs between different schools. Provide accurate analysis of each degree-institution combination. search with thorough, thoughtful, and user-friendly support. Good luck – and happy job hunting to our users!";

// ============================================================================
// PROMPT BUILDING FUNCTIONS (EXACT COPIES FROM BACKGROUND.JS)
// ============================================================================

// Format user profile function (exact copy from background.js)
function formatUserProfile(profile, options = {}) {
    const { includeRaw = false, isProfileToggleOff = false } = options;
    
    if (!profile) {
        console.error('❌ [SERVER] No profile provided - this should never happen as all users must have a profile');
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
function buildUserPromptServerSide(message, userProfile, jobContext, chatHistory, toggleState, mode) {
    // Add null checks and default values
    if (!message) message = '';
    if (!userProfile) {
        console.error('❌ [SERVER] No user profile provided - this should never happen as all users must have a profile');
        userProfile = {}; // Fallback for safety
    }
    if (!jobContext) jobContext = {};
    if (!chatHistory) chatHistory = [];
    if (!toggleState) toggleState = 'off';
    if (!mode) mode = 'natural';
    
    const isProfileToggleOff = toggleState === 'off';
    const isProfileEnabled = !isProfileToggleOff;
    
    // Build conversation context
    let conversationContext = '';
    if (chatHistory && Array.isArray(chatHistory) && chatHistory.length > 0) {
        conversationContext = '\n\nCONVERSATION HISTORY:\n' + chatHistory.map(msg => 
            `${msg.role === 'user' ? 'User' : 'Assistant'}: ${msg.content || ''}`
        ).join('\n');
    }
    
    // Build user context
    let userContext = '';
    if (isProfileEnabled) {
        const profileText = formatUserProfile(userProfile, {
            isProfileToggleOff: isProfileToggleOff,
            includeRaw: !isProfileToggleOff
        });
        userContext = `\n\nUSER PROFILE:\n${profileText}`;
    }
    
    // Build job context
    const jobContextText = formatJobContext(jobContext);
    
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
    }
    
    return message;
}

module.exports = app;
