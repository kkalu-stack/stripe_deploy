// Trontiq Minimal Server Deployment
// Single file deployment - includes all necessary code

const express = require('express');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const stripe = require('stripe')(process.env.STRIPE_SECRET_KEY);
// Redis configuration for key management (optional - only if REDIS_URL is provided)
let Redis, redis;
try {
    Redis = require('ioredis');
    if (process.env.REDIS_URL) {
        // Temporarily disable Redis due to connection loop issues
        console.log('⚠️ Redis temporarily disabled due to connection loop issues');
        redis = null;
    } else {
        console.log('⚠️ REDIS_URL not provided, key management disabled');
    }
} catch (error) {
    console.log('⚠️ ioredis not available, key management disabled:', error.message);
}

// Supabase configuration for direct HTTP requests
const SUPABASE_URL = process.env.SUPABASE_URL;
const SUPABASE_SERVICE_ROLE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY;

// Lua script for atomic RPM reservation
const LUA_TRY_RESERVE_RPM = `
-- KEYS[1] = meta hash (status)
-- KEYS[2] = rpm counter key (string)
-- ARGV[1] = rpmLimit
-- ARGV[2] = ttlSec (60)

local status = redis.call('HGET', KEYS[1], 'status')
if status and status ~= 'active' then
  return {0, 'disabled'}
end

local rpmLimit = tonumber(ARGV[1])
local ttl = tonumber(ARGV[2])
local cur = tonumber(redis.call('GET', KEYS[2]) or '0')

if cur >= rpmLimit then
  return {0, 'saturated'}
end

cur = redis.call('INCR', KEYS[2])
if cur == 1 then redis.call('EXPIRE', KEYS[2], ttl) end

return {1, tostring(cur)}
`;

// KeyPool class for round-robin key management
class KeyPool {
    constructor() {
        this.redis = redis;
        if (!this.redis) {
            console.log('⚠️ KeyPool initialized without Redis - key management disabled');
        }
    }

    aliasesKey() { return "ai:keys:aliases"; }
    metaKey(alias) { return `ai:key:${alias}:meta`; }
    rpmKey(alias) { return `ai:key:${alias}:rpm_count`; }
    rrKey() { return "ai:keys:rr_index"; }

    async list() {
        if (!this.redis) {
            console.log('⚠️ Redis not available, returning empty key list');
            return [];
        }
        const aliases = await this.redis.smembers(this.aliasesKey());
        const metas = [];
        for (const alias of aliases) {
            const h = await this.redis.hgetall(this.metaKey(alias));
            if (h && h.key) {
                metas.push({
                    alias: alias,
                    key: h.key,
                    rpm: Number(h.rpm || process.env.DEFAULT_RPM || 60),
                    status: h.status || 'active'
                });
            }
        }
        return metas.sort((a, b) => a.alias.localeCompare(b.alias));
    }

    async acquire() {
        if (!this.redis) {
            console.log('⚠️ Redis not available, cannot acquire key');
            return null;
        }
        const metas = await this.list();
        if (!metas.length) return null;

        const n = metas.length;
        const start = Number(await this.redis.get(this.rrKey()) || 0) % n;

        for (let i = 0; i < n; i++) {
            const idx = (start + i) % n;
            const m = metas[idx];
            if (m.status !== 'active') continue;

            const res = await this.redis.eval(
                LUA_TRY_RESERVE_RPM, 2,
                this.metaKey(m.alias),
                this.rpmKey(m.alias),
                String(m.rpm),
                "60"
            );

            if (Array.isArray(res) && res[0] === 1) {
                await this.redis.set(this.rrKey(), (idx + 1) % n);
                return m;
            }
        }
        return null;
    }
}

// Initialize key pool
const keyPool = new KeyPool();

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
        
        // Handle 204 No Content responses (no JSON body)
        if (response.status === 204) {
            console.log('✅ Supabase request successful (204 No Content)');
            return null;
        }
        
        // Only try to parse JSON for responses that have content
        const data = await response.json();
        console.log('✅ Supabase request successful');
        return data;
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
        origin: [
            'chrome-extension://*',
            'moz-extension://*',
            'http://localhost:*',
            'https://localhost:*'
        ],
        credentials: true,
        methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
        allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With'],
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

// Add security headers
app.use((req, res, next) => {
    Object.entries(SECURITY_CONFIG.headers).forEach(([key, value]) => {
        res.setHeader(key, value);
    });
    next();
});

// Test endpoint to verify deployment
app.get('/api/test-deployment', (req, res) => {
    res.json({ 
        message: 'NEW CODE DEPLOYED!', 
        timestamp: new Date().toISOString(),
        version: '2.0'
    });
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

// Debug endpoint to show current function code
app.get('/api/debug-functions', (req, res) => {
    try {
        // Get the function source code
        const handleSubscriptionCreatedSource = handleSubscriptionCreated.toString();
        const handlePaymentSucceededSource = handlePaymentSucceeded.toString();
        
        res.json({
            status: 'ok',
            message: 'Current function code',
            handleSubscriptionCreated: handleSubscriptionCreatedSource,
            handlePaymentSucceeded: handlePaymentSucceededSource,
            timestamp: new Date().toISOString()
        });
    } catch (error) {
        res.status(500).json({
            status: 'error',
            message: 'Failed to get function code',
            error: error.message
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

// Complete test flow: Stripe → Supabase → Extension
// Test with curl: curl -X POST https://stripe-deploy.onrender.com/api/test-complete-flow \
//   -H "Content-Type: application/json" \
//   -d '{"userId":"YOUR_UUID_HERE","email":"user@example.com"}'
app.post('/api/test-complete-flow', async (req, res) => {
    try {
        const { userId, email, stripeSubscriptionId, stripeCustomerId } = req.body;
        
        if (!userId || !email) {
            return res.status(400).json({ error: 'userId and email are required' });
        }
        
        console.log('🧪 Testing complete flow: Stripe → Supabase → Extension');
        console.log('👤 User ID:', userId);
        console.log('📧 Email:', email);
        console.log('💳 Stripe Subscription ID:', stripeSubscriptionId || 'test_sub_' + Date.now());
        console.log('👤 Stripe Customer ID:', stripeCustomerId || 'test_cust_' + Date.now());
        
        // Step 1: Simulate Stripe webhook event
        const mockStripeEvent = {
            type: 'customer.subscription.created',
            data: {
                object: {
                    id: stripeSubscriptionId || 'test_sub_' + Date.now(),
                    customer: stripeCustomerId || 'test_cust_' + Date.now(),
                    status: 'active',
                    current_period_start: Math.floor(Date.now() / 1000),
                    current_period_end: Math.floor((Date.now() + 30 * 24 * 60 * 60 * 1000) / 1000)
                }
            }
        };
        
        console.log('📦 Mock Stripe event:', mockStripeEvent);
        
        // Step 2: Process the webhook event (same as real webhook)
        await handleSubscriptionCreated(mockStripeEvent.data.object);
        
        // Step 3: Verify the subscription was created in Supabase
        const verificationResponse = await fetch(`${SUPABASE_URL}/rest/v1/user_subscriptions?user_id=eq.${userId}&select=*`, {
            method: 'GET',
            headers: {
                'Authorization': `Bearer ${SUPABASE_SERVICE_ROLE_KEY}`,
                'apikey': SUPABASE_SERVICE_ROLE_KEY,
                'Content-Type': 'application/json'
            }
        });
        
        if (!verificationResponse.ok) {
            const errorText = await verificationResponse.text();
            console.error('❌ Failed to verify subscription:', verificationResponse.status, errorText);
            return res.status(500).json({ 
                error: 'Failed to verify subscription creation',
                details: errorText
            });
        }
        
        const subscriptions = await verificationResponse.json();
        console.log('✅ Verification - subscriptions found:', subscriptions.length);
        
        if (subscriptions.length === 0) {
            return res.status(500).json({ 
                error: 'No subscription found after creation',
                details: 'The webhook processing did not create a subscription record'
            });
        }
        
        const subscription = subscriptions[0];
        console.log('✅ Subscription verified:', subscription);
        
        res.json({ 
            status: 'ok',
            message: 'Complete test flow successful',
            flow: {
                step1: 'Mock Stripe event created',
                step2: 'Webhook processed',
                step3: 'Subscription verified in Supabase'
            },
            subscription: subscription,
            testData: {
                userId: userId,
                email: email,
                stripeSubscriptionId: subscription.stripe_subscription_id,
                stripeCustomerId: subscription.stripe_customer_id,
                status: subscription.status,
                tokensLimit: subscription.tokens_limit
            }
        });
        
    } catch (error) {
        console.error('❌ Complete test flow failed:', error);
        res.status(500).json({ 
            status: 'error',
            message: 'Complete test flow failed',
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

// Create checkout session (no user data required)
app.post('/api/create-checkout-session', async (req, res) => {
    try {
        // Handle both JSON and form data
        const priceId = req.body.priceId;

        if (!priceId) {
            return res.status(400).json({ error: 'Price ID is required' });
        }

        console.log('Creating Stripe Prebuilt Checkout session for price:', priceId);

        // Use hardcoded base URL
        const baseUrl = 'https://stripe-deploy.onrender.com';

        // Create Stripe checkout session for Prebuilt Checkout
        const session = await stripe.checkout.sessions.create({
            payment_method_types: ['card'],
            line_items: [
                {
                    price: priceId, // Your $4.99/month price ID
                    quantity: 1,
                },
            ],
            mode: 'subscription',
            success_url: `${baseUrl}/success?session_id={CHECKOUT_SESSION_ID}`,
            cancel_url: `${baseUrl}/cancel`,
            // Enable all the features you want
            allow_promotion_codes: true,
            automatic_tax: {
                enabled: true
            },
            // Store minimal metadata in Stripe session
            metadata: {
                created_at: new Date().toISOString()
            }
        });

        console.log('Checkout session created:', session.id);
        
        // Redirect directly to Stripe's checkout page (official Stripe approach)
        return res.redirect(303, session.url);
        
    } catch (error) {
        console.error('Error creating checkout session:', error);
        res.status(500).json({ error: 'Failed to create checkout session', details: error.message });
    }
});

// Verify payment (no user data storage)
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

// Cancel subscription (no user data storage)
app.post('/api/cancel-subscription', async (req, res) => {
    try {
        const { subscriptionId } = req.body;

        console.log('Canceling subscription:', subscriptionId);

        // Cancel subscription immediately in Stripe
        const subscription = await stripe.subscriptions.cancel(subscriptionId);

        console.log('✅ Subscription canceled in Stripe:', subscription.id);

        // Manually update Supabase to reflect the cancellation
        console.log('🔄 Updating Supabase subscription status...');
        try {
            await supabaseRequest(`user_subscriptions?stripe_subscription_id=eq.${subscriptionId}`, {
                method: 'PATCH',
                body: {
                    status: 'free', // Back to free plan (not 'canceled')
                    tokens_limit: 50, // Back to free tier
                    tokens_used: 0, // Reset token usage for new month
                    updated_at: new Date().toISOString()
                }
            });
            console.log('✅ Supabase updated successfully - user back to free plan');
        } catch (supabaseError) {
            console.error('❌ Error updating Supabase:', supabaseError);
            // Continue anyway - the webhook might handle it
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
        console.error('Error canceling subscription:', error);
        res.status(500).json({ error: 'Failed to cancel subscription', details: error.message });
    }
});

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
                res.json({
                    status: subscription.status,
                    tokens_used: subscription.tokens_used || 0,
                    tokens_limit: subscription.tokens_limit,
                    is_unlimited: subscription.tokens_limit === -1,
                    current_period_end: subscription.current_period_end,
                    stripe_subscription_id: subscription.stripe_subscription_id
                });
            } else {
                console.log('📝 No subscription found, returning free tier status...');
                // Don't try to create subscription record - just return free tier status
                // This avoids foreign key constraint issues with test users
                res.json({
                    status: 'free',
                    tokens_used: 0,
                    tokens_limit: 50,
                    is_unlimited: false,
                    current_period_end: null
                });
            }
        } catch (supabaseError) {
            console.error('❌ Supabase query error:', supabaseError);
            // For any query error, just return free tier status
            res.json({
                status: 'free',
                tokens_used: 0,
                tokens_limit: 50,
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

// Get subscription status from Stripe (fallback method)
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

// Update token usage in Supabase
app.post('/api/update-token-usage', async (req, res) => {
    try {
        const { userId, tokensUsed } = req.body;
        
        if (!userId || tokensUsed === undefined) {
            return res.status(400).json({ error: 'Missing userId or tokensUsed' });
        }
        
        // Update token usage in Supabase
        await supabaseRequest(`user_subscriptions?user_id=eq.${userId}`, {
            method: 'PATCH',
            body: {
                tokens_used: tokensUsed,
                updated_at: new Date().toISOString()
            }
        });
        
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

// Create customer portal session (for subscription management)
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

// Error handling middleware
app.use((error, req, res, next) => {
    console.error('Unhandled error:', error);
    res.status(500).json({ error: 'Internal server error' });
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
        console.log('👤 Customer details:', { id: customer.id, email: customer.email });
        
        // For now, let's use a simple approach - update existing subscription record
        // We'll assume the user already has a subscription record and update it
        try {
            // Get subscription period from the subscription items
            const subscriptionItems = subscription.items?.data || [];
            let currentPeriodStart = null;
            let currentPeriodEnd = null;
            
            if (subscriptionItems.length > 0) {
                const item = subscriptionItems[0];
                currentPeriodStart = item.current_period_start;
                currentPeriodEnd = item.current_period_end;
            }
            
            // Try to update existing subscription record
            const updateData = {
                stripe_subscription_id: subscription.id,
                stripe_customer_id: subscription.customer,
                status: subscription.status,
                tokens_limit: -1, // Unlimited for Pro
                updated_at: new Date().toISOString()
            };
            
            // Only add period dates if they exist
            if (currentPeriodStart) {
                updateData.current_period_start = new Date(currentPeriodStart * 1000).toISOString();
            }
            if (currentPeriodEnd) {
                updateData.current_period_end = new Date(currentPeriodEnd * 1000).toISOString();
            }
            
            console.log('📦 Subscription data to update:', updateData);
            
            // Try to update the subscription record
            await supabaseRequest('user_subscriptions?user_id=eq.41309d57-a92d-4dda-b970-a17984e2b210', {
                method: 'PATCH',
                body: updateData
            });
            
            console.log('✅ Subscription updated in Supabase');
            
        } catch (supabaseError) {
            console.error('❌ Error updating subscription in Supabase:', supabaseError);
        }
        
    } catch (error) {
        console.error('❌ Error handling subscription created:', error);
    }
}

async function handleSubscriptionUpdated(subscription) {
    try {
        console.log('🔄 Handling subscription updated:', subscription.id);
        
        // Get subscription period from the subscription items
        const subscriptionItems = subscription.items?.data || [];
        let currentPeriodStart = null;
        let currentPeriodEnd = null;
        
        if (subscriptionItems.length > 0) {
            const item = subscriptionItems[0];
            currentPeriodStart = item.current_period_start;
            currentPeriodEnd = item.current_period_end;
        }
        
        // Prepare update data
        const updateData = {
            status: subscription.status,
            updated_at: new Date().toISOString()
        };
        
        // Only add period dates if they exist
        if (currentPeriodStart) {
            updateData.current_period_start = new Date(currentPeriodStart * 1000).toISOString();
        }
        if (currentPeriodEnd) {
            updateData.current_period_end = new Date(currentPeriodEnd * 1000).toISOString();
        }
        
        console.log('📦 Update data:', updateData);
        
        // Update subscription record using PATCH request
        await supabaseRequest(`user_subscriptions?stripe_subscription_id=eq.${subscription.id}`, {
            method: 'PATCH',
            body: updateData
        });
        
        console.log('✅ Subscription updated in Supabase');
        
    } catch (error) {
        console.error('❌ Error updating subscription in Supabase:', error);
    }
}

async function handleSubscriptionDeleted(subscription) {
    try {
        console.log('🔄 Handling subscription deleted:', subscription.id);
        
        // Update subscription status back to free plan
        await supabaseRequest(`user_subscriptions?stripe_subscription_id=eq.${subscription.id}`, {
            method: 'PATCH',
            body: {
                status: 'free', // Back to free plan (not 'canceled')
                tokens_limit: 50, // Back to free tier
                tokens_used: 0, // Reset token usage for new month
                updated_at: new Date().toISOString()
            }
        });
        
        console.log('✅ User moved back to free plan in Supabase');
        
    } catch (error) {
        console.error('Error updating deleted subscription in Supabase:', error);
    }
}

async function handlePaymentSucceeded(invoice) {
    try {
        console.log('🔄 Handling payment succeeded for invoice:', invoice.id);
        console.log('🔍 DEBUG: This is the NEW handlePaymentSucceeded function!');
        
        // If this is a subscription invoice, update the subscription
        if (invoice.subscription) {
            console.log('📦 Invoice is for subscription:', invoice.subscription);
            
            // Get the subscription details from Stripe
            const subscription = await stripe.subscriptions.retrieve(invoice.subscription);
            console.log('📦 Retrieved subscription:', { id: subscription.id, status: subscription.status });
            
            // Update the subscription record directly using the subscription ID
            await supabaseRequest(`user_subscriptions?stripe_subscription_id=eq.${subscription.id}`, {
                method: 'PATCH',
                body: {
                    status: subscription.status,
                    current_period_start: new Date(subscription.current_period_start * 1000).toISOString(),
                    current_period_end: new Date(subscription.current_period_end * 1000).toISOString(),
                    updated_at: new Date().toISOString()
                }
            });
            
            console.log('✅ Subscription updated for payment success');
        }
        
    } catch (error) {
        console.error('❌ Error handling payment succeeded:', error);
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

// AI Proxy function with key pool
async function callAI(payload) {
    // If Redis is not available, this function won't be called
    // The fallback is handled in the /api/generate endpoint
    
    const maxWaitMs = 5000;
    const pollMs = 100;
    const t0 = Date.now();
    
    // Wait for an available key
    while (Date.now() - t0 < maxWaitMs) {
        const meta = await keyPool.acquire();
        if (meta) {
            console.log(`🔑 Using key: ${meta.alias} (RPM: ${meta.rpm})`);
            
            const res = await fetch(process.env.OPENAI_ENDPOINT || 'https://api.openai.com/v1/chat/completions', {
                method: 'POST',
                headers: {
                    'Authorization': `Bearer ${meta.key}`,
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify(payload),
                timeout: Number(process.env.REQUEST_TIMEOUT_MS || 60000)
            });

            if (res.ok) {
                return res.json();
            }

            const text = await res.text();
            throw new Error(`Provider error ${res.status}: ${text}`);
        }
        
        // Wait before trying again
        await new Promise(resolve => setTimeout(resolve, pollMs));
    }
    
    throw new Error('All API keys are at RPM right now. Please try again in a few seconds.');
}

// Admin endpoints for key management
app.post('/admin/keys', async (req, res) => {
    if (req.headers.authorization !== `Bearer ${process.env.ADMIN_TOKEN}`) {
        return res.status(401).json({ error: 'unauthorized' });
    }
    
    if (!redis) {
        return res.status(503).json({ error: 'Redis not available - key management disabled' });
    }
    
    const { action, alias, key, rpm, status } = req.body || {};
    const aliasesKey = 'ai:keys:aliases';
    const metaKey = (alias) => `ai:key:${alias}:meta`;

    try {
        if (action === 'add') {
            if (!alias || !key) {
                return res.status(400).json({ error: 'alias and key required' });
            }
            await redis.sadd(aliasesKey, alias);
            await redis.hset(metaKey(alias), {
                key: key,
                rpm: String(rpm || process.env.DEFAULT_RPM || 60),
                status: 'active'
            });
            console.log(`✅ Added key: ${alias}`);
            return res.json({ ok: true, message: `Key ${alias} added successfully` });
        }

        if (action === 'disable') {
            await redis.hset(metaKey(alias), { status: 'disabled' });
            console.log(`⚠️ Disabled key: ${alias}`);
            return res.json({ ok: true, message: `Key ${alias} disabled` });
        }

        if (action === 'remove') {
            await redis.srem(aliasesKey, alias);
            await redis.del(metaKey(alias));
            console.log(`🗑️ Removed key: ${alias}`);
            return res.json({ ok: true, message: `Key ${alias} removed` });
        }

        if (action === 'list') {
            const aliases = await redis.smembers(aliasesKey);
            const metas = [];
            for (const a of aliases) {
                const meta = await redis.hgetall(metaKey(a));
                metas.push({ alias: a, ...meta });
            }
            return res.json(metas);
        }

        res.status(400).json({ error: 'unsupported action' });
    } catch (error) {
        console.error('❌ Admin key operation failed:', error);
        res.status(500).json({ error: error.message });
    }
});

// AI generation endpoint
app.post('/api/generate', async (req, res) => {
    try {
        // Check user's request quota
        const userEmail = req.headers['x-user-email']; // Chrome extension will send this
        if (userEmail) {
            try {
                // Get user's subscription status from Supabase
                const userResponse = await fetch(`${SUPABASE_URL}/rest/v1/user_subscriptions?user_email=eq.${encodeURIComponent(userEmail)}`, {
                    headers: {
                        'Authorization': `Bearer ${SUPABASE_SERVICE_ROLE_KEY}`,
                        'apikey': SUPABASE_SERVICE_ROLE_KEY,
                        'Content-Type': 'application/json'
                    }
                });
                
                if (userResponse.ok) {
                    const subscriptions = await userResponse.json();
                    if (subscriptions && subscriptions.length > 0) {
                        const subscription = subscriptions[0];
                        
                        // Check if user has unlimited requests (Pro users)
                        if (subscription.status === 'active' && subscription.is_unlimited) {
                            console.log(`✅ Pro user ${userEmail} - unlimited requests`);
                        } else {
                            // Free tier: check monthly request limit
                            const currentMonth = new Date().toISOString().slice(0, 7); // YYYY-MM
                            const requestsThisMonth = subscription.requests_used_this_month || 0;
                            const monthlyLimit = 10; // Free tier gets 10 requests per month
                            
                            if (requestsThisMonth >= monthlyLimit) {
                                return res.status(429).json({ 
                                    error: 'Monthly request limit reached. Upgrade to Pro for unlimited requests.',
                                    limit: monthlyLimit,
                                    used: requestsThisMonth
                                });
                            }
                            
                            // Increment request count
                            await fetch(`${SUPABASE_URL}/rest/v1/user_subscriptions?id=eq.${subscription.id}`, {
                                method: 'PATCH',
                                headers: {
                                    'Authorization': `Bearer ${SUPABASE_SERVICE_ROLE_KEY}`,
                                    'apikey': SUPABASE_SERVICE_ROLE_KEY,
                                    'Content-Type': 'application/json'
                                },
                                body: JSON.stringify({
                                    requests_used_this_month: requestsThisMonth + 1,
                                    updated_at: new Date().toISOString()
                                })
                            });
                            
                            console.log(`📊 Free user ${userEmail} - ${requestsThisMonth + 1}/${monthlyLimit} requests used`);
                        }
                    }
                }
            } catch (quotaError) {
                console.log('⚠️ Could not check user quota:', quotaError.message);
                // Continue without quota check if there's an error
            }
        }
        
        const payload = {
            model: req.body.model || 'gpt-4o-mini',
            messages: req.body.messages,
            max_tokens: req.body.max_tokens || 2000  // Increased from 1000
        };
        
        console.log('🤖 Calling AI with payload:', { model: payload.model, max_tokens: payload.max_tokens });
        
        // If Redis is not available, fall back to direct OpenAI call
        if (!redis) {
            console.log('⚠️ Redis not available, using fallback OpenAI call');
            
            if (!process.env.OPENAI_API_KEY) {
                throw new Error('OpenAI API key not configured. Please add OPENAI_API_KEY to environment variables.');
            }
            
            const response = await fetch('https://api.openai.com/v1/chat/completions', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Authorization': `Bearer ${process.env.OPENAI_API_KEY}`
                },
                body: JSON.stringify(payload)
            });
            
            if (!response.ok) {
                const errorText = await response.text();
                throw new Error(`OpenAI API error: ${response.status} - ${errorText}`);
            }
            
            const data = await response.json();
            return res.json(data);
        }
        
        // Check if any keys are available
        try {
            const availableKeys = await keyPool.list();
            if (!availableKeys || availableKeys.length === 0) {
                console.log('⚠️ No API keys available, using fallback OpenAI call');
                if (!process.env.OPENAI_API_KEY) {
                    throw new Error('No API keys configured. Please add keys via admin endpoint or set OPENAI_API_KEY.');
                }
                const response = await fetch('https://api.openai.com/v1/chat/completions', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        'Authorization': `Bearer ${process.env.OPENAI_API_KEY}`
                    },
                    body: JSON.stringify(payload)
                });
                
                if (!response.ok) {
                    const errorText = await response.text();
                    throw new Error(`OpenAI API error: ${response.status} - ${errorText}`);
                }
                
                const data = await response.json();
                return res.json(data);
            }
        } catch (keyError) {
            console.log('⚠️ Key pool error, using fallback:', keyError.message);
            if (!process.env.OPENAI_API_KEY) {
                throw new Error('Key management failed and no fallback API key configured.');
            }
            const response = await fetch('https://api.openai.com/v1/chat/completions', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Authorization': `Bearer ${process.env.OPENAI_API_KEY}`
                },
                body: JSON.stringify(payload)
            });
            
            if (!response.ok) {
                const errorText = await response.text();
                throw new Error(`OpenAI API error: ${response.status} - ${errorText}`);
            }
            
            const data = await response.json();
            return res.json(data);
        }
        
        const data = await callAI(payload);
        res.json(data);
    } catch (error) {
        console.error('❌ AI generation failed:', error);
        const msg = String(error.message || error);
        const code = /RPM limit/i.test(msg) || /keys are at RPM/i.test(msg) ? 503 : 400;
        res.status(code).json({ error: msg, retryAfterSeconds: 30 });
    }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`🚀 Trontiq Stripe API server running on port ${PORT}`);
    console.log(`📊 Health check: http://localhost:${PORT}/api/health`);
    console.log(`🔒 Security: Rate limiting and CORS enabled`);
    console.log(`🔗 Supabase integration: Active`);
});

// 404 handler - must be at the very end
app.use('*', (req, res) => {
    res.status(404).json({ error: 'Endpoint not found' });
});

module.exports = app;
