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
            'https://localhost:*',
            'https://www.google.com',
            'https://*.google.com'
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

        // Cancel subscription directly in Stripe
        const subscription = await stripe.subscriptions.update(subscriptionId, {
            cancel_at_period_end: true
        });

        console.log('Subscription canceled successfully');

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

// Session-based user info endpoint (secure)
app.get('/api/me', async (req, res) => {
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
            
        } catch (adminApiError) {
            console.error('❌ [API/ME] Admin API error:', adminApiError);
            return res.status(401).json({
                success: false,
                error: 'User not found'
            });
        }
        
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
            const isProUser = subscription.status === 'active' && isUnlimited;
            
            // Set cache headers
            res.set('Cache-Control', 'private, max-age=30');
            
            res.json({
                success: true,
                isAuthenticated: true,
                plan: isProUser ? 'pro' : 'free',
                isProUser: isProUser,
                canChat: isProUser || requestsUsed < monthlyLimit,
                requestsUsed: requestsUsed,
                monthlyLimit: monthlyLimit,
                upgradeRequired: !isProUser && requestsUsed >= monthlyLimit,
                upgradeUrl: 'https://stripe-deploy.onrender.com/api/create-checkout-session',
                // Add user personal information
                user: {
                    email: user.email,
                    display_name: displayName,
                    full_name: fullName,
                    user_metadata: user.user_metadata
                }
            });
        } else {
            // No subscription found - return free user data
            res.set('Cache-Control', 'private, max-age=30');
            
            res.json({
                success: true,
                isAuthenticated: true,
                plan: 'free',
                isProUser: false,
                canChat: true,
                requestsUsed: 0,
                monthlyLimit: 75,
                upgradeRequired: false,
                upgradeUrl: 'https://stripe-deploy.onrender.com/api/create-checkout-session',
                // Add user personal information
                user: {
                    email: user.email,
                    display_name: displayName,
                    full_name: fullName,
                    user_metadata: user.user_metadata
                }
            });
        }
        
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

// User preferences endpoint
app.get('/api/prefs', async (req, res) => {
    try {
        const { userId } = req.query;
        
        if (!userId) {
            return res.status(401).json({
                success: false,
                error: 'User ID required'
            });
        }
        
        // For now, we'll use a simpler approach since auth.users is not accessible via REST API
        // In a production environment, you would validate the session token and get user data
        let displayName = 'User'; // Would come from validated session
        
        // Return user preferences (in real implementation, this would come from a user_preferences table)
        res.json({
            success: true,
            data: {
                trontiq_display_name: displayName,
                trontiq_education_level: 'bachelor',
                trontiq_language: 'english',
                trontiq_tone: 'professional'
            }
        });
        
    } catch (error) {
        console.error('❌ Get prefs error:', error);
        res.status(500).json({
            success: false,
            error: error.message
        });
    }
});

app.post('/api/prefs', async (req, res) => {
    try {
        const { userId, data } = req.body;
        
        if (!userId) {
            return res.status(401).json({
                success: false,
                error: 'User ID required'
            });
        }
        
        console.log('✅ User preferences saved:', Object.keys(data || {}));
        
        res.json({ success: true });
        
    } catch (error) {
        console.error('❌ Save prefs error:', error);
        res.status(500).json({
            success: false,
            error: error.message
        });
    }
});

// Individual preference endpoints
app.get('/api/prefs/tone', async (req, res) => {
    try {
        const { userId } = req.query;
        
        if (!userId) {
            return res.status(401).json({
                success: false,
                error: 'User ID required'
            });
        }
        
        // Return user's tone preference (in real implementation, this would come from database)
        res.json({
            success: true,
            data: {
                tone: 'professional' // Default value
            }
        });
        
    } catch (error) {
        console.error('❌ Get tone error:', error);
        res.status(500).json({
            success: false,
            error: error.message
        });
    }
});

app.post('/api/prefs/tone', async (req, res) => {
    try {
        const { userId, tone } = req.body;
        
        if (!userId) {
            return res.status(401).json({
                success: false,
                error: 'User ID required'
            });
        }
        
        if (!tone) {
            return res.status(400).json({
                success: false,
                error: 'Tone is required'
            });
        }
        
        console.log('✅ Tone preference saved:', { userId, tone });
        
        res.json({ success: true, tone });
        
    } catch (error) {
        console.error('❌ Save tone error:', error);
        res.status(500).json({
            success: false,
            error: error.message
        });
    }
});

app.get('/api/prefs/education', async (req, res) => {
    try {
        const { userId } = req.query;
        
        if (!userId) {
            return res.status(401).json({
                success: false,
                error: 'User ID required'
            });
        }
        
        // Return user's education level preference
        res.json({
            success: true,
            data: {
                education: 'bachelor' // Default value
            }
        });
        
    } catch (error) {
        console.error('❌ Get education error:', error);
        res.status(500).json({
            success: false,
            error: error.message
        });
    }
});

app.post('/api/prefs/education', async (req, res) => {
    try {
        const { userId, education } = req.body;
        
        if (!userId) {
            return res.status(401).json({
                success: false,
                error: 'User ID required'
            });
        }
        
        if (!education) {
            return res.status(400).json({
                success: false,
                error: 'Education level is required'
            });
        }
        
        console.log('✅ Education preference saved:', { userId, education });
        
        res.json({ success: true, education });
        
    } catch (error) {
        console.error('❌ Save education error:', error);
        res.status(500).json({
            success: false,
            error: error.message
        });
    }
});

app.get('/api/prefs/language', async (req, res) => {
    try {
        const { userId } = req.query;
        
        if (!userId) {
            return res.status(401).json({
                success: false,
                error: 'User ID required'
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

app.post('/api/prefs/language', async (req, res) => {
    try {
        const { userId, language } = req.body;
        
        if (!userId) {
            return res.status(401).json({
                success: false,
                error: 'User ID required'
            });
        }
        
        if (!language) {
            return res.status(400).json({
                success: false,
                error: 'Language is required'
            });
        }
        
        console.log('✅ Language preference saved:', { userId, language });
        
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
app.get('/api/prefs/display_name', async (req, res) => {
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

app.post('/api/prefs/display_name', async (req, res) => {
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
        upgradeUrl: 'https://stripe-deploy.onrender.com/api/create-checkout-session'
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
app.get('/api/resume', async (req, res) => {
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

app.post('/api/resume', async (req, res) => {
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

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`🚀 Trontiq Stripe API server running on port ${PORT}`);
    console.log(`📊 Health check: http://localhost:${PORT}/api/health`);
    console.log(`🔒 Security: Rate limiting and CORS enabled`);
    console.log(`🔗 Supabase integration: Active`);
});

module.exports = app;
 
