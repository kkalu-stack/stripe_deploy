// Trontiq Minimal Server Deployment
// Single file deployment - includes all necessary code

const express = require('express');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const stripe = require('stripe')(process.env.STRIPE_SECRET_KEY);
const cookieParser = require('cookie-parser');
// Environment-based API key management (no Redis needed)
const API_KEYS = [
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
].filter(key => key); // Remove any undefined keys

let currentKeyIndex = 0;

// Simple round-robin key rotation
function getNextApiKey() {
    if (API_KEYS.length === 0) {
        return process.env.OPENAI_API_KEY; // Fallback to single key
    }
    
    const key = API_KEYS[currentKeyIndex];
    currentKeyIndex = (currentKeyIndex + 1) % API_KEYS.length;
    return key;
}

console.log(`🚀 Loaded ${API_KEYS.length} API keys from environment variables`);
if (API_KEYS.length > 0) {
    console.log(`⚡ Round-robin rotation enabled - ${API_KEYS.length * 60} RPM capacity`);
} else {
    console.log('⚠️ No rotation keys found, using fallback single key');
}

// Supabase configuration for direct HTTP requests
const SUPABASE_URL = process.env.SUPABASE_URL;
const SUPABASE_SERVICE_ROLE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY;

// Simple environment-based key management (no Redis needed)
console.log('⚡ Using environment-based API key rotation (no Redis)');

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
            requests_used_this_month: 0,
            monthly_request_limit: 75,
            is_unlimited: false,
            current_period_end: null
        });
    } else {
        // Other error - fallback to free tier response
        res.json({
            status: 'free',
            requests_used_this_month: 0,
            monthly_request_limit: 75,
            is_unlimited: false,
            current_period_end: null
        });
    }
}

// Session management
const sessions = new Map(); // In-memory session store (in production, use Redis)

// Helper function to create session
function createSession(userId, userData) {
    const sessionId = `session_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
    const session = {
        userId,
        userData,
        createdAt: Date.now(),
        lastActivity: Date.now()
    };
    sessions.set(sessionId, session);
    return sessionId;
}

// Helper function to get session
function getSession(sessionId) {
    const session = sessions.get(sessionId);
    if (session) {
        session.lastActivity = Date.now();
        return session;
    }
    return null;
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
app.use(cookieParser()); // Add cookie parser for session management
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
        environment: process.env.NODE_ENV || 'production',
        apiKeys: {
            total: API_KEYS.length,
            currentIndex: currentKeyIndex,
            rotationEnabled: API_KEYS.length > 0,
            rpmCapacity: API_KEYS.length * 60
        }
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
            monthly_request_limit: -1, // Unlimited for Pro
            requests_used_this_month: 0,
            is_unlimited: true,
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
                    status: 'canceled', // Mark as canceled but keep Pro access until period end
                    cancel_at_period_end: true, // Will revert to free at period end
                    updated_at: new Date().toISOString()
                }
            });
            console.log('✅ Supabase updated successfully - user keeps Pro access until period end');
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
                    requests_used_this_month: 0,
                    monthly_request_limit: 75,
                    is_unlimited: false,
                    current_period_end: null
                });
            }
        } catch (supabaseError) {
            console.error('❌ Supabase query error:', supabaseError);
            // For any query error, just return free tier status
            res.json({
                status: 'free',
                requests_used_this_month: 0,
                monthly_request_limit: 75,
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

// Update request usage in Supabase (replaces old token usage)
app.post('/api/update-request-usage', async (req, res) => {
    try {
        const { userId, requestsUsed } = req.body;
        
        if (!userId || requestsUsed === undefined) {
            return res.status(400).json({ error: 'Missing userId or requestsUsed' });
        }
        
        // Update request usage in Supabase
        await supabaseRequest(`user_subscriptions?user_id=eq.${userId}`, {
            method: 'PATCH',
            body: {
                requests_used_this_month: requestsUsed,
                updated_at: new Date().toISOString()
            }
        });
        
        console.log('✅ Request usage updated for user:', userId, 'requests:', requestsUsed);
        res.json({ success: true, requestsUsed });
        
    } catch (error) {
        console.error('Error updating request usage in Supabase:', error);
        res.status(500).json({ error: 'Failed to update request usage' });
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
            requests_used_this_month: 0,
            monthly_request_limit: status === 'active' ? -1 : 75,
            is_unlimited: status === 'active',
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

// Upgrade page endpoint
app.get('/upgrade', (req, res) => {
    res.json({
        title: 'Upgrade to Pro',
        message: 'Get unlimited AI assistance and advanced features',
        features: [
            'Unlimited access per month',
            'Advanced resume and cover letter tools',
            'Priority support',
            'Early access to new features'
        ],
        price: '$4.99/month',
        upgradeUrl: 'https://stripe-deploy.onrender.com/api/create-checkout-session'
    });
});

// Login endpoint to create session
app.post('/api/login', async (req, res) => {
    try {
        const { email, password } = req.body;
        
        if (!email || !password) {
            return res.status(400).json({
                success: false,
                error: 'Email and password are required'
            });
        }
        
        // Authenticate with Supabase
        const authResponse = await fetch(`${SUPABASE_URL}/auth/v1/token?grant_type=password`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'apikey': SUPABASE_SERVICE_ROLE_KEY
            },
            body: JSON.stringify({ email, password })
        });
        
        if (!authResponse.ok) {
            return res.status(401).json({
                success: false,
                error: 'Invalid credentials'
            });
        }
        
        const authData = await authResponse.json();
        
        // Get user data
        const userResponse = await fetch(`${SUPABASE_URL}/auth/v1/user`, {
            headers: {
                'Authorization': `Bearer ${authData.access_token}`,
                'apikey': SUPABASE_SERVICE_ROLE_KEY
            }
        });
        
        if (!userResponse.ok) {
            return res.status(401).json({
                success: false,
                error: 'Failed to get user data'
            });
        }
        
        const userData = await userResponse.json();
        
        // Create session
        const sessionId = createSession(userData.id, userData);
        
        // Set HttpOnly cookie
        res.cookie('trontiq_session', sessionId, {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: 'lax',
            maxAge: 7 * 24 * 60 * 60 * 1000 // 7 days
        });
        
        res.json({
            success: true,
            isAuthenticated: true,
            user: {
                id: userData.id,
                email: userData.email,
                display_name: userData.user_metadata?.full_name || 'User'
            }
        });
        
    } catch (error) {
        console.error('❌ Login error:', error);
        res.status(500).json({
            success: false,
            error: error.message
        });
    }
});

// Logout endpoint
app.post('/api/logout', (req, res) => {
    const sessionId = req.cookies.trontiq_session;
    
    if (sessionId) {
        sessions.delete(sessionId);
    }
    
    res.clearCookie('trontiq_session');
    res.json({ success: true });
});

// Session-based user info endpoint (secure)
app.get('/api/me', async (req, res) => {
    try {
        const sessionId = req.cookies.trontiq_session;
        
        if (!sessionId) {
            return res.status(401).json({
                success: false,
                isAuthenticated: false,
                error: 'No session found'
            });
        }
        
        const session = getSession(sessionId);
        if (!session) {
            return res.status(401).json({
                success: false,
                isAuthenticated: false,
                error: 'Invalid session'
            });
        }
        
        // Get user profile data
        const userProfile = await supabaseRequest(`user_profiles?user_id=eq.${session.userId}&select=*`);
        
        // Get user subscription data
        const data = await supabaseRequest(`user_subscriptions?user_id=eq.${session.userId}&select=*`);
        
        if (data && data.length > 0) {
            const subscription = data[0];
            const requestsUsed = subscription.requests_used_this_month || 0;
            const monthlyLimit = subscription.monthly_request_limit || 75;
            const isUnlimited = subscription.is_unlimited || false;
            
            // Check if user is Pro (active or canceled but still in paid period)
            const isProUser = (subscription.status === 'active' || 
                              (subscription.status === 'canceled' && subscription.cancel_at_period_end)) && 
                             isUnlimited;
            
            res.json({
                success: true,
                isAuthenticated: true,
                user: {
                    id: session.userId,
                    email: session.userData.email,
                    display_name: userProfile && userProfile.length > 0 ? userProfile[0].display_name : session.userData.user_metadata?.full_name || 'User',
                    user_metadata: {
                        full_name: userProfile && userProfile.length > 0 ? userProfile[0].display_name : session.userData.user_metadata?.full_name || 'User'
                    }
                },
                plan: isProUser ? 'pro' : 'free',
                isProUser: isProUser,
                requestsUsed: requestsUsed,
                monthlyLimit: monthlyLimit,
                canChat: isProUser || requestsUsed < monthlyLimit
            });
        } else {
            res.json({
                success: true,
                isAuthenticated: true,
                user: {
                    id: session.userId,
                    email: session.userData.email,
                    display_name: userProfile && userProfile.length > 0 ? userProfile[0].display_name : session.userData.user_metadata?.full_name || 'User',
                    user_metadata: {
                        full_name: userProfile && userProfile.length > 0 ? userProfile[0].display_name : session.userData.user_metadata?.full_name || 'User'
                    }
                },
                plan: 'free',
                isProUser: false,
                requestsUsed: 0,
                monthlyLimit: 75,
                canChat: true
            });
        }
    } catch (error) {
        console.error('❌ /me endpoint error:', error);
        res.status(500).json({
            success: false,
            isAuthenticated: false,
            error: error.message
        });
    }
});

// Check user status and quota (legacy endpoint - will be deprecated)
app.get('/api/user-status/:userId', async (req, res) => {
    try {
        const { userId } = req.params;
        console.log('🔍 Checking user status for:', userId);
        
        // Production validation - user ID must exist and be valid
        if (!userId) {
            console.log('❌ No user ID provided');
            return res.status(401).json({
                success: false,
                error: 'Authentication required',
                message: 'User must be authenticated to access this endpoint'
            });
        }
        
        const data = await supabaseRequest(`user_subscriptions?user_id=eq.${userId}&select=*`);
        
        if (data && data.length > 0) {
            const subscription = data[0];
            const requestsUsed = subscription.requests_used_this_month || 0;
            const monthlyLimit = subscription.monthly_request_limit || 75;
            const isUnlimited = subscription.is_unlimited || false;
            
            // Check if user is Pro (active or canceled but still in paid period)
            const isProUser = (subscription.status === 'active' || 
                              (subscription.status === 'canceled' && subscription.cancel_at_period_end)) && 
                             isUnlimited;
            
            res.json({
                success: true,
                status: subscription.status,
                requestsUsed: requestsUsed,
                monthlyLimit: monthlyLimit,
                isUnlimited: isUnlimited,
                isProUser: isProUser,
                canChat: isProUser || requestsUsed < monthlyLimit,
                upgradeRequired: !isProUser && requestsUsed >= monthlyLimit,
                upgradeMessage: !isProUser && requestsUsed >= monthlyLimit ? 
                    `You've used all ${monthlyLimit} free requests this month. Upgrade to Pro for unlimited access!` : 
                    null,
                upgradeUrl: 'https://stripe-deploy.onrender.com/upgrade'
            });
        } else {
            res.json({
                success: false,
                message: 'No subscription found',
                canChat: false,
                upgradeRequired: true,
                upgradeMessage: 'Please create an account to start using AI assistance.',
                upgradeUrl: 'https://stripe-deploy.onrender.com/upgrade'
            });
        }
    } catch (error) {
        console.error('❌ User status check error:', error);
        res.status(500).json({
            success: false,
            error: error.message
        });
    }
});

// Manual fix endpoint to update subscription status
app.post('/api/fix-subscription-status', async (req, res) => {
    try {
        const { userId, status } = req.body;
        console.log('🔧 Manual subscription status fix:', { userId, status });
        
        if (!userId || !status) {
            return res.status(400).json({ error: 'userId and status are required' });
        }
        
        // Update subscription status
        await supabaseRequest(`user_subscriptions?user_id=eq.${userId}`, {
            method: 'PATCH',
            body: {
                status: status,
                updated_at: new Date().toISOString()
            }
        });
        
        console.log('✅ Subscription status manually updated to:', status);
        res.json({ success: true, message: `Status updated to ${status}` });
        
    } catch (error) {
        console.error('❌ Error fixing subscription status:', error);
        res.status(500).json({ error: error.message });
    }
});

// Debug endpoint to check user subscription data
app.get('/api/debug-subscription/:userId', async (req, res) => {
    try {
        const { userId } = req.params;
        console.log('🔍 Debugging subscription for user:', userId);
        
        // Get subscription from Supabase
        const data = await supabaseRequest(`user_subscriptions?user_id=eq.${userId}&select=*`);
        console.log('📊 Raw subscription data:', data);
        
        if (data && data.length > 0) {
            const subscription = data[0];
            res.json({
                success: true,
                subscription: subscription,
                fields: {
                    has_requests_used: 'requests_used_this_month' in subscription,
                    has_monthly_limit: 'monthly_request_limit' in subscription,
                    has_is_unlimited: 'is_unlimited' in subscription,
                    requests_used: subscription.requests_used_this_month,
                    monthly_limit: subscription.monthly_request_limit,
                    is_unlimited: subscription.is_unlimited
                }
            });
        } else {
            res.json({
                success: false,
                message: 'No subscription found',
                userId: userId
            });
        }
    } catch (error) {
        console.error('❌ Debug subscription error:', error);
        res.status(500).json({
            success: false,
            error: error.message
        });
    }
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
                    
                    // Cancel the subscription in Stripe (at period end)
                    const stripe = require('stripe')(process.env.STRIPE_SECRET_KEY);
                    await stripe.subscriptions.cancel(subscription.stripe_subscription_id);
                    
                    // Update Supabase to reflect cancellation but keep Pro access until period ends
                    await supabaseRequest(`user_subscriptions?user_id=eq.${userId}`, {
                        method: 'PATCH',
                        body: {
                            status: 'canceled',
                            cancel_at_period_end: true,
                            monthly_request_limit: -1, // Keep unlimited until period ends
                            is_unlimited: true,
                            updated_at: new Date().toISOString()
                        }
                    });
                    
                    console.log('✅ Stripe subscription canceled, user keeps Pro access until period ends');
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

// Check for expired subscriptions and move to free tier
async function checkExpiredSubscriptions() {
    try {
        console.log('🔍 Checking for expired subscriptions...');
        
        // Get all canceled subscriptions that should have expired
        const now = new Date().toISOString();
        const expiredSubscriptions = await supabaseRequest(
            `user_subscriptions?status=eq.canceled&cancel_at_period_end=eq.true&current_period_end=lt.${now}&select=*`
        );
        
        if (expiredSubscriptions && expiredSubscriptions.length > 0) {
            console.log(`📅 Found ${expiredSubscriptions.length} expired subscriptions`);
            
            for (const subscription of expiredSubscriptions) {
                console.log(`🔄 Moving user ${subscription.user_id} to free tier (period ended: ${subscription.current_period_end})`);
                
                await supabaseRequest(`user_subscriptions?id=eq.${subscription.id}`, {
                    method: 'PATCH',
                    body: {
                        status: 'free',
                        cancel_at_period_end: false,
                        monthly_request_limit: 75,
                        requests_used_this_month: 0,
                        is_unlimited: false,
                        updated_at: new Date().toISOString()
                    }
                });
            }
            
            console.log('✅ Expired subscriptions processed');
        } else {
            console.log('✅ No expired subscriptions found');
        }
    } catch (error) {
        console.error('❌ Error checking expired subscriptions:', error);
    }
}

// Run expired subscription check every hour
setInterval(checkExpiredSubscriptions, 60 * 60 * 1000); // Every hour
// Also run it on startup
checkExpiredSubscriptions();

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
                monthly_request_limit: -1, // Unlimited for Pro
                requests_used_this_month: 0, // Reset request usage
                is_unlimited: true,
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
                monthly_request_limit: -1, // Unlimited for Pro
                is_unlimited: true,
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
            
            // Try to update the subscription record - this should be dynamic based on the subscription
            // For now, we'll use the stripe_subscription_id to find the record
            if (subscription.id) {
                await supabaseRequest(`user_subscriptions?stripe_subscription_id=eq.${subscription.id}`, {
                    method: 'PATCH',
                    body: updateData
                });
            } else {
                console.log('⚠️ No subscription ID available for update');
            }
            
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
        
        // Check if subscription was cancelled but still in paid period
        const now = new Date();
        const periodEnd = subscription.current_period_end ? new Date(subscription.current_period_end) : null;
        
        if (periodEnd && now < periodEnd) {
            // Subscription cancelled but still in paid period - keep Pro access until period ends
            console.log('📅 Subscription cancelled but still in paid period until:', periodEnd);
            await supabaseRequest(`user_subscriptions?stripe_subscription_id=eq.${subscription.id}`, {
                method: 'PATCH',
                body: {
                    status: 'canceled',
                    cancel_at_period_end: true,
                    monthly_request_limit: -1, // Keep unlimited
                    is_unlimited: true,
                    updated_at: new Date().toISOString()
                }
            });
            console.log('✅ User keeps Pro access until period ends');
        } else {
            // Period has ended or no period data - move to free plan
            console.log('📅 Subscription period ended, moving to free plan');
            await supabaseRequest(`user_subscriptions?stripe_subscription_id=eq.${subscription.id}`, {
                method: 'PATCH',
                body: {
                    status: 'free',
                    cancel_at_period_end: false,
                    monthly_request_limit: 75, // Free tier gets 75 requests
                    requests_used_this_month: 0, // Reset request usage for new month
                    is_unlimited: false,
                    updated_at: new Date().toISOString()
                }
            });
            console.log('✅ User moved to free plan');
        }
        
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

// Environment-based key management (no admin endpoints needed)
// Keys are managed via environment variables: OPENAI_API_KEY_1 through OPENAI_API_KEY_10

// AI generation endpoint
app.post('/api/generate', async (req, res) => {
    try {
        // Check user's request quota
        const userEmail = req.headers['x-user-email']; // Chrome extension will send this
        const userId = req.headers['x-user-id']; // Alternative: user ID
        if (userEmail || userId) {
            try {
                // Get user's subscription status from Supabase
                const queryParam = userId ? `user_id=eq.${userId}` : `user_email=eq.${encodeURIComponent(userEmail)}`;
                const userResponse = await fetch(`${SUPABASE_URL}/rest/v1/user_subscriptions?${queryParam}`, {
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
                        
                        // Check if user has unlimited requests (Pro users - active or canceled but still in paid period)
                        const isProUser = (subscription.status === 'active' || 
                                          (subscription.status === 'canceled' && subscription.cancel_at_period_end)) && 
                                         subscription.is_unlimited;
                        
                        if (isProUser) {
                            console.log(`✅ Pro user ${userEmail} - unlimited requests (status: ${subscription.status})`);
                        } else {
                            // Free tier: check monthly request limit
                            const currentMonth = new Date().toISOString().slice(0, 7); // YYYY-MM
                            const requestsThisMonth = subscription.requests_used_this_month || 0;
                            const monthlyLimit = 75; // Free tier gets 75 requests per month
                            
                            if (requestsThisMonth >= monthlyLimit) {
                                return res.status(429).json({ 
                                    error: 'Monthly request limit reached. Upgrade to Pro for unlimited requests.',
                                    limit: monthlyLimit,
                                    used: requestsThisMonth,
                                    upgradeRequired: true,
                                    upgradeMessage: `You've used all ${monthlyLimit} free requests this month. Upgrade to Pro for Unlimited Access!`,
                                    upgradeUrl: 'https://stripe-deploy.onrender.com/upgrade'
                                });
                            }
                            
                            // Increment request count
                            console.log(`📊 Updating request count for user ${userEmail}: ${requestsThisMonth} → ${requestsThisMonth + 1}`);
                            
                            const updateResponse = await fetch(`${SUPABASE_URL}/rest/v1/user_subscriptions?id=eq.${subscription.id}`, {
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
                            
                            if (!updateResponse.ok) {
                                const errorText = await updateResponse.text();
                                console.error(`❌ Failed to update request count: ${updateResponse.status} - ${errorText}`);
                            } else {
                                console.log(`✅ Request count updated successfully: ${requestsThisMonth + 1}/${monthlyLimit}`);
                            }
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
        
        // Use environment-based key rotation (no Redis needed)
        const apiKey = getNextApiKey();
        
        if (!apiKey) {
            throw new Error('No OpenAI API keys configured. Please add OPENAI_API_KEY or OPENAI_API_KEY_1 through OPENAI_API_KEY_10 to environment variables.');
        }
        
        console.log(`🔑 Using API key ${currentKeyIndex}/${API_KEYS.length} (round-robin rotation)`);
        
        const response = await fetch('https://api.openai.com/v1/chat/completions', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${apiKey}`
            },
            body: JSON.stringify(payload)
        });
        
        if (!response.ok) {
            const errorText = await response.text();
            throw new Error(`OpenAI API error: ${response.status} - ${errorText}`);
        }
        
        const data = await response.json();
        return res.json(data);
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
