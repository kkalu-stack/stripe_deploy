// Trontiq Minimal Server Deployment
// Single file deployment - includes all necessary code

const express = require('express');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const stripe = require('stripe')(process.env.STRIPE_SECRET_KEY);

// Supabase client for database operations
const { createClient } = require('@supabase/supabase-js');

const supabase = createClient(
    process.env.SUPABASE_URL || 'https://vlsolqjzzelultbrpmis.supabase.co',
    process.env.SUPABASE_SERVICE_ROLE_KEY || 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6InZsc29scWp6emVsdWx0YnJwbWlzIiwicm9sZSI6InNlcnZpY2Vfcm9sZSIsImlhdCI6MTc1NTIxNjAzNSwiZXhwIjoyMDcwNzkyMDM1fQ.lC9nTJSv6tOecSjb0vwJPIB38Jt-4X9mNnMD3N_UZaw'
);

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
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true })); // Add this for form data

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

// Success page endpoint
app.get('/success', (req, res) => {
    const sessionId = req.query.session_id;
    res.send(`
        <!DOCTYPE html>
        <html>
        <head>
            <title>Payment Successful - Trontiq</title>
            <style>
                body { font-family: Arial, sans-serif; text-align: center; padding: 50px; }
                .success { color: green; font-size: 24px; }
                .btn { background: #667eea; color: white; padding: 10px 20px; border: none; border-radius: 5px; cursor: pointer; }
            </style>
        </head>
        <body>
            <div class="success">✅ Payment Successful!</div>
            <p>Your Trontiq Pro subscription has been activated.</p>
            <button class="btn" onclick="window.close()">Close</button>
            <script>
                if (sessionId) {
                    console.log('Payment successful:', sessionId);
                }
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
        
        // Get subscription from Supabase
        const { data, error } = await supabase
            .from('user_subscriptions')
            .select('*')
            .eq('user_id', userId)
            .single();
            
        if (error) {
            if (error.code === 'PGRST116') {
                // No subscription found, return free tier
                return res.json({
                    status: 'free',
                    tokens_used: 0,
                    tokens_limit: 50,
                    is_unlimited: false,
                    current_period_end: null
                });
            }
            throw error;
        }
        
        res.json({
            status: data.status,
            tokens_used: data.tokens_used || 0,
            tokens_limit: data.tokens_limit,
            is_unlimited: data.tokens_limit === -1,
            current_period_end: data.current_period_end,
            stripe_subscription_id: data.stripe_subscription_id
        });
    } catch (error) {
        console.error('Error retrieving subscription from Supabase:', error);
        res.status(500).json({ error: 'Failed to retrieve subscription' });
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
        const { data, error } = await supabase
            .from('user_subscriptions')
            .update({
                tokens_used: tokensUsed,
                updated_at: new Date().toISOString()
            })
            .eq('user_id', userId);
            
        if (error) {
            console.error('Error updating token usage in Supabase:', error);
            return res.status(500).json({ error: 'Failed to update token usage' });
        }
        
        console.log('✅ Token usage updated for user:', userId, 'tokens:', tokensUsed);
        res.json({ success: true, tokensUsed });
        
    } catch (error) {
        console.error('Error updating token usage:', error);
        res.status(500).json({ error: 'Failed to update token usage' });
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

// Webhook handler for Stripe events (no user data storage)
app.post('/api/webhook', express.raw({ type: 'application/json' }), async (req, res) => {
    const sig = req.headers['stripe-signature'];
    const endpointSecret = process.env.STRIPE_WEBHOOK_SECRET;

    let event;

    try {
        event = stripe.webhooks.constructEvent(req.body, sig, endpointSecret);
        console.log('Webhook event received:', event.type);
    } catch (err) {
        console.error('Webhook signature verification failed:', err.message);
        return res.status(400).send(`Webhook Error: ${err.message}`);
    }

    // Handle the event with Supabase database operations
    switch (event.type) {
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
            console.log(`Unhandled event type: ${event.type}`);
    }

    res.json({ received: true });
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

async function handleSubscriptionCreated(subscription) {
    try {
        console.log('🔄 Handling subscription created:', subscription.id);
        
        // Get customer details from Stripe
        const customer = await stripe.customers.retrieve(subscription.customer);
        
        // Find user by email in Supabase
        const { data: users, error: userError } = await supabase.auth.admin.listUsers();
        if (userError) {
            console.error('Error fetching users:', userError);
            return;
        }
        
        const user = users.users.find(u => u.email === customer.email);
        if (!user) {
            console.log('No user found for email:', customer.email);
            return;
        }
        
        // Insert or update subscription record
        const { data, error } = await supabase
            .from('user_subscriptions')
            .upsert({
                user_id: user.id,
                stripe_subscription_id: subscription.id,
                stripe_customer_id: subscription.customer,
                status: subscription.status,
                current_period_start: new Date(subscription.current_period_start * 1000).toISOString(),
                current_period_end: new Date(subscription.current_period_end * 1000).toISOString(),
                tokens_limit: -1, // Unlimited for Pro
                updated_at: new Date().toISOString()
            }, { onConflict: 'stripe_subscription_id' });
            
        if (error) {
            console.error('Error saving subscription to Supabase:', error);
        } else {
            console.log('✅ Subscription saved to Supabase for user:', user.id);
        }
        
    } catch (error) {
        console.error('Error handling subscription created:', error);
    }
}

async function handleSubscriptionUpdated(subscription) {
    try {
        console.log('🔄 Handling subscription updated:', subscription.id);
        
        // Update subscription record
        const { data, error } = await supabase
            .from('user_subscriptions')
            .update({
                status: subscription.status,
                current_period_start: new Date(subscription.current_period_start * 1000).toISOString(),
                current_period_end: new Date(subscription.current_period_end * 1000).toISOString(),
                updated_at: new Date().toISOString()
            })
            .eq('stripe_subscription_id', subscription.id);
            
        if (error) {
            console.error('Error updating subscription in Supabase:', error);
        } else {
            console.log('✅ Subscription updated in Supabase');
        }
        
    } catch (error) {
        console.error('Error handling subscription updated:', error);
    }
}

async function handleSubscriptionDeleted(subscription) {
    try {
        console.log('🔄 Handling subscription deleted:', subscription.id);
        
        // Update subscription status to canceled
        const { data, error } = await supabase
            .from('user_subscriptions')
            .update({
                status: 'canceled',
                tokens_limit: 50, // Back to free tier
                updated_at: new Date().toISOString()
            })
            .eq('stripe_subscription_id', subscription.id);
            
        if (error) {
            console.error('Error updating deleted subscription in Supabase:', error);
        } else {
            console.log('✅ Subscription marked as canceled in Supabase');
        }
        
    } catch (error) {
        console.error('Error handling subscription deleted:', error);
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
            const { data, error } = await supabase
                .from('user_subscriptions')
                .update({
                    status: 'past_due',
                    updated_at: new Date().toISOString()
                })
                .eq('stripe_subscription_id', invoice.subscription);
                
            if (error) {
                console.error('Error updating failed payment in Supabase:', error);
            } else {
                console.log('✅ Payment failure recorded in Supabase');
            }
        }
        
    } catch (error) {
        console.error('Error handling payment failed:', error);
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
