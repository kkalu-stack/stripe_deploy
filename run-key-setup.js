#!/usr/bin/env node

// Simple script to run the key setup process
// This will be executed on Render after the .env file is uploaded

console.log('🚀 Starting Trontiq API key setup...');

// Load environment variables
require('dotenv').config();

// Check if we have the required environment variables
const requiredVars = [
    'ADMIN_TOKEN',
    'OPENAI_API_KEY_1',
    'OPENAI_API_KEY_2',
    'OPENAI_API_KEY_3',
    'OPENAI_API_KEY_4',
    'OPENAI_API_KEY_5',
    'OPENAI_API_KEY_6',
    'OPENAI_API_KEY_7',
    'OPENAI_API_KEY_8',
    'OPENAI_API_KEY_9',
    'OPENAI_API_KEY_10'
];

const missingVars = requiredVars.filter(varName => !process.env[varName]);

if (missingVars.length > 0) {
    console.log('❌ Missing environment variables:');
    missingVars.forEach(varName => console.log(`   - ${varName}`));
    console.log('\n💡 Make sure your .env file is uploaded to Render Secret Files');
    process.exit(1);
}

console.log('✅ All environment variables found');
console.log('🎯 Ready to add 10 API keys for 600 RPM capacity');

// Run the key addition script
require('./add-keys-env.js');
