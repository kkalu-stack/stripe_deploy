// Refactored Popup Script - Clean separation of concerns
// Note: Popup scripts have module limitations, so we'll use the existing services

// === CLEANED I18N LOGIC: Using external translations file ===
const i18n = {
    currentLanguage: 'english',
    translations: window.TRANSLATIONS || {},

    t(key) {
        return this.translations[this.currentLanguage]?.[key] || this.translations.english?.[key] || key;
    },

    setLanguage(lang) {
        this.currentLanguage = lang;
        return Promise.resolve();
    },

    apply() {
        
        // Text content
        document.querySelectorAll('[data-i18n]').forEach(el => {
            const key = el.dataset.i18n;
            const translation = this.t(key);
            if (translation !== key) {
                el.textContent = translation;
            }
        });

        // Placeholder attributes
        document.querySelectorAll('[data-i18n-placeholder]').forEach(el => {
            const key = el.dataset.i18nPlaceholder;
            const translation = this.t(key);
            if (translation !== key) {
                el.placeholder = translation;
            }
        });

        // Title attributes
        document.querySelectorAll('[data-i18n-title]').forEach(el => {
            const key = el.dataset.i18nTitle;
            const translation = this.t(key);
            if (translation !== key) {
                el.title = translation;
            }
        });

        // CRITICAL FIX: Update dropdown option text while preserving selected values
        this.updateDropdownOptions();
    },

    updateDropdownOptions() {
        // Update language dropdown options
        const languageSelect = document.getElementById('language');
        if (languageSelect) {
            const currentValue = languageSelect.value;
            languageSelect.querySelectorAll('option').forEach(option => {
                const key = option.dataset.i18n;
                if (key) {
                    const translation = this.t(key);
                    if (translation !== key) {
                        option.textContent = translation;
                    }
                }
            });
            // Restore the selected value after updating text
            languageSelect.value = currentValue;
        }

        // Update education level dropdown options
        const educationSelect = document.getElementById('educationLevel');
        if (educationSelect) {
            const currentValue = educationSelect.value;
            educationSelect.querySelectorAll('option').forEach(option => {
                const key = option.dataset.i18n;
                if (key) {
                    const translation = this.t(key);
                    if (translation !== key) {
                        option.textContent = translation;
                    }
                }
            });
            // Restore the selected value after updating text
            educationSelect.value = currentValue;
        }

        // Update tone dropdown options
        const toneSelect = document.getElementById('tone');
        if (toneSelect) {
            const currentValue = toneSelect.value;
            toneSelect.querySelectorAll('option').forEach(option => {
                const key = option.dataset.i18n;
                if (key) {
                    const translation = this.t(key);
                    if (translation !== key) {
                        option.textContent = translation;
                    }
                }
            });
            // Restore the selected value after updating text
            toneSelect.value = currentValue;
        }
    }
};

// Make i18n globally accessible
window.i18n = i18n;

// === Language Change Handler ===
function setupLanguageChangeListener() {
    const select = document.getElementById('language');
    if (!select) return;

    const updateLanguage = (lang) => {
        
        // Save immediately - no debouncing, no duplicate prevention
        i18n.setLanguage(lang).then(() => {
            chrome.storage.local.set({ trontiq_language: lang });
            i18n.apply();
            
            // CRITICAL FIX: Ensure dropdown options are updated after language change
            setTimeout(() => {
                i18n.updateDropdownOptions();
            }, 50);
            
            // Notify content script immediately
            chrome.tabs.query({}, (tabs) => {
                tabs.forEach(tab => {
                    try {
                        chrome.tabs.sendMessage(tab.id, {
                            type: 'preference:update',
                            preference: 'language',
                            value: lang
                        }).catch(() => {});
            } catch (error) {
                        // Tab might not have content script
                    }
                });
            });
        });
    };

    select.addEventListener('change', e => updateLanguage(e.target.value));
}

class PopupController {
    constructor() {
        this.isInitialized = false;
        this.hasInitializedOnce = false; // Add guard to prevent re-initialization
        this.currentUser = null;
        this.userProfile = null;
        this.resumeAutoSaveTimer = null; // For auto-save functionality
        this.originalResumeValue = ''; // Store original resume value for change detection
    }

    // Clean up duplicate and old storage keys for consistency
    cleanupStorageKeys(storageData) {
        const keysToRemove = [];
        
        // Remove old/duplicate education keys
        if (storageData.trontiq_educationLevel && storageData.trontiq_education_level) {
            // Keep the consistent one, remove the old one
            if (storageData.trontiq_education_level !== storageData.trontiq_educationLevel) {
                // Update the consistent key with the value from the old key
                chrome.storage.local.set({
                    'trontiq_education_level': storageData.trontiq_educationLevel
                });
            }
            keysToRemove.push('trontiq_educationLevel');
        }
        
        // Remove any other duplicate keys if they exist
        if (keysToRemove.length > 0) {
            chrome.storage.local.remove(keysToRemove, () => {
            });
        }
    }

    async initialize() {
        if (this.isInitialized) return;

        try {
            
            // Initialize Supabase storage
            if (typeof TrontiqSupabaseStorage !== 'undefined') {
                window.supabaseStorage = new TrontiqSupabaseStorage(SUPABASE_CONFIG.url, SUPABASE_CONFIG.anonKey);
                
                // SECURITY: Clear any existing Supabase sessions from localStorage
                if (window.supabaseStorage.clearLocalStorageSessions) {
                    window.supabaseStorage.clearLocalStorageSessions();
                }
            } else {
                // TrontiqSupabaseStorage not available
            }
            
            // Add debug logging to check storage contents on startup
            chrome.storage.local.get(null, (result) => {
                
                // Clean up duplicate/old keys for consistency
                this.cleanupStorageKeys(result);
            });

            // Initialize i18n before first render (prevents flash of old language)
            const { trontiq_language } = await chrome.storage.local.get('trontiq_language');
            
            // FIXED: Prevent default language from overwriting saved settings
            const savedLanguage = typeof trontiq_language === 'string' && trontiq_language !== ''
                ? trontiq_language
                : 'english';
                
            await i18n.setLanguage(savedLanguage);
            
            // Subscribe to language changes (real-time)
            chrome.storage.onChanged.addListener((changes, ns) => {
                if (ns === 'local' && changes.trontiq_language) {
                    i18n.setLanguage(changes.trontiq_language.newValue).then(() => {
                        i18n.apply();
                        
                        // CRITICAL FIX: Update dropdown options after language change
                        setTimeout(() => {
                            i18n.updateDropdownOptions();
                        }, 50);
                        
                        // Refresh subscription UI with new language after a short delay - DISABLED (moved to server)
                        // setTimeout(() => {
                        //     if (window.trontiqPopup && window.trontiqPopup.stripePayment && window.trontiqPopup.stripePayment.updateSubscriptionUI) {
                        //         window.trontiqPopup.stripePayment.updateSubscriptionUI();
                        //     }
                        // }, 100);
                    });
                }
            });
            
            // Apply localization after i18n is initialized
            i18n.apply();
            
            // Check cached authentication status first to prevent flash
            const cachedAuth = await new Promise((resolve) => {
                chrome.storage.local.get(['trontiq_authenticated'], resolve);
            });
            
            
            // Note: Supabase auth calls removed - using session-based authentication instead
            
            if (cachedAuth.trontiq_authenticated === true) {
                
                // Clear sensitive data first
                this.clearSensitiveData();
                
                // Ensure supabaseStorage is available before getting user data
                if (!window.supabaseStorage) {
                    this.showAuthSection();
                    return;
                }
                
                // Get real user data from server instead of cached data
                const userData = await this.getCurrentUser();
                if (userData && userData.user) {
                    this.showMainApp(userData.user);
                } else {
                    this.showAuthSection();
                }
                
                // Set up event listeners immediately
                this.setupEventListeners();
                this.setDefaultPrivacyState();
                this.loadProfileSettings();
                setupLanguageChangeListener();
                
                            // Mark as initialized
            this.isInitialized = true;
            this.hasInitializedOnce = true;
            
            // Clear any old sensitive data from local storage
            this.clearSensitiveData();
            
            // Apply i18n and verify session in background (don't block UI)
            setTimeout(() => {
                i18n.apply();
                this.verifySessionInBackground();
            }, 100);
                
                return;
            }
            
            // Check if user is already authenticated (only if supabaseStorage is available)
            if (window.supabaseStorage) {
            const user = await this.getCurrentUser();
            if (user) {
                this.currentUser = user;
                this.showMainApp(user);
                
                // Ensure subscription data is fetched and UI is updated
                if (window.restoreWorkingSystem) {
                    setTimeout(() => window.restoreWorkingSystem(), 500);
                }
                
                // Show loading state immediately to prevent flash of default UI - DISABLED (moved to server)
                // if (window.trontiqPopup && window.trontiqPopup.stripePayment) {
                //     window.trontiqPopup.stripePayment.showLoadingState();
                // }
                
                // SECURITY: Background subscription sync removed to prevent cross-user data leakage
                
                // Apply i18n after main app is shown
                setTimeout(() => i18n.apply(), 100);
                setTimeout(() => i18n.apply(), 300);
                setTimeout(() => i18n.apply(), 500);
                setTimeout(() => i18n.apply(), 1000);
            } else {
                this.showAuthSection();
                // Apply i18n for auth section
                setTimeout(() => i18n.apply(), 100);
            }

            // Set up event listeners
            this.setupEventListeners();
            
            // Set default privacy state
            this.setDefaultPrivacyState();
            
            // Load profile settings and set up language change listener immediately
            this.loadProfileSettings();
            setupLanguageChangeListener();
            
            // Mark as initialized to prevent re-initialization
            this.isInitialized = true;
            this.hasInitializedOnce = true;
            
            // Apply i18n and verify session in background (don't block UI)
            setTimeout(() => {
                i18n.apply();
                this.verifySessionInBackground();
            }, 100);
            
            return;
        }
        
        // Check if user is already authenticated (only if supabaseStorage is available)
        if (window.supabaseStorage) {
            const user = await this.getCurrentUser();
            if (user) {
                this.currentUser = user;
                this.showMainApp(user);
                
                // Ensure subscription data is fetched and UI is updated
                if (window.restoreWorkingSystem) {
                    setTimeout(() => window.restoreWorkingSystem(), 500);
                }
                
                // Show loading state immediately to prevent flash of default UI - DISABLED (moved to server)
                // if (window.trontiqPopup && window.trontiqPopup.stripePayment) {
                //     window.trontiqPopup.stripePayment.showLoadingState();
                // }
                
                // Set up event listeners
                this.setupEventListeners();
                this.setDefaultPrivacyState();
                this.loadProfileSettings();
                setupLanguageChangeListener();
                
                // Mark as initialized
                this.isInitialized = true;
                this.hasInitializedOnce = true;
                
                // Apply i18n and verify session in background
                setTimeout(() => {
                    i18n.apply();
                    this.verifySessionInBackground();
                }, 100);
                
                return;
            }
        }
        
        // If we get here, user is not authenticated or supabaseStorage not available
        this.showAuthSection();
        this.setupEventListeners();
        setupLanguageChangeListener();
        
        // Mark as initialized
        this.isInitialized = true;
        this.hasInitializedOnce = true;
        
    } catch (error) {
            // Popup initialization error
            this.showAuthSection();
    }
}

    // Verify session in background without blocking UI
    async verifySessionInBackground() {
        try {
            
            // Check authentication state from local storage
            const result = await new Promise((resolve) => {
                chrome.storage.local.get(['trontiq_authenticated'], resolve);
            });
            
            
            if (!result.trontiq_authenticated) {
                return;
            }
            
            // Verify with server using session cookie
            const response = await fetch(`https://stripe-deploy.onrender.com/api/me`, {
                method: 'GET',
                credentials: 'include', // Important for cookies
                headers: {
                    'Content-Type': 'application/json'
                }
            });
            
            if (!response.ok) {
                chrome.storage.local.set({ 'trontiq_authenticated': false });
                return;
            }
            
            const serverData = await response.json();
            
            if (!serverData.success) {
                chrome.storage.local.set({ 'trontiq_authenticated': false });
                return;
            }
            
            
            // Update subscription UI with fresh data - DISABLED (moved to server)
            // if (window.trontiqPopup && window.trontiqPopup.stripePayment) {
            //     window.trontiqPopup.stripePayment.updateSubscriptionUI();
            // }
            
        } catch (error) {
            // Error verifying session
    }
}

    setupEventListeners() {
    // Auth tab switching
    const authTabButtons = document.querySelectorAll('.auth-tab-btn');
    const authContents = document.querySelectorAll('.auth-content');
    
    authTabButtons.forEach(button => {
        button.addEventListener('click', () => {
            const targetTab = button.getAttribute('data-auth-tab');
            
            authTabButtons.forEach(btn => btn.classList.remove('active'));
            authContents.forEach(content => content.classList.remove('active'));
            
            button.classList.add('active');
            document.getElementById(targetTab + '-content').classList.add('active');
        });
    });
    
    // Sign in form
    const signinForm = document.getElementById('signinForm');
    if (signinForm) {
            signinForm.addEventListener('submit', this.handleSignIn.bind(this));
    }
    
    // Sign up form
    const signupForm = document.getElementById('signupForm');
    if (signupForm) {
            signupForm.addEventListener('submit', this.handleSignUp.bind(this));
    }
    
    // Sign out button
    const signOutBtn = document.getElementById('signOutBtn');
    if (signOutBtn) {
            signOutBtn.addEventListener('click', this.handleSignOut.bind(this));
        }

        // Profile update button
        const updateDisplayNameBtn = document.getElementById('updateDisplayNameBtn');
        if (updateDisplayNameBtn) {
            updateDisplayNameBtn.addEventListener('click', this.handleUpdateDisplayName.bind(this));
        }

        // Change password button
        const changePasswordBtn = document.getElementById('changePasswordBtn');
        if (changePasswordBtn) {
            changePasswordBtn.addEventListener('click', this.handleChangePassword.bind(this));
        }

        // Change password modal event listeners
        const changePasswordClose = document.getElementById('changePasswordClose');
        if (changePasswordClose) {
            changePasswordClose.addEventListener('click', this.closeChangePasswordModal.bind(this));
        }

        const changePasswordCancel = document.getElementById('changePasswordCancel');
        if (changePasswordCancel) {
            changePasswordCancel.addEventListener('click', this.closeChangePasswordModal.bind(this));
        }

        const changePasswordConfirm = document.getElementById('changePasswordConfirm');
        if (changePasswordConfirm) {
            changePasswordConfirm.addEventListener('click', this.handleChangePasswordConfirm.bind(this));
        }

        // Change password toggle buttons
        const toggleCurrentPassword = document.getElementById('toggleCurrentPassword');
        if (toggleCurrentPassword) {
            toggleCurrentPassword.addEventListener('click', () => this.handleTogglePassword('currentPassword', 'toggleCurrentPassword'));
        }

        const toggleNewPassword = document.getElementById('toggleNewPassword');
        if (toggleNewPassword) {
            toggleNewPassword.addEventListener('click', () => this.handleTogglePassword('newPassword', 'toggleNewPassword'));
        }

        const toggleConfirmNewPassword = document.getElementById('toggleConfirmNewPassword');
        if (toggleConfirmNewPassword) {
            toggleConfirmNewPassword.addEventListener('click', () => this.handleTogglePassword('confirmNewPassword', 'toggleConfirmNewPassword'));
        }

        // Account management button
        const unsubscribeBtn = document.getElementById('unsubscribeBtn');
        if (unsubscribeBtn) {
            unsubscribeBtn.addEventListener('click', this.handleUnsubscribeOnly.bind(this));
        }

        const deleteAccountBtn = document.getElementById('deleteAccountBtn');
        if (deleteAccountBtn) {
            deleteAccountBtn.addEventListener('click', this.handleDeleteAccountOnly.bind(this));
        }

        // Clear All Data button (Profile tab)
        const clearAllDataBtn = document.getElementById('clearAllData');
        if (clearAllDataBtn) {
            clearAllDataBtn.addEventListener('click', this.handleClearAllData.bind(this));
        }

        // Waitlist buttons (Stripe functionality moved to separate file)
        const upgradeBtn = document.getElementById('upgradeBtn');
        if (upgradeBtn) {
            upgradeBtn.addEventListener('click', this.handleUpgradeToPro.bind(this));
        }

        const cancelSubscriptionBtn = document.getElementById('cancelSubscriptionBtn');
        if (cancelSubscriptionBtn) {
            cancelSubscriptionBtn.addEventListener('click', this.handleCancelSubscription.bind(this));
        }

        const manageSubscriptionBtn = document.getElementById('manageSubscriptionBtn');
        if (manageSubscriptionBtn) {
            manageSubscriptionBtn.addEventListener('click', this.handleManageSubscription.bind(this));
        }



        // Toggle buttons for privacy
        const toggleEmailBtn = document.getElementById('toggleEmail');
        if (toggleEmailBtn) {
            toggleEmailBtn.addEventListener('click', this.handleToggleEmail.bind(this));
        }

        const toggleFullNameBtn = document.getElementById('toggleFullName');
        if (toggleFullNameBtn) {
            toggleFullNameBtn.addEventListener('click', this.handleToggleFullName.bind(this));
        }

        // User email toggle in profile section
        const toggleUserEmailBtn = document.getElementById('toggleUserEmail');
        if (toggleUserEmailBtn) {
            toggleUserEmailBtn.addEventListener('click', this.handleToggleUserEmail.bind(this));
        }

        // Resume actions
        const saveResumeBtn = document.getElementById('saveResume');
        if (saveResumeBtn) {
            saveResumeBtn.addEventListener('click', this.handleSaveResume.bind(this));
        }

        const updateResumeBtn = document.getElementById('updateResume');
        if (updateResumeBtn) {
            updateResumeBtn.onclick = this.handleUpdateResume.bind(this);
        } else {
            // Could not find updateResume button
        }

        // Note: Profile form submission removed - preferences auto-save on change

        // Individual profile field change listeners for immediate saving
        const educationLevelEl = document.getElementById('educationLevel');
        const languageEl = document.getElementById('language');
        const toneEl = document.getElementById('tone');

        if (educationLevelEl) {
            educationLevelEl.addEventListener('change', this.handleProfileFieldChange.bind(this));
        }
        if (languageEl) {
            languageEl.addEventListener('change', this.handleProfileFieldChange.bind(this));
        }
        if (toneEl) {
            toneEl.addEventListener('change', this.handleProfileFieldChange.bind(this));
        }

        // Add click handler to resume textarea for editing
        const resumeText = document.getElementById('resumeText');
        if (resumeText) {
            resumeText.addEventListener('click', this.handleResumeTextClick.bind(this));
        }

        const cancelResumeBtn = document.getElementById('cancelResume');
        if (cancelResumeBtn) {
            cancelResumeBtn.addEventListener('click', this.handleCancelResume.bind(this));
        }

        // Auth tab switching
        const switchToSignupBtn = document.getElementById('switchToSignup');
        if (switchToSignupBtn) {
            switchToSignupBtn.addEventListener('click', () => this.switchAuthTab('signup'));
        }

        const switchToSigninBtn = document.getElementById('switchToSignin');
        if (switchToSigninBtn) {
            switchToSigninBtn.addEventListener('click', () => this.switchAuthTab('signin'));
        }

        // Password toggle functionality
        this.setupPasswordToggles();

        // Waitlist modal event listeners
        const waitlistModalClose = document.getElementById('waitlistModalClose');
        if (waitlistModalClose) {
            waitlistModalClose.addEventListener('click', this.hideWaitlistModal.bind(this));
        }

        const waitlistForm = document.getElementById('waitlistForm');
        if (waitlistForm) {
            waitlistForm.addEventListener('submit', this.handleWaitlistSubmit.bind(this));
        }

        // Close modal when clicking outside
        const waitlistModal = document.getElementById('waitlistModal');
        if (waitlistModal) {
            waitlistModal.addEventListener('click', (event) => {
                if (event.target === waitlistModal) {
                    this.hideWaitlistModal();
                }
            });
        }

        // Login error modal event listeners
        const loginErrorClose = document.getElementById('loginErrorClose');
        if (loginErrorClose) {
            loginErrorClose.addEventListener('click', this.hideLoginErrorModal.bind(this));
        }

        const loginErrorOk = document.getElementById('loginErrorOk');
        if (loginErrorOk) {
            loginErrorOk.addEventListener('click', this.hideLoginErrorModal.bind(this));
        }

        const resetPasswordBtn = document.getElementById('resetPasswordBtn');
        if (resetPasswordBtn) {
            resetPasswordBtn.addEventListener('click', this.handleResetPassword.bind(this));
        }

        const contactSupportBtn = document.getElementById('contactSupportBtn');
        if (contactSupportBtn) {
            contactSupportBtn.addEventListener('click', this.handleContactSupport.bind(this));
        }

        // Sign-in form help buttons (always visible)
        const forgotPasswordBtnSignin = document.getElementById('forgotPasswordBtnSignin');
        if (forgotPasswordBtnSignin) {
            console.log('Adding event listener to forgotPasswordBtnSignin');
            forgotPasswordBtnSignin.addEventListener('click', this.handleResetPassword.bind(this));
        } else {
            console.log('forgotPasswordBtnSignin button not found!');
        }

        const contactSupportBtnSignin = document.getElementById('contactSupportBtnSignin');
        if (contactSupportBtnSignin) {
            console.log('Adding event listener to contactSupportBtnSignin');
            contactSupportBtnSignin.addEventListener('click', this.handleContactSupport.bind(this));
        } else {
            console.log('contactSupportBtnSignin button not found!');
        }

        // Close login error modal when clicking outside
        const loginErrorModal = document.getElementById('loginErrorModal');
        if (loginErrorModal) {
            loginErrorModal.addEventListener('click', (event) => {
                if (event.target === loginErrorModal) {
                    this.hideLoginErrorModal();
                }
            });
        }

        // Email verification button event listeners
        const resendVerificationBtn = document.getElementById('resendVerificationBtn');
        if (resendVerificationBtn) {
            resendVerificationBtn.addEventListener('click', this.handleResendVerification.bind(this));
        }

        const backToSignInBtn = document.getElementById('backToSignInBtn');
        if (backToSignInBtn) {
            backToSignInBtn.addEventListener('click', this.handleBackToSignIn.bind(this));
        }

        // Check Status button removed - using email redirect only

    }

    async handleSignIn(event) {
    event.preventDefault();
    
    // Prevent multiple submissions
    const submitButton = document.getElementById('signinForm').querySelector('button[type="submit"]');
    if (submitButton.disabled) {
        return; // Already processing
    }
    
    // Clear any previous status messages
    this.clearStatus();
    
    const email = document.getElementById('signinEmail').value;
    const password = document.getElementById('signinPassword').value;
    
    if (!email || !password) {
        this.showStatus(i18n.t('please_fill_fields'), 'error');
        return;
    }
    
    const submitBtn = event.target.querySelector('button[type="submit"]');
    const originalText = submitBtn.textContent;
    submitBtn.textContent = i18n.t('signing_in');
    submitBtn.disabled = true;
    
    try {
            
            // Use Supabase authentication
            const { data, error } = await supabaseStorage.supabase.auth.signInWithPassword({
                email: email,
                password: password
            });
            
            if (error) {
                throw error;
            }
            
            if (data.user && data.session) {
                this.currentUser = data.user;
                
                // Exchange Supabase token for server session
                const exchangeResponse = await fetch('https://stripe-deploy.onrender.com/api/auth/exchange', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json'
                    },
                    credentials: 'include', // Important for cookies
                    body: JSON.stringify({
                        idToken: data.session.access_token
                    })
                });
                
                if (!exchangeResponse.ok) {
                    throw new Error('Failed to exchange token for server session');
                }
                
                
                // Store authentication state (session token is in HttpOnly cookie)
                await new Promise((resolve) => {
                    chrome.storage.local.set({
                        'trontiq_authenticated': true,
                        'trontiq_auth_timestamp': Date.now()
                    }, () => {
                        resolve();
                    });
                });
                
                // Fetch user data from server to get proper display name
                const userDataResponse = await fetch('https://stripe-deploy.onrender.com/api/me', {
                    method: 'GET',
                    credentials: 'include'
                });
                
                let serverUserData = null;
                if (userDataResponse.ok) {
                    const userData = await userDataResponse.json();
                    serverUserData = userData.user;
                    // Show main app with server user data (has proper display name)
                    this.showMainApp(serverUserData);
                } else {
                    // Fallback to Supabase data
                    this.showMainApp(data.user);
                }
                this.showStatus(i18n.t('signed_in_successfully'), 'success');
                
                // Notify background script of auth state change
                chrome.runtime.sendMessage({
                    type: 'auth:update',
                    user: {
                        id: data.user.id,
                        email: data.user.email,
                        display_name: serverUserData ? serverUserData.display_name : (data.user.user_metadata?.full_name || 'User')
                    }
                });
                
                // Notify content script that user is authenticated IMMEDIATELY
                this.notifyContentScript(true);
                
                // Broadcast authentication state to all tabs
                this.broadcastAuthStateChange(true);
                
                // SECURITY: Clear any existing Supabase sessions from localStorage
                if (window.supabaseStorage && window.supabaseStorage.clearLocalStorageSessions) {
                    window.supabaseStorage.clearLocalStorageSessions();
                }
                
            } else {
                this.showLoginErrorModal(i18n.t('sign_in_failed') + ': ' + i18n.t('no_user_data'));
        }
    } catch (error) {
        // Sign in error
        
        let errorMessage = i18n.t('sign_in_failed');
        
        // Handle different error formats
        if (error && typeof error === 'object') {
            if (error.message) {
                if (error.message.includes('Invalid login credentials') || error.message.includes('Invalid login') || 
                    error.message.includes('invalid_credentials') || error.message.includes('Invalid email or password') ||
                    error.message.includes('Email not confirmed') || error.message.includes('Invalid credentials')) {
                    errorMessage = i18n.t('invalid_credentials');
                } else if (error.message.includes('network') || error.message.includes('Network')) {
                    errorMessage = i18n.t('network_error');
                } else if (error.message.includes('400')) {
                    errorMessage = i18n.t('invalid_credentials');
                } else {
                    // For any other error, use the translated generic error message instead of raw English
                    errorMessage = i18n.t('sign_in_failed');
                }
            } else if (error.error_description) {
                // Check if error_description contains credential-related errors
                if (error.error_description.includes('Invalid login credentials') || 
                    error.error_description.includes('Invalid email or password') ||
                    error.error_description.includes('invalid_credentials')) {
                    errorMessage = i18n.t('invalid_credentials');
                } else {
                    errorMessage = i18n.t('sign_in_failed');
                }
            } else if (error.msg) {
                // Check if msg contains credential-related errors
                if (error.msg.includes('Invalid login credentials') || 
                    error.msg.includes('Invalid email or password') ||
                    error.msg.includes('invalid_credentials')) {
                    errorMessage = i18n.t('invalid_credentials');
                } else {
                    errorMessage = i18n.t('sign_in_failed');
                }
            } else {
                errorMessage = i18n.t('sign_in_failed');
            }
        } else if (typeof error === 'string') {
            // For string errors, use generic translated message instead of raw error
            errorMessage = i18n.t('sign_in_failed');
        }
        
        this.showLoginErrorModal(errorMessage);
    } finally {
        submitBtn.textContent = originalText;
        submitBtn.disabled = false;
    }
}

    async handleSignUp(event) {
    event.preventDefault();
    
    // Clear any previous status messages
    this.clearStatus();
    
    const fullName = document.getElementById('signupFullName').value;
    const displayName = document.getElementById('signupDisplayName').value;
    const email = document.getElementById('signupEmail').value;
    const password = document.getElementById('signupPassword').value;
    const confirmPassword = document.getElementById('signupConfirmPassword').value;
    
    if (!fullName || !displayName || !email || !password || !confirmPassword) {
        this.showStatus(i18n.t('please_fill_fields'), 'error');
        return;
    }
    
    if (password.length < 8) {
        this.showStatus(i18n.t('password_too_short'), 'error');
        return;
    }
    
    if (password !== confirmPassword) {
        this.showStatus(i18n.t('passwords_dont_match'), 'error');
        return;
    }
    
    const submitBtn = event.target.querySelector('button[type="submit"]');
    const originalText = submitBtn.textContent;
    submitBtn.textContent = i18n.t('creating_account');
    submitBtn.disabled = true;
    
    try {
            console.log('Starting signup process...');
            const result = await this.signUp(email, password, displayName, fullName);
            console.log('Signup result:', result);
        
        if (result && result.success) {
                console.log('Signup successful, showing verification screen');
                // Show email verification screen instead of auto-signin
                this.showEmailVerificationScreen(email, displayName);
                this.showStatus(i18n.t('verify_email_sent'), 'success');
                
                // Handle user preferences in background (non-blocking)
                this.createUserPreferencesInBackground(email, displayName, fullName);
        } else {
                console.log('Signup failed, result:', result);
                // Signup failed - show error
                this.showStatus(i18n.t('sign_up_failed'), 'error');
        }
    } catch (error) {
        // Sign up error
        
        let errorMessage = i18n.t('sign_up_failed');
        if (error.message) {
            if (error.message.includes('email') || error.message.includes('Email') || 
                error.message.includes('already exists') || error.message.includes('already registered')) {
                errorMessage = i18n.t('invalid_email_or_exists');
            } else if (error.message.includes('password') || error.message.includes('Password')) {
                errorMessage = i18n.t('password_too_short');
            } else if (error.message.includes('network') || error.message.includes('Network')) {
                errorMessage = i18n.t('network_error');
            } else {
                // For any other error, use the translated generic error message instead of raw English
                errorMessage = i18n.t('sign_up_failed');
            }
        }
        
        this.showStatus(errorMessage, 'error');
    } finally {
        submitBtn.textContent = originalText;
        submitBtn.disabled = false;
    }
    }

    async createUserPreferencesInBackground(email, displayName, fullName) {
        // Create user preferences in background without blocking UI
        try {
            const preferencesResponse = await fetch('https://stripe-deploy.onrender.com/api/me', {
                method: 'POST',
                credentials: 'include',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({
                    display_name: displayName,
                    full_name: fullName,
                    email: email
                })
            });

            if (preferencesResponse.ok) {
                console.log('User preferences created in background');
            } else {
                console.log('Failed to create user preferences in background');
            }
        } catch (error) {
            console.log('Error creating user preferences in background:', error);
        }
    }

    showEmailVerificationScreen(email, displayName) {
        // Hide auth section and show verification section
        const authSection = document.getElementById('authSection');
        const verificationSection = document.getElementById('emailVerificationSection');
        
        if (authSection) {
            authSection.style.display = 'none';
        }
        
        if (verificationSection) {
            verificationSection.style.display = 'block';
            
            // Update the email display
            const emailDisplay = verificationSection.querySelector('.verification-email');
            if (emailDisplay) {
                emailDisplay.textContent = email;
            }
        }
        
        // Don't start auto-polling - let user manually check
    }

    // Removed startVerificationPolling - now using manual check only

    async checkVerificationStatus(email) {
        try {
            // Try to sign in with the email to check if verification is complete
            const password = document.getElementById('signupPassword').value;
            if (!password) {
                return false;
            }
            
            const signInResult = await this.signIn(email, password);
            return signInResult.success;
        } catch (error) {
            return false;
        }
    }

    async handleVerificationComplete(email) {
        // No polling to stop - using manual check only
        
        try {
            // Get the password from the signup form
            const password = document.getElementById('signupPassword').value;
            if (!password) {
                throw new Error('Password not found');
            }
            
            // Sign in the user now that verification is complete
            const signInResult = await this.signIn(email, password);
            
            if (signInResult.success) {
                // Store authentication state
                await new Promise((resolve) => {
                    chrome.storage.local.set({
                        'trontiq_authenticated': true,
                        'trontiq_auth_timestamp': Date.now()
                    }, () => {
                        resolve();
                    });
                });
                
                // Fetch user data from server
                const userDataResponse = await fetch('https://stripe-deploy.onrender.com/api/me', {
                    method: 'GET',
                    credentials: 'include'
                });
                
                let serverUserData = null;
                if (userDataResponse.ok) {
                    const userData = await userDataResponse.json();
                    serverUserData = userData.user;
                }
                
                // Use server user data if available, otherwise use signup result
                const finalUserData = serverUserData || signInResult.user;
                
                // Show main app
                this.showMainApp(finalUserData);
                
                // Notify background script
                chrome.runtime.sendMessage({
                    type: 'auth:update',
                    user: finalUserData
                });
                
                // Notify content script
                this.notifyContentScript(true);
                
                // Broadcast auth state change
                this.broadcastAuthStateChange(true);
                
                this.showStatus(i18n.t('email_verified_successfully'), 'success');
            }
        } catch (error) {
            this.showStatus(i18n.t('verification_error'), 'error');
        }
    }

    async handleResendVerification() {
        try {
            const email = document.getElementById('signupEmail').value;
            if (!email) {
                this.showStatus(i18n.t('email_required'), 'error');
                return;
            }
            
            // Show loading state
            const resendBtn = document.getElementById('resendVerificationBtn');
            const originalText = resendBtn.textContent;
            resendBtn.textContent = i18n.t('sending');
            resendBtn.disabled = true;
            
            // Resend verification email
            if (!window.supabaseStorage || !window.supabaseStorage.supabase) {
                throw new Error('Supabase client not available');
            }
            
            const { data, error } = await window.supabaseStorage.supabase.auth.resendVerificationEmail({
                email: email,
                redirectTo: 'https://stripe-deploy.onrender.com/auth/verify-complete'
            });
            
            if (error) {
                throw error;
            }
            
            this.showStatus(i18n.t('verification_email_resent'), 'success');
            
        } catch (error) {
            this.showStatus(i18n.t('resend_verification_failed'), 'error');
        } finally {
            // Restore button state
            const resendBtn = document.getElementById('resendVerificationBtn');
            if (resendBtn) {
                resendBtn.textContent = i18n.t('resend_verification');
                resendBtn.disabled = false;
            }
        }
    }

    async handleBackToSignIn() {
        // Hide verification section and show auth section
        const authSection = document.getElementById('authSection');
        const verificationSection = document.getElementById('emailVerificationSection');
        
        if (verificationSection) {
            verificationSection.style.display = 'none';
        }
        
        if (authSection) {
            authSection.style.display = 'block';
        }
        
        // No polling to stop - using manual check only
        
        // Switch to sign in tab
        this.switchAuthTab('signin');
    }

    // handleCheckStatus method removed - using email redirect only

    async handleSignOut() {
        try {
            // IMMEDIATELY clear authentication state to trigger widget removal
            await new Promise((resolve) => {
                chrome.storage.local.remove(['trontiq_authenticated'], () => {
                    if (chrome.runtime.lastError) {
                        // Error clearing authentication data
                    } else {
                    }
                    resolve();
                });
            });
            
            // Call server logout endpoint
            const logoutResponse = await fetch('https://stripe-deploy.onrender.com/api/auth/logout', {
                method: 'POST',
                credentials: 'include', // Important for cookies
                headers: {
                    'Content-Type': 'application/json'
                }
            });
            
            if (logoutResponse.ok) {
            } else {
            }
            
            this.currentUser = null;
            this.userProfile = null;
            this.showAuthSection();
            this.showStatus(i18n.t('signed_out_successfully'), 'success');
            
            // Clear ALL sensitive data from chrome.storage.local
            this.clearSensitiveData();
            
            // Notify background script of auth state change
            chrome.runtime.sendMessage({
                type: 'auth:update',
                user: null
            });
        
            // IMMEDIATELY notify content script that user is not authenticated
            this.notifyContentScript(false);
            
            // Also broadcast auth state change to ensure all tabs get the message
            this.broadcastAuthStateChange(false);
            
            // Force immediate widget removal by sending a direct message
            chrome.tabs.query({}, (tabs) => {
                tabs.forEach(tab => {
                    try {
                        chrome.tabs.sendMessage(tab.id, {
                            type: 'FORCE_REMOVE_WIDGET',
                            reason: 'user_signed_out'
                        }).catch((error) => {
                            // Could not send force remove message to tab
                        });
                    } catch (error) {
                        // Error sending force remove message to tab
                    }
                });
            });
            
            // Sign out complete - widget should be removed from all tabs
    } catch (error) {
        // Sign out error
        this.showStatus(i18n.t('sign_out_failed'), 'error');
    }
}

    async handleUpdateDisplayName() {
    const newDisplayName = document.getElementById('accountDisplayName').value.trim();
    
    if (!newDisplayName) {
        this.showStatus('Please enter a display name', 'error');
        return;
    }
    
    const updateBtn = document.getElementById('updateDisplayNameBtn');
    const originalText = updateBtn.textContent;
    updateBtn.textContent = i18n.t('updating');
    updateBtn.disabled = true;
    
    try {
            // Update user metadata in Supabase
            const { data, error } = await this.updateUser({ display_name: newDisplayName });
            
            if (error) throw error;
            
                    // Save to server endpoint using session-based authentication
            try {
                const response = await fetch('https://stripe-deploy.onrender.com/api/me', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json'
                    },
                    credentials: 'include', // Use HttpOnly cookies for authentication
                    body: JSON.stringify({ display_name: newDisplayName })
                });
                
                if (response.ok) {
                    // Display name saved to server
                    
                    // Broadcast the change to other parts of the extension
                    this.broadcastAuthStateChange(true);
                } else {
                    // Error saving display name to server
                }
            } catch (error) {
                // Error saving display name to server
            }
            
            // Update the display name in the Profile tab (read-only field)
            const profileDisplayName = document.getElementById('displayName');
            if (profileDisplayName) {
                profileDisplayName.value = newDisplayName;
            }
            
            // Update the display in the user profile section
        const userDisplayName = document.getElementById('userDisplayName');
        if (userDisplayName) {
            userDisplayName.textContent = newDisplayName;
        }
        
        // Update initials
        const userInitials = document.getElementById('userInitials');
        if (userInitials) {
            const initials = newDisplayName.split(' ').map(name => name[0]).join('').toUpperCase().slice(0, 2);
            userInitials.textContent = initials;
        }
            
            // Refresh user data from server to ensure consistency
            try {
                const userData = await this.getCurrentUser();
                if (userData && userData.user) {
                    // User data refreshed after display name update
                }
            } catch (error) {
                // Error refreshing user data
            }
            
            // No chrome.storage for display name - server-only
            // Display name updated on server - cross-tab sync via messages only
            
            // Notify content scripts about the display name update
            chrome.tabs.query({}, (tabs) => {
                // Sending display name update to tabs
                tabs.forEach(tab => {
                    try {
                        const message = {
                            type: 'display_name_updated',
                            displayName: newDisplayName,
                            timestamp: Date.now()
                        };
                        // Sending to tab
                        chrome.tabs.sendMessage(tab.id, message).catch((error) => {
                            // Tab might not have content script
                        });
                    } catch (error) {
                        // Error sending to tab
                    }
                });
            });
        
            this.showStatus(i18n.t('display_name_updated'), 'success');
    } catch (error) {
        // Update display name error
        this.showStatus('Failed to update display name. Please try again.', 'error');
    } finally {
        updateBtn.textContent = originalText;
        updateBtn.disabled = false;
    }
}

    // Change Password Methods
    handleChangePassword() {
        // Show the change password modal
        const modal = document.getElementById('changePasswordModal');
        if (modal) {
            modal.style.display = 'flex';
            
            // Clear form fields
            document.getElementById('currentPassword').value = '';
            document.getElementById('newPassword').value = '';
            document.getElementById('confirmNewPassword').value = '';
        }
    }

    closeChangePasswordModal() {
        // Hide the change password modal
        const modal = document.getElementById('changePasswordModal');
        if (modal) {
            modal.style.display = 'none';
            
            // Clear form fields
            document.getElementById('currentPassword').value = '';
            document.getElementById('newPassword').value = '';
            document.getElementById('confirmNewPassword').value = '';
        }
    }

    async handleChangePasswordConfirm() {
        const currentPassword = document.getElementById('currentPassword').value;
        const newPassword = document.getElementById('newPassword').value;
        const confirmNewPassword = document.getElementById('confirmNewPassword').value;
        
        // Validation
        if (!currentPassword || !newPassword || !confirmNewPassword) {
            this.showStatus(i18n.t('please_fill_fields'), 'error');
            return;
        }
        
        if (newPassword.length < 8) {
            this.showStatus(i18n.t('password_too_short'), 'error');
            return;
        }
        
        if (newPassword !== confirmNewPassword) {
            this.showStatus(i18n.t('passwords_do_not_match'), 'error');
            return;
        }
        
        const confirmBtn = document.getElementById('changePasswordConfirm');
        const originalText = confirmBtn.textContent;
        
        try {
            confirmBtn.textContent = i18n.t('sending');
            confirmBtn.disabled = true;
            
            console.log('Attempting to update password...');
            console.log('Supabase client:', window.supabaseStorage.supabase);
            console.log('Auth object:', window.supabaseStorage.supabase.auth);
            console.log('UpdateUser method:', window.supabaseStorage.supabase.auth.updateUser);
            
            // Call Supabase to update password
            const { data, error } = await window.supabaseStorage.supabase.auth.updateUser({
                password: newPassword
            });
            
            console.log('UpdateUser response:', { data, error });
            
            if (error) {
                throw error;
            }
            
            // Success - check if reauthentication is required
            if (data && data.requiresReauth) {
                // Password changed successfully but session was invalidated
                this.showStatus(data.message || i18n.t('password_changed_please_login'), 'success');
                this.closeChangePasswordModal();
                
                // Sign out user to clear local session
                setTimeout(async () => {
                    try {
                        await window.supabaseStorage.signOut();
                        this.handleSignOut();
                    } catch (error) {
                        console.error('Error signing out after password change:', error);
                        // Force logout anyway
                        this.handleSignOut();
                    }
                }, 2000); // Show success message for 2 seconds before logout
            } else {
                // Legacy behavior (shouldn't happen with new implementation)
                this.showStatus(i18n.t('password_changed_successfully'), 'success');
                this.closeChangePasswordModal();
            }
            
        } catch (error) {
            console.error('Password change error:', error);
            console.error('Error details:', JSON.stringify(error, null, 2));
            
            let errorMessage = i18n.t('password_change_failed');
            if (error.message && error.message.includes('Invalid login credentials')) {
                errorMessage = i18n.t('current_password_incorrect');
            } else if (error.message) {
                errorMessage = error.message;
            }
            
            this.showStatus(errorMessage, 'error');
        } finally {
            confirmBtn.textContent = originalText;
            confirmBtn.disabled = false;
        }
    }

    async handleResumeExtraction() {
        const file = document.getElementById('resumeUpload').files[0];
        if (!file) {
        this.showStatus('Please select a file first.', 'error');
        return;
    }
        
        if (file.type === 'text/plain') {
            const reader = new FileReader();
            reader.onload = async (e) => {
                const text = e.target.result;
                await this.extractProfileFromText(text);
            };
            reader.readAsText(file);
        } else {
            this.showStatus('Please select a TXT file or use the copy-paste option.', 'error');
        }
    }

    async handleSaveResume() {
        const text = document.getElementById('resumeText').value.trim();
        
        if (!text) {
        this.showStatus('Please paste your resume text first.', 'error');
        return;
    }
        
        // Attempting to save resume to server
        
        try {
            // Save to server endpoint using session-based authentication
            const response = await fetch('https://stripe-deploy.onrender.com/api/resume', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                credentials: 'include', // Use HttpOnly cookies for authentication
                body: JSON.stringify({ resume_text: text })
            });
            
            if (response.ok) {
                const result = await response.json();
                // Resume saved to server
        
                // Update the original value for change detection
                this.originalResumeValue = text;
        
        // Make textarea read-only and show saved content
        this.setResumeReadOnly(text);
        
        // Show permanent notification
                this.showResumeSavedNotification(result.data.saved_date);
        
        this.showStatus('Resume saved successfully!', 'success');
                
                // Notify content scripts and background script about the resume update
                chrome.tabs.query({}, (tabs) => {
                    tabs.forEach(tab => {
                        try {
                            chrome.tabs.sendMessage(tab.id, {
                                type: 'resume_updated',
                                timestamp: Date.now()
                            }).catch(() => {});
                        } catch (error) {
                            // Tab might not have content script
                        }
                    });
                });
                
                // Also notify background script to refresh its cached profile
                chrome.runtime.sendMessage({
                    type: 'resume_updated',
                    timestamp: Date.now()
                }).catch(() => {
                    // Background script might not be available
                });
            } else {
                // Error saving resume to server
                this.showStatus('Error saving resume to server', 'error');
            }
        } catch (error) {
            // Error saving resume
            this.showStatus('Error saving resume. Please try again.', 'error');
        }
    }

    handleToggleEmail() {
        const emailInput = document.getElementById('accountEmail');
        const toggleBtn = document.getElementById('toggleEmail');
        const toggleIcon = toggleBtn.querySelector('.toggle-icon');
        
        if (emailInput.classList.contains('hidden')) {
            emailInput.classList.remove('hidden');
            toggleIcon.innerHTML = '<path d="M12 4.5C7 4.5 2.73 7.61 1 12c1.73 4.39 6 7.5 11 7.5s9.27-3.11 11-7.5c-1.73-4.39-6-7.5-11-7.5zM12 17c-2.76 0-5-2.24-5-5s2.24-5 5-5 5 2.24 5 5-2.24 5-5 5zm0-8c-1.66 0-3 1.34-3 3s1.34 3 3 3 3-1.34 3-3-1.34-3-3-3z"/>';
            toggleBtn.title = 'Hide Email';
        } else {
            emailInput.classList.add('hidden');
            toggleIcon.innerHTML = '<path d="M12 7c2.76 0 5 2.24 5 5 0 .65-.13 1.26-.36 1.83l2.92 2.92c1.51-1.26 2.7-2.89 3.43-4.75-1.73-4.39-6-7.5-11-7.5-1.4 0-2.74.25-3.98.7l2.16 2.16C10.74 7.13 11.35 7 12 7zM2 4.27l2.28 2.28.46.46C3.08 8.3 1.78 10.02 1 12c1.73 4.39 6 7.5 11 7.5 1.55 0 3.03-.3 4.38-.84l.42.42L19.73 22 21 20.73 3.27 3 2 4.27zM7.53 9.8l1.55 1.55c-.05.21-.08.43-.08.65 0 1.66 1.34 3 3 3 .22 0 .44-.03.65-.08l1.55 1.55c-.67.33-1.41.53-2.2.53-2.76 0-5-2.24-5-5 0-.79.2-1.53.53-2.2zm4.31-.78l3.15 3.15.02-.16c0-1.66-1.34-3-3-3l-.17.01z"/>';
            toggleBtn.title = 'Show Email';
        }
    }

    handleToggleFullName() {
        const fullNameInput = document.getElementById('accountFullName');
        const toggleBtn = document.getElementById('toggleFullName');
        const toggleIcon = toggleBtn.querySelector('.toggle-icon');
        
        if (fullNameInput.classList.contains('hidden')) {
            fullNameInput.classList.remove('hidden');
            toggleIcon.innerHTML = '<path d="M12 4.5C7 4.5 2.73 7.61 1 12c1.73 4.39 6 7.5 11 7.5s9.27-3.11 11-7.5c-1.73-4.39-6-7.5-11-7.5zM12 17c-2.76 0-5-2.24-5-5s2.24-5 5-5 5 2.24 5 5-2.24 5-5 5zm0-8c-1.66 0-3 1.34-3 3s1.34 3 3 3 3-1.34 3-3-1.34-3-3-3z"/>';
            toggleBtn.title = 'Hide Full Name';
        } else {
            fullNameInput.classList.add('hidden');
            toggleIcon.innerHTML = '<path d="M12 7c2.76 0 5 2.24 5 5 0 .65-.13 1.26-.36 1.83l2.92 2.92c1.51-1.26 2.7-2.89 3.43-4.75-1.73-4.39-6-7.5-11-7.5-1.4 0-2.74.25-3.98.7l2.16 2.16C10.74 7.13 11.35 7 12 7zM2 4.27l2.28 2.28.46.46C3.08 8.3 1.78 10.02 1 12c1.73 4.39 6 7.5 11 7.5 1.55 0 3.03-.3 4.38-.84l.42.42L19.73 22 21 20.73 3.27 3 2 4.27zM7.53 9.8l1.55 1.55c-.05.21-.08.43-.08.65 0 1.66 1.34 3 3 3 .22 0 .44-.03.65-.08l1.55 1.55c-.67.33-1.41.53-2.2.53-2.76 0-5-2.24-5-5 0-.79.2-1.53.53-2.2zm4.31-.78l3.15 3.15.02-.16c0-1.66-1.34-3-3-3l-.17.01z"/>';
            toggleBtn.title = 'Show Full Name';
        }
    }

    handleToggleUserEmail() {
        const userEmail = document.getElementById('userEmail');
        const toggleBtn = document.getElementById('toggleUserEmail');
        const toggleIcon = toggleBtn.querySelector('.toggle-icon-small');
        
        if (userEmail.classList.contains('hidden')) {
            userEmail.classList.remove('hidden');
            toggleIcon.innerHTML = '<path d="M12 4.5C7 4.5 2.73 7.61 1 12c1.73 4.39 6 7.5 11 7.5s9.27-3.11 11-7.5c-1.73-4.39-6-7.5-11-7.5zM12 17c-2.76 0-5-2.24-5-5s2.24-5 5-5 5 2.24 5 5-2.24 5-5 5zm0-8c-1.66 0-3 1.34-3 3s1.34 3 3 3 3-1.34 3-3-1.34-3-3-3z"/>';
            toggleBtn.title = 'Hide Email';
        } else {
            userEmail.classList.add('hidden');
            toggleIcon.innerHTML = '<path d="M12 7c2.76 0 5 2.24 5 5 0 .65-.13 1.26-.36 1.83l2.92 2.92c1.51-1.26 2.7-2.89 3.43-4.75-1.73-4.39-6-7.5-11-7.5-1.4 0-2.74.25-3.98.7l2.16 2.16C10.74 7.13 11.35 7 12 7zM2 4.27l2.28 2.28.46.46C3.08 8.3 1.78 10.02 1 12c1.73 4.39 6 7.5 11 7.5 1.55 0 3.03-.3 4.38-.84l.42.42L19.73 22 21 20.73 3.27 3 2 4.27zM7.53 9.8l1.55 1.55c-.05.21-.08.43-.08.65 0 1.66 1.34 3 3 3 .22 0 .44-.03.65-.08l1.55 1.55c-.67.33-1.41.53-2.2.53-2.76 0-5-2.24-5-5 0-.79.2-1.53.53-2.2zm4.31-.78l3.15 3.15.02-.16c0-1.66-1.34-3-3-3l-.17.01z"/>';
            toggleBtn.title = 'Show Email';
        }
    }

    handleTogglePassword(inputId, toggleId) {
        const passwordInput = document.getElementById(inputId);
        const toggleBtn = document.getElementById(toggleId);
        const toggleIcon = toggleBtn.querySelector('.toggle-icon');
        
        if (passwordInput.type === 'password') {
            passwordInput.type = 'text';
            toggleIcon.innerHTML = '<path d="M2.73 21.18l15.46-15.46a1 1 0 0 0-1.42-1.42L1.31 19.76a1 1 0 0 0 1.42 1.42zM9.88 9.88a3 3 0 1 0 4.24 4.24l-1.41-1.41a1 1 0 1 1-1.42-1.42l1.41-1.41zM15.89 15.89a5 5 0 0 1-6.36.59l1.41-1.41a3 3 0 0 0 4.24-4.24l1.41-1.41a5 5 0 0 1-.7 6.47zM12 6.5a5.5 5.5 0 0 1 5.5 5.5 1 1 0 0 0 2 0A7.5 7.5 0 0 0 12 4.5a1 1 0 0 0 0 2z"/>';
            toggleBtn.title = 'Hide Password';
        } else {
            passwordInput.type = 'password';
            toggleIcon.innerHTML = '<path d="M12 4.5C7 4.5 2.73 7.61 1 12c1.73 4.39 6 7.5 11 7.5s9.27-3.11 11-7.5c-1.73-4.39-6-7.5-11-7.5zM12 17c-2.76 0-5-2.24-5-5s2.24-5 5-5 5 2.24 5 5-2.24 5-5 5zm0-8c-1.66 0-3 1.34-3 3s1.34 3 3 3 3-1.34 3-3-1.34-3-3-3z"/>';
            toggleBtn.title = 'Show Password';
        }
    }

    setDefaultPrivacyState() {
        // Set all privacy fields to hidden by default
        const emailInput = document.getElementById('accountEmail');
        const fullNameInput = document.getElementById('accountFullName');
    const userEmail = document.getElementById('userEmail');
        const toggleEmailBtn = document.getElementById('toggleEmail');
        const toggleFullNameBtn = document.getElementById('toggleFullName');
        const toggleUserEmailBtn = document.getElementById('toggleUserEmail');

        if (emailInput && toggleEmailBtn) {
            emailInput.classList.add('hidden');
            const toggleIcon = toggleEmailBtn.querySelector('.toggle-icon');
            toggleIcon.innerHTML = '<path d="M12 7c2.76 0 5 2.24 5 5 0 .65-.13 1.26-.36 1.83l2.92 2.92c1.51-1.26 2.7-2.89 3.43-4.75-1.73-4.39-6-7.5-11-7.5-1.4 0-2.74.25-3.98.7l2.16 2.16C10.74 7.13 11.35 7 12 7zM2 4.27l2.28 2.28.46.46C3.08 8.3 1.78 10.02 1 12c1.73 4.39 6 7.5 11 7.5 1.55 0 3.03-.3 4.38-.84l.42.42L19.73 22 21 20.73 3.27 3 2 4.27zM7.53 9.8l1.55 1.55c-.05.21-.08.43-.08.65 0 1.66 1.34 3 3 3 .22 0 .44-.03.65-.08l1.55 1.55c-.67.33-1.41.53-2.2.53-2.76 0-5-2.24-5-5 0-.79.2-1.53.53-2.2zm4.31-.78l3.15 3.15.02-.16c0-1.66-1.34-3-3-3l-.17.01z"/>';
            toggleEmailBtn.title = 'Show Email';
        }

        if (fullNameInput && toggleFullNameBtn) {
            fullNameInput.classList.add('hidden');
            const toggleIcon = toggleFullNameBtn.querySelector('.toggle-icon');
            toggleIcon.innerHTML = '<path d="M12 7c2.76 0 5 2.24 5 5 0 .65-.13 1.26-.36 1.83l2.92 2.92c1.51-1.26 2.7-2.89 3.43-4.75-1.73-4.39-6-7.5-11-7.5-1.4 0-2.74.25-3.98.7l2.16 2.16C10.74 7.13 11.35 7 12 7zM2 4.27l2.28 2.28.46.46C3.08 8.3 1.78 10.02 1 12c1.73 4.39 6 7.5 11 7.5 1.55 0 3.03-.3 4.38-.84l.42.42L19.73 22 21 20.73 3.27 3 2 4.27zM7.53 9.8l1.55 1.55c-.05.21-.08.43-.08.65 0 1.66 1.34 3 3 3 .22 0 .44-.03.65-.08l1.55 1.55c-.67.33-1.41.53-2.2.53-2.76 0-5-2.24-5-5 0-.79.2-1.53.53-2.2zm4.31-.78l3.15 3.15.02-.16c0-1.66-1.34-3-3-3l-.17.01z"/>';
            toggleFullNameBtn.title = 'Show Full Name';
        }

        if (userEmail && toggleUserEmailBtn) {
            userEmail.classList.add('hidden');
            const toggleIcon = toggleUserEmailBtn.querySelector('.toggle-icon-small');
            toggleIcon.innerHTML = '<path d="M12 7c2.76 0 5 2.24 5 5 0 .65-.13 1.26-.36 1.83l2.92 2.92c1.51-1.26 2.7-2.89 3.43-4.75-1.73-4.39-6-7.5-11-7.5-1.4 0-2.74.25-3.98.7l2.16 2.16C10.74 7.13 11.35 7 12 7zM2 4.27l2.28 2.28.46.46C3.08 8.3 1.78 10.02 1 12c1.73 4.39 6 7.5 11 7.5 1.55 0 3.03-.3 4.38-.84l.42.42L19.73 22 21 20.73 3.27 3 2 4.27zM7.53 9.8l1.55 1.55c-.05.21-.08.43-.08.65 0 1.66 1.34 3 3 3 .22 0 .44-.03.65-.08l1.55 1.55c-.67.33-1.41.53-2.2.53-2.76 0-5-2.24-5-5 0-.79.2-1.53.53-2.2zm4.31-.78l3.15 3.15.02-.16c0-1.66-1.34-3-3-3l-.17.01z"/>';
            toggleUserEmailBtn.title = 'Show Email';
        }
    }

    // Setup password toggle functionality
    setupPasswordToggles() {
        const passwordToggles = document.querySelectorAll('.password-toggle');
        
        passwordToggles.forEach(toggle => {
            toggle.addEventListener('click', (e) => {
                e.preventDefault();
                e.stopPropagation();
                
                const targetId = toggle.getAttribute('data-target');
                const passwordInput = document.getElementById(targetId);
                
                if (!passwordInput) {
                    // Password input not found
                    return;
                }
                
                // Toggle password visibility
                if (passwordInput.type === 'password') {
                    passwordInput.type = 'text';
                    toggle.classList.add('showing');
                    toggle.title = 'Hide password';
                } else {
                    passwordInput.type = 'password';
                    toggle.classList.remove('showing');
                    toggle.title = 'Show password';
                }
                
                // Toggle eye icon visibility
                const eyeOpen = toggle.querySelector('.eye-open');
                const eyeClosed = toggle.querySelector('.eye-closed');
                
                if (eyeOpen && eyeClosed) {
                    if (passwordInput.type === 'text') {
                        eyeOpen.style.display = 'none';
                        eyeClosed.style.display = 'block';
                    } else {
                        eyeOpen.style.display = 'block';
                        eyeClosed.style.display = 'none';
                    }
                }
            });
        });
        
        // Password toggle functionality initialized
    }

    // Note: handleProfileFormSubmit function removed - preferences now auto-save on change

    async loadProfileSettings() {
        // Loading saved profile settings from server
        
        try {
            // Get current user ID
            const userData = await this.getCurrentUser();
            if (!userData || !userData.user || !userData.user.id) {
                // No user data available for loading preferences
                return;
            }
            
            // Load preferences from local storage (fast, UI-only) - Use consistent key names
            chrome.storage.local.get([
                'trontiq_education_level',    // Consistent with server
                'trontiq_language', 
                'trontiq_tone'
            ], (result) => {
                const savedEducationLevel = result.trontiq_education_level || 'bachelor';
                const savedLanguage = result.trontiq_language || 'english';
                const savedTone = result.trontiq_tone || 'professional';
        
                // Update form fields with saved values (without triggering change events)
                const educationSelect = document.getElementById('educationLevel');
                const languageSelect = document.getElementById('language');
                const toneSelect = document.getElementById('tone');
                
                if (educationSelect && savedEducationLevel) {
                    educationSelect.value = savedEducationLevel;
                    // Education level loaded from local storage
                }
                
                if (languageSelect && savedLanguage) {
                    languageSelect.value = savedLanguage;
                    // Language loaded from local storage
                }
                
                if (toneSelect && savedTone) {
                    toneSelect.value = savedTone;
                    // Tone loaded from local storage
                }
                
                // CRITICAL FIX: Re-apply i18n to ensure dropdown text matches selected values
                setTimeout(() => {
                    i18n.updateDropdownOptions();
                    // Dropdown options updated after loading preferences
                }, 100);
                
                // Profile settings loaded from local storage
            });
        } catch (error) {
            // Error loading profile settings from server
            // No fallback to local storage - server endpoints only
        }
    }

    refreshLanguageFromStorage() {
        // FIXED: Only refresh if we haven't initialized yet and there's a saved language
        if (this.hasInitializedOnce) {
            // Skipping language refresh - already initialized
            return;
        }
        
        // Force refresh language from storage to ensure consistency
        chrome.storage.local.get(['trontiq_language'], async (result) => {
            const savedLanguage = result.trontiq_language;
            if (savedLanguage && savedLanguage !== i18n.currentLanguage) {
                // Refreshing language from storage
                await i18n.setLanguage(savedLanguage);
                i18n.apply();
                // Language refreshed from storage
            }
        });
    }

    async handleProfileFieldChange(event) {
        // Save individual field changes immediately
        const fieldName = event.target.id;
        const fieldValue = event.target.value;
        
        // Field changed
        
        try {
            // Get current user ID
            const userData = await this.getCurrentUser();
            if (!userData || !userData.user || !userData.user.id) {
                // No user data available for saving field change
                return;
            }
            
            // Map field names to server endpoints
            const endpointMap = {
                'tone': 'tone',
                'educationLevel': 'education', 
                'education': 'education', 
                'language': 'language'
            };
            
            const endpointField = endpointMap[fieldName];
            if (!endpointField) {
                // Unknown field
                return;
            }
            
            // Save to local storage (fast, UI-only) - Use consistent key names
            const keyMap = {
                'tone': 'trontiq_tone',
                'educationLevel': 'trontiq_education_level',    // Consistent with server
                'language': 'trontiq_language'
            };
            
            const storageKey = keyMap[fieldName] || `trontiq_${fieldName}`;
            
                chrome.storage.local.set({
                [storageKey]: fieldValue,
                    'trontiq_profile_settings_saved_date': new Date().toLocaleString()
                }, () => {
                // Field saved to local storage
                
                // Verify the data was actually saved
                chrome.storage.local.get([storageKey], (result) => {
                });
            });
                        
                        // Special handling for language changes
                        if (fieldName === 'language') {
                            i18n.setLanguage(fieldValue).then(() => {
                                i18n.apply();
                                // UI updated with new language
                                // Refresh subscription UI with new language after a short delay - DISABLED (moved to server)
                                // setTimeout(() => {
                                //     if (window.trontiqPopup && window.trontiqPopup.stripePayment && window.trontiqPopup.stripePayment.updateSubscriptionUI) {
                                //         window.trontiqPopup.stripePayment.updateSubscriptionUI();
                                //     }
                                // }, 100);
                            });
                        }
            
        } catch (error) {
            // Error saving field
            
            // Fallback to local storage only
            chrome.storage.local.set({
                [`trontiq_${fieldName}`]: fieldValue,
                'trontiq_profile_settings_saved_date': new Date().toLocaleString()
            }, () => {
                // Field saved to local storage (fallback)
            });
        }
    }

    handleUpdateResume() {
        // Edit Resume clicked
        this.enterEditMode();
    }

    handleResumeTextClick() {
        const resumeText = document.getElementById('resumeText');
        if (resumeText && resumeText.readOnly) {
            // Resume textarea clicked
            this.enterEditMode();
        }
    }

    enterEditMode() {
        // Make textarea editable
        const resumeText = document.getElementById('resumeText');
        if (resumeText) {
            resumeText.readOnly = false;
            resumeText.style.backgroundColor = 'white';
            // Made textarea editable
            
            // Add auto-save functionality with debouncing
            this.setupResumeAutoSave(resumeText);
        } else {
            // Could not find resumeText element
        }
        
        // Change Edit Resume to Save Resume, enable Cancel
        const updateBtn = document.getElementById('updateResume');
        const cancelBtn = document.getElementById('cancelResume');
        
        if (updateBtn && cancelBtn) {
            updateBtn.querySelector('.btn-text').textContent = i18n.t('save_resume');
            updateBtn.onclick = this.handleSaveResume.bind(this);
            
            cancelBtn.classList.remove('disabled');
            // Entered edit mode
            } else {
            // Could not find button elements
        }
    }

    setupResumeAutoSave(resumeText) {
        // Clear any existing auto-save timer
        if (this.resumeAutoSaveTimer) {
            clearTimeout(this.resumeAutoSaveTimer);
        }
        
        // Store the original value to detect changes
        this.originalResumeValue = resumeText.value;
        
        // Add input event listener for auto-save
        const autoSaveHandler = () => {
            // Clear existing timer
            if (this.resumeAutoSaveTimer) {
                clearTimeout(this.resumeAutoSaveTimer);
            }
            
            // Set new timer for auto-save (2 seconds after user stops typing)
            this.resumeAutoSaveTimer = setTimeout(async () => {
                const currentValue = resumeText.value.trim();
                
                // Only save if the value has changed and is not empty
                if (currentValue !== this.originalResumeValue && currentValue.length > 0) {
                    // Auto-saving resume changes
                    this.showStatus('Auto-saving resume...', 'info');
                    await this.handleSaveResume();
                }
            }, 2000); // 2 second delay
        };
        
        // Remove any existing event listeners to avoid duplicates
        resumeText.removeEventListener('input', this.resumeAutoSaveHandler);
        resumeText.removeEventListener('blur', this.resumeAutoSaveHandler);
        
        // Store reference to handler for cleanup
        this.resumeAutoSaveHandler = autoSaveHandler;
        
        // Add event listeners
        resumeText.addEventListener('input', autoSaveHandler);
        resumeText.addEventListener('blur', autoSaveHandler); // Also save when user clicks away
        
        // Auto-save setup complete for resume
    }

    cleanupResumeAutoSave() {
        // Clear auto-save timer
        if (this.resumeAutoSaveTimer) {
            clearTimeout(this.resumeAutoSaveTimer);
            this.resumeAutoSaveTimer = null;
        }
        
        // Remove event listeners
        const resumeText = document.getElementById('resumeText');
        if (resumeText && this.resumeAutoSaveHandler) {
            resumeText.removeEventListener('input', this.resumeAutoSaveHandler);
            resumeText.removeEventListener('blur', this.resumeAutoSaveHandler);
            this.resumeAutoSaveHandler = null;
        }
        
        // Reset original value
        this.originalResumeValue = '';
        
        // Auto-save cleanup complete
    }

    async handleCancelResume() {
        // Only allow cancel if not disabled
        const cancelBtn = document.getElementById('cancelResume');
        if (cancelBtn && cancelBtn.classList.contains('disabled')) {
            return;
        }
        
        // Clean up auto-save functionality
        this.cleanupResumeAutoSave();
        
        // Restore original saved content from server
        await this.loadResumeFromServer();
    }

    setResumeReadOnly(text) {
        // Clean up auto-save functionality when setting to read-only
        this.cleanupResumeAutoSave();
        
        const resumeText = document.getElementById('resumeText');
        resumeText.value = text;
        resumeText.readOnly = true;
        resumeText.style.backgroundColor = '#f8f9fa';
        
        // Show update and cancel buttons (cancel disabled), hide save button
        const saveBtn = document.getElementById('saveResume');
        const updateBtn = document.getElementById('updateResume');
        const cancelBtn = document.getElementById('cancelResume');
        
        if (saveBtn && updateBtn && cancelBtn) {
            saveBtn.style.display = 'none';
            updateBtn.style.display = 'flex';
            cancelBtn.style.display = 'flex';
            cancelBtn.classList.add('disabled');
            
            // Reset Edit Resume button to original state
            updateBtn.querySelector('.btn-text').textContent = i18n.t('edit_resume');
            updateBtn.onclick = this.handleUpdateResume.bind(this);
        }
    }

    showResumeSavedNotification(timestamp) {
        const resumeStatus = document.getElementById('resumeStatus');
        const resumeSavedDate = document.getElementById('resumeSavedDate');
        
        if (resumeStatus && resumeSavedDate) {
            resumeSavedDate.textContent = timestamp;
            resumeStatus.style.display = 'flex';
        }
    }

    async loadResumeFromServer() {
        // Loading resume from server
        
        try {
            const response = await fetch('https://stripe-deploy.onrender.com/api/resume', {
                method: 'GET',
                headers: {
                    'Content-Type': 'application/json'
                },
                credentials: 'include' // Use HttpOnly cookies for authentication
            });
            
            if (response.ok) {
                const result = await response.json();
                // Resume loaded from server
                
                if (result.success && result.data.resume_text) {
                    const resumeText = result.data.resume_text;
                    const savedDate = result.data.saved_date;
                    
                    // Resume text length and saved date
        
                    // Show saved notification and set read-only mode
            this.showResumeSavedNotification(savedDate);
                    this.setResumeReadOnly(resumeText);
                    // Resume loaded in read-only mode from server
        } else {
                    // No resume found on server
                }
            } else if (response.status === 401) {
                // User not authenticated, no resume to load
            } else {
                // Error loading resume from server
            }
        } catch (error) {
            // Error loading resume from server
        }
    }

    // Upgrade and Subscription Handlers (Stripe functionality moved to separate file)
    async handleUpgradeToPro() {
        try {
            // Opening waitlist modal
            this.showWaitlistModal();

        } catch (error) {
            // Error opening waitlist modal
            this.showStatus('Failed to open waitlist. Please try again.', 'error');
        }
    }

    async handleCancelSubscription() {
        // Subscription management handled server-side
        this.showStatus('Subscription management is handled server-side.', 'info');
    }

    async handleManageSubscription() {
        // Subscription management handled server-side
        this.showStatus('Subscription management is handled server-side.', 'info');
    }

    // Waitlist Modal Functions
    showWaitlistModal() {
        const modal = document.getElementById('waitlistModal');
        if (modal) {
            modal.style.display = 'flex';
            
            // Pre-fill email if user is logged in
            const userEmail = document.getElementById('userEmail')?.textContent;
            if (userEmail && userEmail !== 'user@email.com') {
                const emailInput = document.getElementById('waitlistEmail');
                if (emailInput) {
                    emailInput.value = userEmail;
                }
            }
        }
    }

    hideWaitlistModal() {
        const modal = document.getElementById('waitlistModal');
        if (modal) {
            modal.style.display = 'none';
            
            // Reset form
            const form = document.getElementById('waitlistForm');
            const message = document.getElementById('waitlistMessage');
            if (form) form.reset();
            if (message) {
                message.style.display = 'none';
                message.className = 'waitlist-message';
            }
        }
    }

    // Login Error Modal Functions
    showLoginErrorModal(errorMessage) {
        const modal = document.getElementById('loginErrorModal');
        const title = document.getElementById('loginErrorTitle');
        const message = document.getElementById('loginErrorMessage');
        
        if (modal && title && message) {
            title.textContent = i18n.t('login_failed');
            message.textContent = errorMessage || i18n.t('invalid_credentials');
            modal.style.display = 'flex';
        }
    }

    hideLoginErrorModal() {
        const modal = document.getElementById('loginErrorModal');
        if (modal) {
            modal.style.display = 'none';
        }
    }

    attachLoginErrorModalListeners() {
        // Reattach event listeners for login error modal
        const resetPasswordBtn = document.getElementById('resetPasswordBtn');
        const contactSupportBtn = document.getElementById('contactSupportBtn');
        const loginErrorClose = document.getElementById('loginErrorClose');
        const loginErrorOk = document.getElementById('loginErrorOk');
        const modal = document.getElementById('loginErrorModal');

        if (resetPasswordBtn) {
            resetPasswordBtn.addEventListener('click', this.handleResetPassword.bind(this));
        }
        if (contactSupportBtn) {
            contactSupportBtn.addEventListener('click', this.handleContactSupport.bind(this));
        }
        if (loginErrorClose) {
            loginErrorClose.addEventListener('click', this.hideLoginErrorModal.bind(this));
        }
        if (loginErrorOk) {
            loginErrorOk.addEventListener('click', this.hideLoginErrorModal.bind(this));
        }
        if (modal) {
            modal.addEventListener('click', (event) => {
                if (event.target === modal) {
                    this.hideLoginErrorModal();
                }
            });
        }
    }

    showPasswordResetConfirmation(email) {
        // Get the existing login error modal and update its content
        const modal = document.getElementById('loginErrorModal');
        if (!modal) {
            console.error('Login error modal not found');
            return;
        }
        
        // Store original modal content to restore later
        if (!modal.dataset.originalContent) {
            modal.dataset.originalContent = modal.innerHTML;
        }
        
        // Update the modal content instead of creating a new one
        modal.innerHTML = `
            <div class="modal-content">
                <div class="modal-header">
                    <h3 data-i18n="confirm_password_reset">Confirm Password Reset</h3>
                    <button type="button" class="modal-close" id="passwordResetConfirmClose">&times;</button>
                </div>
                <div class="modal-body">
                    <p>Send password reset instructions to <strong>${email}</strong>?</p>
                    <p class="confirmation-note" style="color: #6c757d; font-size: 14px; margin-top: 10px; font-style: italic;">If an account with this email exists, you'll receive reset instructions in your inbox.</p>
                </div>
                <div class="modal-footer">
                    <button id="passwordResetConfirmCancel" class="modal-btn secondary" data-i18n="cancel">Cancel</button>
                    <button id="passwordResetConfirmSend" class="modal-btn primary" data-i18n="send_reset_email">Send Reset Email</button>
                </div>
            </div>
        `;
        
        // Add event listeners
        const closeBtn = document.getElementById('passwordResetConfirmClose');
        const cancelBtn = document.getElementById('passwordResetConfirmCancel');
        const sendBtn = document.getElementById('passwordResetConfirmSend');
        
        const cleanup = () => {
            // Restore original modal content and reattach event listeners
            if (modal.dataset.originalContent) {
                modal.innerHTML = modal.dataset.originalContent;
                // Reattach the original event listeners
                this.attachLoginErrorModalListeners();
            } else {
                this.hideLoginErrorModal();
            }
        };
        
        closeBtn.addEventListener('click', cleanup);
        cancelBtn.addEventListener('click', cleanup);
        
        // Close modal when clicking outside
        modal.addEventListener('click', (event) => {
            if (event.target === modal) {
                cleanup();
            }
        });
        
        // Handle send button
        sendBtn.addEventListener('click', async () => {
            await this.proceedWithPasswordReset(email);
            cleanup();
        });
    }
    
    async handleResetPassword(event) {
        console.log('handleResetPassword called', event);
        
        // Prevent default button behavior
        if (event) {
            event.preventDefault();
            event.stopPropagation();
        }
        
        // Show the forgot password form modal
        this.showForgotPasswordForm();
    }

    showForgotPasswordForm() {
        // Get the existing login error modal and update its content
        const modal = document.getElementById('loginErrorModal');
        if (!modal) {
            console.error('Login error modal not found');
            return;
        }
        
        // Store original modal content to restore later
        if (!modal.dataset.originalContent) {
            modal.dataset.originalContent = modal.innerHTML;
        }
        
        // Check if user already has email in sign-in form
        const signinEmailInput = document.getElementById('signinEmail');
        const prefillEmail = signinEmailInput ? signinEmailInput.value.trim() : '';
        
        // Update the modal content with email input form
        modal.innerHTML = `
            <div class="modal-content">
                <div class="modal-header">
                    <h3 data-i18n="forgot_username_password">Reset Password</h3>
                    <button type="button" class="modal-close" id="forgotPasswordFormClose">&times;</button>
                </div>
                <div class="modal-body">
                    <p data-i18n="password_reset_email_sent">Enter your email address and we'll send you a password reset link.</p>
                    <form id="forgotPasswordForm">
                        <div class="form-group">
                            <label for="forgotPasswordEmail" data-i18n="email_address">Email Address</label>
                            <input type="email" id="forgotPasswordEmail" name="email" required data-i18n-placeholder="email_placeholder" placeholder="your@email.com" value="${prefillEmail}" style="width: 100%; padding: 10px; border: 1px solid #ddd; border-radius: 4px; font-size: 14px;">
                        </div>
                    </form>
                </div>
                <div class="modal-footer">
                    <button id="forgotPasswordFormCancel" class="modal-btn secondary" data-i18n="cancel">Cancel</button>
                    <button id="forgotPasswordFormSubmit" class="modal-btn primary" data-i18n="send_reset_email">Send Reset Email</button>
                </div>
            </div>
        `;
        
        // Apply translations to the modal
        i18n.apply();
        
        // Add event listeners
        const closeBtn = document.getElementById('forgotPasswordFormClose');
        const cancelBtn = document.getElementById('forgotPasswordFormCancel');
        const submitBtn = document.getElementById('forgotPasswordFormSubmit');
        const emailInput = document.getElementById('forgotPasswordEmail');
        
        const cleanup = () => {
            modal.style.display = 'none';
            if (modal.dataset.originalContent) {
                modal.innerHTML = modal.dataset.originalContent;
            }
        };
        
        if (closeBtn) closeBtn.addEventListener('click', cleanup);
        if (cancelBtn) cancelBtn.addEventListener('click', cleanup);
        
        if (submitBtn) {
            submitBtn.addEventListener('click', async () => {
                const email = emailInput ? emailInput.value.trim() : '';
                
                if (!email) {
                    this.showStatus('Please enter your email address', 'error');
                    return;
                }
                
                // Validate email format
                const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
                if (!emailRegex.test(email)) {
                    this.showStatus('Please enter a valid email address', 'error');
                    return;
                }
                
                // Close this modal and directly send the reset email
                cleanup();
                await this.proceedWithPasswordReset(email);
            });
        }
        
        // Show the modal
        modal.style.display = 'flex';
        
        // Focus on email input (only if it's empty)
        if (emailInput && !prefillEmail) {
            setTimeout(() => emailInput.focus(), 100);
        }
    }
    
    async proceedWithPasswordReset(email) {
        console.log('Starting password reset for:', email);
        
        try {
            // Use Supabase to send password reset email
            if (!window.supabaseStorage || !window.supabaseStorage.supabase) {
                console.error('Supabase client not available');
                throw new Error('Supabase client not available');
            }
            
            console.log('Supabase client available, sending reset email...');
            
            const { data, error } = await window.supabaseStorage.supabase.auth.resetPasswordForEmail({
                email: email,
                redirectTo: `https://stripe-deploy.onrender.com/auth/reset-password`
            });
            
            console.log('Password reset response:', { data, error });
            
            if (error) {
                console.error('Password reset error:', error);
                throw error;
            }
            
            // Show success message
            console.log('Password reset email sent successfully');
            this.showStatus(i18n.t('password_reset_email_sent'), 'success');
            
        } catch (error) {
            console.error('Password reset error:', error);
            let errorMessage = i18n.t('password_reset_failed');
            
            // Provide more specific error messages
            if (error.message && error.message.includes('User not found')) {
                errorMessage = i18n.t('no_account_found');
            } else if (error.message && error.message.includes('rate limit')) {
                errorMessage = i18n.t('too_many_requests');
            }
            
            this.showStatus(errorMessage, 'error');
        }
    }

    handleContactSupport(event) {
        // Prevent default button behavior
        if (event) {
            event.preventDefault();
            event.stopPropagation();
        }
        
        // Close the modal first
        this.hideLoginErrorModal();
        
        // Show contact support form
        this.showContactSupportForm();
    }

    showContactSupportForm() {
        // Get the existing login error modal and update its content
        const modal = document.getElementById('loginErrorModal');
        if (!modal) {
            console.error('Login error modal not found');
            return;
        }
        
        // Store original modal content to restore later
        if (!modal.dataset.originalContent) {
            modal.dataset.originalContent = modal.innerHTML;
        }
        
        // Get the email from the signin form for pre-filling
        const signinEmailInput = document.getElementById('signinEmail');
        const prefillEmail = signinEmailInput ? signinEmailInput.value.trim() : '';
        
        // Create a sample email template
        const sampleEmail = `To: support@trontiq.com
Subject: Login Issue - Need Help

Hi Trontiq Support,

I'm having trouble logging into my account${prefillEmail ? ` with email: ${prefillEmail}` : ''}.

Please help me resolve this issue.

Thank you!`;
        
        // Update the modal content with support information
        modal.innerHTML = `
            <div class="modal-content">
                <div class="modal-header">
                    <h3 data-i18n="contact_support">Contact Support</h3>
                    <button type="button" class="modal-close" id="contactSupportFormClose">&times;</button>
                </div>
                <div class="modal-body">
                    <p data-i18n="support_help_message">We're here to help! Please send us an email with the following information:</p>
                    
                    <div class="support-info" style="background: #f8f9fa; padding: 15px; border-radius: 8px; margin: 15px 0;">
                        <p><strong data-i18n="support_email">Support Email:</strong> <span data-i18n="support_email_address">support@trontiq.com</span></p>
                        <p><strong data-i18n="please_include">Please include:</strong></p>
                        <ul style="margin: 10px 0; padding-left: 20px;">
                            <li data-i18n="your_email_address">Your email address</li>
                            <li data-i18n="description_of_issue">Description of the issue</li>
                            <li data-i18n="error_messages">Any error messages you see</li>
                        </ul>
                    </div>
                    
                    <div class="sample-email" style="background: white; padding: 15px; border: 1px solid #dee2e6; border-radius: 4px; margin: 15px 0;">
                        <p><strong data-i18n="sample_email_template">Sample email template:</strong></p>
                        <textarea readonly style="width: 100%; height: 120px; border: none; background: #f8f9fa; padding: 10px; border-radius: 4px; font-family: monospace; font-size: 12px; resize: none;">${sampleEmail}</textarea>
                    </div>
                    
                    <p style="color: #6c757d; font-size: 14px;" data-i18n="copy_template_instruction">Copy the template above and send it to our support email using your preferred email client.</p>
                </div>
                <div class="modal-footer">
                    <button id="contactSupportFormCancel" class="modal-btn secondary" data-i18n="close">Close</button>
                    <button id="copyEmailTemplateBtn" class="modal-btn primary" data-i18n="copy_template">Copy Template</button>
                </div>
            </div>
        `;
        
        // Apply translations to the modal
        i18n.apply();
        
        // Add event listeners
        const closeBtn = document.getElementById('contactSupportFormClose');
        const cancelBtn = document.getElementById('contactSupportFormCancel');
        const copyBtn = document.getElementById('copyEmailTemplateBtn');
        
        const cleanup = () => {
            modal.style.display = 'none';
            if (modal.dataset.originalContent) {
                modal.innerHTML = modal.dataset.originalContent;
            }
        };
        
        if (closeBtn) closeBtn.addEventListener('click', cleanup);
        if (cancelBtn) cancelBtn.addEventListener('click', cleanup);
        
        if (copyBtn) {
            copyBtn.addEventListener('click', () => {
                navigator.clipboard.writeText(sampleEmail).then(() => {
                    copyBtn.textContent = 'Copied!';
                    setTimeout(() => {
                        copyBtn.textContent = 'Copy Template';
                    }, 2000);
                }).catch(() => {
                    // Fallback for older browsers
                    const textArea = document.createElement('textarea');
                    textArea.value = sampleEmail;
                    document.body.appendChild(textArea);
                    textArea.select();
                    document.execCommand('copy');
                    document.body.removeChild(textArea);
                    copyBtn.textContent = 'Copied!';
                    setTimeout(() => {
                        copyBtn.textContent = 'Copy Template';
                    }, 2000);
                });
            });
        }
        
        // Show the modal
        modal.style.display = 'flex';
    }



    async handleWaitlistSubmit(event) {
        event.preventDefault();
        
        const emailInput = document.getElementById('waitlistEmail');
        const submitBtn = document.getElementById('waitlistSubmitBtn');
        const message = document.getElementById('waitlistMessage');
        
        if (!emailInput || !submitBtn || !message) return;
        
        const email = emailInput.value.trim();
        if (!email) return;
        
        // Show loading state
        const originalText = submitBtn.innerHTML;
        submitBtn.innerHTML = '<span class="btn-text">Joining...</span>';
        submitBtn.disabled = true;
        
        try {
            // Submitting waitlist signup
            
            const response = await fetch('https://stripe-deploy.onrender.com/api/waitlist', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                credentials: 'include',
                body: JSON.stringify({ email })
            });
            
            const data = await response.json();
            
            if (data.success) {
                message.className = 'waitlist-message success';
                message.textContent = data.message || 'Successfully joined the waitlist! We\'ll notify you when Pro features are available.';
                message.style.display = 'block';
                
                // Hide form and show success message
                const form = document.getElementById('waitlistForm');
                if (form) form.style.display = 'none';
                
                // Auto-close modal after 3 seconds
                setTimeout(() => {
                    this.hideWaitlistModal();
                }, 3000);
                
            } else {
                throw new Error(data.error || 'Failed to join waitlist');
            }

        } catch (error) {
            // Error joining waitlist
            message.className = 'waitlist-message error';
            message.textContent = 'Error: Failed to join waitlist. Please try again.';
            message.style.display = 'block';
        } finally {
            // Reset button
            submitBtn.innerHTML = originalText;
            submitBtn.disabled = false;
        }
    }

    // Stripe payment handler moved to separate file (stripe-payment.js)
    // This functionality is not included in Chrome Web Store submission

    // Load subscription data from server
    async loadSubscriptionData() {
        try {
            
            const response = await fetch('https://stripe-deploy.onrender.com/api/me', {
                method: 'GET',
                credentials: 'include',
                headers: {
                    'Content-Type': 'application/json'
                }
            });
            
            if (!response.ok) {
                throw new Error(`Server error: ${response.status}`);
            }
            
            const data = await response.json();
            
            if (data.success && data.user) {
                // Subscription data loaded
                this.updateSubscriptionUI(data);
            } else {
                // No subscription data available
                this.updateSubscriptionUI(null);
            }
            
        } catch (error) {
            // Error loading subscription data
            this.updateSubscriptionUI(null);
        }
    }

    // Update subscription UI with server data
    updateSubscriptionUI(data) {
        const statusElement = document.getElementById('subscriptionStatus');
        const usageElement = document.getElementById('tokenUsage');
        const upgradeBtn = document.getElementById('upgradeBtn');
        const cancelBtn = document.getElementById('cancelSubscriptionBtn');
        
        if (!data || !data.user) {
            // No data available - show free plan
            if (statusElement) {
                statusElement.textContent = 'Free Plan';
                statusElement.className = 'status-free';
            }
            if (usageElement) {
                usageElement.textContent = '20 requests/month';
            }
            if (upgradeBtn) {
                upgradeBtn.style.display = 'block';
            }
            if (cancelBtn) {
                cancelBtn.style.display = 'none';
            }
            return;
        }
        
        const isProUser = data.user.plan === 'pro';
        const requestsUsed = data.user.requestsUsed || 0;
        const monthlyLimit = data.user.monthlyLimit || 20;
        
        // Update status
        if (statusElement) {
            if (isProUser) {
                statusElement.textContent = 'Pro Plan';
                statusElement.className = 'status-pro';
            } else {
                statusElement.textContent = 'Free Plan';
                statusElement.className = 'status-free';
            }
        }
        
        // Update usage
        if (usageElement) {
            if (isProUser) {
                usageElement.textContent = 'Unlimited';
            } else {
                usageElement.textContent = `${requestsUsed}/${monthlyLimit} requests used`;
            }
        }
        
        // Update buttons
        if (upgradeBtn) {
            upgradeBtn.style.display = isProUser ? 'none' : 'block';
        }
        if (cancelBtn) {
            cancelBtn.style.display = isProUser ? 'block' : 'none';
        }
        
        // Subscription UI updated
    }

    // Ensure user data is correct and has ID
    async ensureUserDataCorrect() {
        try {
            // Ensuring user data is correct
            
            // Get current user data
            const userData = await this.getCurrentUser();
            
            if (!userData || !userData.id) {
                // User data missing or invalid - user should re-authenticate
                return false;
            }
            
            // User data is correct
            return true;
            
        } catch (error) {
            // Error ensuring user data
            return false;
        }
    }

    // Check token usage before AI requests - DISABLED (moved to server)
    async checkTokenUsage(requiredTokens = 1) {
        // Token usage check disabled - handled server-side
        return true; // Always allow for now, server handles limits
    }

    // Show token limit warning
    showTokenLimitWarning() {
        const warningHtml = `
            <div class="token-warning">
                <strong>Token Limit Reached!</strong><br>
                You've used all your free tokens. Join our waitlist to be notified when Pro features are available!
                <br><br>
                <button onclick="document.getElementById('upgradeBtn').click()" class="upgrade-btn" style="margin-top: 10px;">
                    <span class="btn-icon">⭐</span>
                    <span class="btn-text">${i18n.t('join_waitlist')}</span>
                </button>
            </div>
        `;
        
        this.showStatus(warningHtml, 'warning');
    }

    async handleClearAllData() {
        const confirmed = await this.showCustomConfirm(
            i18n.t('clear_all_data'),
            i18n.t('clear_all_data_confirm_message')
        );
        
        if (confirmed) {
            try {
                // Clear user data from server (resume, profile, preferences)
                await this.clearUserDataFromServer();
                
                // Clear all local data
                this.clearAllLocalData();
                
                // Sign out the user (keeps account intact)
                await this.handleSignOut();
                
                this.showStatus('All user data cleared. Your account remains but you will need to set up your profile again.', 'success');
                this.showAuthSection();
            } catch (error) {
                // Error clearing user data
                this.showStatus('Error clearing data. Please try again.', 'error');
            }
        }
    }

    async handleUnsubscribeOnly() {
        const confirmed = await this.showCustomConfirm(
            'Cancel Subscription',
            'Are you sure you want to cancel your subscription? You will lose access to Pro features at the end of your current billing period.',
            'This will cancel your subscription but keep your account and data. You can resubscribe anytime. Are you sure?'
        );
        
        if (confirmed) {
            try {
                // Subscription cancellation moved to separate file
                this.showStatus('Subscription management is handled server-side.', 'info');
            } catch (error) {
                // Error cancelling subscription
                this.showStatus('Error cancelling subscription. Please try again.', 'error');
            }
        }
    }

        // Custom confirmation modal
    showCustomConfirm(title, message, confirmMessage) {
        return new Promise((resolve) => {
            const modal = document.getElementById('customModal');
            const modalTitle = document.getElementById('modalTitle');
            const modalMessage = document.getElementById('modalMessage');
            const cancelBtn = document.getElementById('modalCancel');
            const confirmBtn = document.getElementById('modalConfirm');
            
            // Set modal content (title and message are already translated)
            modalTitle.textContent = title;
            modalMessage.textContent = message;
            
            // Show modal
            modal.style.display = 'flex';
            
            // Handle cancel
            const handleCancel = () => {
                modal.style.display = 'none';
                resolve(false);
                cleanup();
            };
            
            // Handle confirm
            const handleConfirm = () => {
                // If there's a confirm message, show it as a second confirmation
                if (confirmMessage) {
                    modalMessage.textContent = confirmMessage;
                    confirmBtn.textContent = 'Yes, I\'m Sure';
                    cancelBtn.textContent = 'No, Keep My Account';
                    
                    // Remove old listeners and add new ones
                    cleanup();
                    confirmBtn.addEventListener('click', () => {
                        modal.style.display = 'none';
                        resolve(true);
                        cleanup();
                    });
                    cancelBtn.addEventListener('click', handleCancel);
                } else {
                    modal.style.display = 'none';
                    resolve(true);
                    cleanup();
                }
            };
            
            // Cleanup function
            const cleanup = () => {
                confirmBtn.removeEventListener('click', handleConfirm);
                cancelBtn.removeEventListener('click', handleCancel);
            };
            
            // Add event listeners
            confirmBtn.addEventListener('click', handleConfirm);
            cancelBtn.addEventListener('click', handleCancel);
        });
    }

    async handleDeleteAccountOnly() {
        const confirmed = await this.showCustomConfirm(
            i18n.t('delete_account'),
            'Are you sure you want to delete your account? This will permanently delete all your data and cannot be undone.'
        );
        
        if (confirmed) {
            try {
                // Starting account deletion process
                
                // Get current user data from session
                const userData = await this.getCurrentUser();
                
                if (!userData) {
                    // No user data found for deletion
                    this.showStatus('Error: No user data found', 'error');
                    return;
                }
                
                // User data for deletion
                
                // Get user ID from current user data
                let userId = userData.id;
                if (!userId) {
                    // User ID not found in stored data, attempting to get from multiple sources
                    
                    // Try to get from current user state first
                    if (this.currentUser && this.currentUser.id) {
                        userId = this.currentUser.id;
                        // Found user ID from current user state
                    }
                    // Try to get from Supabase storage current user
                    else if (window.supabaseStorage && window.supabaseStorage.currentUser && window.supabaseStorage.currentUser.id) {
                        userId = window.supabaseStorage.currentUser.id;
                        // Found user ID from Supabase storage current user
                    }
                    // Note: Supabase auth calls removed - using session-based authentication
                    
                    // If still no user ID, try to get from sessionStorage
                    if (!userId) {
                        try {
                            const sessionUser = sessionStorage.getItem('trontiq_user');
                            if (sessionUser) {
                                const parsedUser = JSON.parse(sessionUser);
                                if (parsedUser && parsedUser.id) {
                                    userId = parsedUser.id;
                                    // Found user ID from sessionStorage
                                }
                            }
                        } catch (sessionError) {
                            // Error getting user ID from sessionStorage
                        }
                    }
                    
                    // If still no user ID, show error
                    if (!userId) {
                        this.showStatus('Error: Could not retrieve user ID. Please sign out and sign in again to refresh your session.', 'error');
                        return;
                    }
                }
                
                if (!userId) {
                    this.showStatus('Error: Could not determine user ID for deletion', 'error');
                    return;
                }
                
                // Using user ID for deletion
                
                // Call server endpoint to delete account
                const response = await fetch('https://stripe-deploy.onrender.com/api/delete-account', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json'
                    },
                    body: JSON.stringify({
                        email: userData.email,
                        userId: userId
                    })
                });
                
                const result = await response.json();
                // Server deletion response
                
                if (!response.ok) {
                    throw new Error(result.error || 'Failed to delete account from server');
                }
                
                // Server account deletion successful, now clearing local data
                
                // Clear all local data first
                this.clearAllLocalData();
                
                // Sign out from Supabase immediately
                try {
                    if (window.supabaseStorage && window.supabaseStorage.supabase) {
                        // Signing out from Supabase
                        const { error } = await window.supabaseStorage.supabase.auth.signOut();
                        if (error) {
                            // Error signing out from Supabase
                        } else {
                            // Successfully signed out from Supabase
                        }
                    }
                } catch (signOutError) {
                    // Error during Supabase sign out
                }
                
                // Clear current user state
                this.currentUser = null;
                this.userProfile = null;
                
                // Force clear any remaining session data
                sessionStorage.clear();
                localStorage.clear();
                
                // Account deletion complete - user logged out and all data cleared
                this.showStatus('Account deleted successfully. You have been logged out.', 'success');
                this.showAuthSection();
            } catch (error) {
                // Error deleting account
                this.showStatus('Error deleting account. Please try again.', 'error');
            }
        }
    }

    async clearUserDataFromServer() {
        try {
            // Clear user data from server (resume, profile, preferences)
            const response = await fetch('https://stripe-deploy.onrender.com/api/clear-user-data', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                credentials: 'include'
            });

            if (!response.ok) {
                throw new Error('Failed to clear user data from server');
            }

            const result = await response.json();
            if (!result.success) {
                throw new Error(result.error || 'Failed to clear user data from server');
            }

            console.log('User data cleared from server successfully');
        } catch (error) {
            console.error('Error clearing user data from server:', error);
            throw error;
        }
    }

    clearAllLocalData() {
        // Clear all chrome.storage.local data
        chrome.storage.local.remove([
            'trontiq_authenticated',
            'trontiq_user',
            'trontiq_display_name',
            'trontiq_education_level',
            'trontiq_language',
            'trontiq_tone',
            'trontiq_profile_settings_saved_date',
            'trontiq_userProfile',
            'trontiq_profileLastUpdated'
        ], () => {
            if (chrome.runtime.lastError) {
                // Error clearing chrome.storage.local
            } else {
                // All chrome.storage.local data cleared
            }
        });
        
        // Clear sessionStorage
        sessionStorage.removeItem('trontiq_authenticated');
        sessionStorage.removeItem('trontiq_user');
        sessionStorage.removeItem('trontiq_userProfile');
        
        // Clear Chrome storage
        chrome.storage.local.remove([
            'trontiq_authenticated', 
            'trontiq_user', 
            'trontiq_session',
            'trontiq_userProfile',
            'trontiq_profileLastUpdated'
        ]);
    }

    async extractProfileFromText(resumeText) {
        const extractBtn = document.getElementById('extractProfile');
        const originalText = extractBtn.textContent;
        extractBtn.textContent = 'Extracting...';
        extractBtn.disabled = true;
        
        try {
            const profile = await this.extractProfileFromResume(resumeText);
            
            // Save profile to database
            await this.saveProfile(profile);
            
            // Update UI
            this.userProfile = profile;
            this.displayExtractedProfile(profile);
            
            this.showStatus('Profile extracted and saved successfully!', 'success');
        } catch (error) {
            // Profile extraction error
            this.showStatus('Failed to extract profile. Please try again.', 'error');
        } finally {
            extractBtn.textContent = originalText;
            extractBtn.disabled = false;
        }
    }

    displayExtractedProfile(profile) {
        const extractedProfileDiv = document.getElementById('extractedProfile');
        if (!extractedProfileDiv) return;

        // Update the extracted profile display
        const nameEl = document.getElementById('extractedName');
        const resumeLengthEl = document.getElementById('extractedResumeLength');
        const educationLevelEl = document.getElementById('extractedEducationLevel');
        const languageEl = document.getElementById('extractedLanguage');

        if (nameEl) nameEl.textContent = profile.displayName || 'Not found';
        if (resumeLengthEl) resumeLengthEl.textContent = profile.resumeText ? `${profile.resumeText.length} characters` : 'Not found';
        if (educationLevelEl) educationLevelEl.textContent = profile.educationLevel || 'Not found';
        if (languageEl) languageEl.textContent = profile.language || 'Not found';

        // Show the extracted profile section
        extractedProfileDiv.style.display = 'block';
    }

    showMainApp(user) {
        // Hide auth section
        document.getElementById('authSection').style.display = 'none';
        
        // Show main app section
        document.getElementById('mainAppSection').style.display = 'flex';
        
        // Update user info
        this.updateUserInfo(user);
        
        // Initialize tabs
        this.initializeMainAppTabs();
        
        // Load resume from server if exists
        this.loadResumeFromServer();
        
        // Stripe payment functionality moved to separate file (stripe-payment.js)
        // Load subscription data from server
        this.loadSubscriptionData();
        
        // Restore working system - fix user data and subscription
        if (window.restoreWorkingSystem) {
            window.restoreWorkingSystem();
        }
    }

    showAuthSection() {
        // Hide main app section
        document.getElementById('mainAppSection').style.display = 'none';
        
        // Show auth section
        document.getElementById('authSection').style.display = 'flex';
    }

    updateUserInfo(user) {
        const userInitials = document.getElementById('userInitials');
        const userDisplayName = document.getElementById('userDisplayName');
        const userEmail = document.getElementById('userEmail');
        const accountFullName = document.getElementById('accountFullName');
        const accountDisplayName = document.getElementById('accountDisplayName');
        const accountEmail = document.getElementById('accountEmail');
        const profileDisplayName = document.getElementById('displayName');
        
        
        // Use server data (user object from /api/me endpoint)
        // Only use email prefix as fallback if display_name is explicitly null/undefined
        // This prevents showing email prefix before server data is fully loaded
        let displayName = 'User'; // Default fallback
        if (user.display_name) {
            displayName = user.display_name;
        } else if (user.display_name === null || user.display_name === undefined) {
            // Only use email prefix if display_name is explicitly null/undefined from server
            displayName = user.email?.split('@')[0] || 'User';
        }
        const fullName = user.full_name || user.user_metadata?.full_name || 'Not provided';
        const email = user.email || 'Not provided';
        const initials = displayName.split(' ').map(name => name[0]).join('').toUpperCase().slice(0, 2);
        
        
        if (userInitials) userInitials.textContent = initials;
        if (userDisplayName) userDisplayName.textContent = displayName;
        if (userEmail) userEmail.textContent = email;
        if (accountFullName) accountFullName.value = fullName;
        if (accountDisplayName) accountDisplayName.value = displayName;
        if (accountEmail) accountEmail.value = email;
        
        // Sync display name to profile (read-only)
        if (profileDisplayName) profileDisplayName.value = displayName;
        
        // UI updated with server data
    }

    initializeMainAppTabs() {
        const tabButtons = document.querySelectorAll('.main-app-section .tab-btn');
        const tabContents = document.querySelectorAll('.main-app-section .tab-content');
        
        tabButtons.forEach(button => {
            button.addEventListener('click', () => {
                const targetTab = button.getAttribute('data-tab');
                
                tabButtons.forEach(btn => btn.classList.remove('active'));
                tabContents.forEach(content => content.classList.remove('active'));
                
                button.classList.add('active');
                document.getElementById(targetTab).classList.add('active');
            });
        });
    }

    switchAuthTab(tab) {
        const signinContent = document.getElementById('signin-content');
        const signupContent = document.getElementById('signup-content');
        
        if (tab === 'signup') {
            signinContent.classList.remove('active');
            signupContent.classList.add('active');
        } else {
            signupContent.classList.remove('active');
            signinContent.classList.add('active');
        }
    }



    // Email verification is skipped for now - users go straight to main app

    clearStatus() {
        const statusDiv = document.getElementById('status');
        if (statusDiv) {
            statusDiv.textContent = '';
            statusDiv.className = 'status';
            statusDiv.style.display = 'none';
            statusDiv.style.visibility = 'hidden';
            statusDiv.style.opacity = '0';
        }
    }

    showStatus(message, type) {
        const statusDiv = document.getElementById('status');
        if (!statusDiv) {
            // Status div not found
            return;
        }

        // Set the message content and styling
        statusDiv.textContent = message;
        statusDiv.className = `status ${type}`;
        statusDiv.style.setProperty('display', 'block', 'important');
        statusDiv.style.visibility = 'visible';
        statusDiv.style.opacity = '1';
        statusDiv.style.position = 'relative';
        statusDiv.style.margin = '15px 0';
        statusDiv.style.padding = '12px 15px';
        statusDiv.style.borderRadius = '6px';
        statusDiv.style.fontSize = '14px';
        statusDiv.style.fontWeight = '500';
        statusDiv.style.textAlign = 'center';
        statusDiv.style.backgroundColor = type === 'error' ? '#f8d7da' : '#d4edda';
        statusDiv.style.color = type === 'error' ? '#721c24' : '#155724';
        statusDiv.style.border = type === 'error' ? '1px solid #f5c6cb' : '1px solid #c3e6cb';

        // Auto-hide after 5 seconds
        setTimeout(() => {
            statusDiv.style.setProperty('display', 'none', 'important');
        }, 5000);
    }
    
    notifyContentScript(isAuthenticated) {
        // Send message to all content scripts to update authentication status
        chrome.tabs.query({}, (tabs) => {
            // Found tabs
            tabs.forEach(tab => {
                try {
                    // Sending message to tab
                    chrome.tabs.sendMessage(tab.id, {
                        type: 'AUTH_STATUS_CHANGED',
                        isAuthenticated: isAuthenticated
                    }).catch((error) => {
                        // Error sending message to tab
                    });
                } catch (error) {
                    // Error sending message to tab
                }
            });
        });
    }

    broadcastAuthStateChange(isAuthenticated) {
        // Broadcasting auth state change
        
        // Update chrome.storage.local to trigger change events
        chrome.storage.local.set({
            'trontiq_authenticated': isAuthenticated
        }, () => {
            if (chrome.runtime.lastError) {
                // Error broadcasting auth state
            } else {
                // Auth state broadcasted to all extension surfaces
            }
        });
        
        // Also notify content scripts directly
        this.notifyContentScript(isAuthenticated);
        
        // Force a cross-tab sync by updating a timestamp
        chrome.storage.local.set({
            'trontiq_auth_timestamp': Date.now()
        }, () => {
            // Auth timestamp updated for cross-tab sync
        });
    }

    // Get current user from server endpoints
    async getCurrentUser() {
        try {
            
            // Check authentication state from local storage
            const result = await new Promise((resolve) => {
                chrome.storage.local.get(['trontiq_authenticated'], resolve);
            });
            
            if (result.trontiq_authenticated === true || result.trontiq_authenticated === 'true') {
                // User authenticated via local storage
                
                // Fetch user data from server with session cookie
                const response = await fetch(`https://stripe-deploy.onrender.com/api/me`, {
                    method: 'GET',
                    credentials: 'include', // Important for cookies
                    headers: {
                        'Content-Type': 'application/json'
                    }
                });
                
                if (response.ok) {
                    const userData = await response.json();
                    if (userData.success) {
                        // User data fetched from server
                        
                        // Note: User ID and email are NOT stored in local storage for security
                        // They are available in the returned user object when needed
                        
                        // SECURITY: Subscription data is now managed server-side only
                        // No local caching to prevent cross-user data leakage
                        
                        return {
                            isAuthenticated: true,
                            plan: userData.plan,
                            isProUser: userData.isProUser,
                            canChat: userData.canChat,
                            requestsUsed: userData.requestsUsed,
                            monthlyLimit: userData.monthlyLimit,
                            // Include user personal information
                            user: userData.user
                        };
                    }
                } else if (response.status === 401) {
                    // Session expired, clearing auth state
                    chrome.storage.local.set({ 'trontiq_authenticated': false });
                    return null;
                } else {
                    // Server error
                }
            }
            
            // No valid authentication found in local storage
            return null;
        } catch (error) {
            // Error checking local storage authentication
            return null;
        }
    }


    // Function to clear old localStorage data and ensure chrome.storage.local is used
    clearOldLocalStorage() {
        // Clearing old localStorage data
        const keysToRemove = [
            'trontiq_authenticated',
            'trontiq_user',
            'trontiq_display_name',
            'trontiq_education_level',
            'trontiq_language',
            'trontiq_tone',
            'trontiq_profile_settings_saved_date',
            'trontiq_userProfile',
            'trontiq_profileLastUpdated',
            'trontiq_session'
        ];
        
        keysToRemove.forEach(key => {
            localStorage.removeItem(key);
            // Removed key from localStorage
        });
        
        // Old localStorage data cleared
    }

    // Helper function to get stored session
    getStoredSession() {
        try {
            const sessionData = localStorage.getItem('trontiq_session') || 
                               sessionStorage.getItem('trontiq_session');
            if (sessionData) {
                return JSON.parse(sessionData);
            }
            
            // Also check chrome.storage.local
            if (typeof chrome !== 'undefined' && chrome.storage) {
                // This is async, but we need sync for this use case
                // For now, return null and handle async in the calling function
                return null;
            }
            
            return null;
        } catch (error) {
            // Error getting stored session
            return null;
        }
    }

    // Function to clear sensitive data from chrome.storage.local
    clearSensitiveData() {
        // Clearing sensitive data from chrome.storage.local
        const forbiddenKeys = [
            'trontiq_user',           // Remove full user object
            'trontiq_subscription',   // Remove subscription object
            'trontiq_subscription_cache', // Remove subscription cache (CRITICAL!)
            'trontiq_user_id',        // Remove Supabase UUID (PII)
            'trontiq_user_email',     // Remove email (PII)
            'trontiq_session',        // Remove session data
            'trontiq_display_name'    // Remove display name (server-side)
        ];
        
        chrome.storage.local.remove(forbiddenKeys, () => {
            // Forbidden data cleared from chrome.storage.local
            
            // VERIFICATION: Check if cache was actually cleared
            chrome.storage.local.get(['trontiq_subscription_cache', 'trontiq_subscription'], (result) => {
                if (result.trontiq_subscription_cache || result.trontiq_subscription) {
                    // Subscription cache still exists after clearing
                } else {
                    // Subscription cache successfully cleared
                }
            });
        });
        
        // SECURITY: Clear subscription cache to prevent cross-user data leakage
        // Stripe subscription cache clearing moved to separate file
        
        // Also clear localStorage subscription data
        try {
            localStorage.removeItem('trontiq_subscription');
            // localStorage subscription data cleared
        } catch (error) {
            // Error clearing localStorage subscription data
        }
    }

    // Function to clear test data from chrome.storage.local
    clearTestDataFromChromeStorage() {
        // Clearing test data from chrome.storage.local
        
        // Clear any test data that might be there
        chrome.storage.local.remove([
            'trontiq_userProfile' // This might contain old test data
        ], () => {
            // Test data cleared from chrome.storage.local
        });
    }

    // Function to clear old session tokens (security cleanup)
    clearOldSessionTokens() {
        // Clearing old session tokens from chrome.storage.local
        
        // Remove any existing session tokens for security
        chrome.storage.local.remove([
            'trontiq_session_token',
            'trontiq_session'
        ], () => {
            // Old session tokens cleared from chrome.storage.local
        });
    }

    // Shared render helper (data-i18n approach)
    rerenderAllText() {
        document.querySelectorAll('[data-i18n]').forEach(el => {
            el.textContent = this.i18n.t(el.dataset.i18n);
        });
        document.querySelectorAll('[data-i18n-title]').forEach(el => {
            el.title = this.i18n.t(el.dataset.i18nTitle);
        });
        document.querySelectorAll('[data-i18n-placeholder]').forEach(el => {
            el.placeholder = this.i18n.t(el.dataset.i18nPlaceholder);
        });
    }

    // Function to ensure all profile data is saved to chrome.storage.local
    ensureProfileDataInChromeStorage() {
        // Ensuring all profile data is in chrome.storage.local
        
        // Get current form values (but preserve saved language if form is empty)
        const displayName = document.getElementById('accountDisplayName')?.value || 
                           document.getElementById('displayName')?.value || '';
        const educationLevel = document.getElementById('educationLevel')?.value || 'none';
        
        // FIXED: Don't overwrite saved language with form default
        const languageEl = document.getElementById('language');
        const language = languageEl?.value || i18n.currentLanguage || 'english';
        
        // Language element value, i18n.currentLanguage, and determined language to save
        
        const tone = document.getElementById('tone')?.value || 'professional';
        const resumeText = document.getElementById('resumeText')?.value || '';
        
        // Save all profile data to chrome.storage.local in individual fields (as content.js expects)
        // Note: Resume text is now stored server-side, not in local storage
        const profileData = {
            'trontiq_display_name': displayName,
            'trontiq_education_level': educationLevel,
            'trontiq_language': language,
            'trontiq_tone': tone,
            'trontiq_profile_settings_saved_date': new Date().toLocaleString()
        };
        
        // Also save as a JSON object for compatibility (resume text is server-side)
        const userProfileObject = {
            displayName: displayName,
            educationLevel: educationLevel,
            language: language,
            preferredTone: tone,
            extractedAt: new Date().toISOString(),
            version: '2.0'
        };
        
        const allData = {
            ...profileData,
            'trontiq_userProfile': JSON.stringify(userProfileObject)
        };
        
        // About to save to chrome.storage.local
        chrome.storage.local.set(allData, () => {
            if (chrome.runtime.lastError) {
                // Error saving profile data
            } else {
                // All profile data saved to chrome.storage.local
                // Saved language value
            }
        });
    }

    async signIn(email, password) {
        try {
            if (!window.supabaseStorage) {
                throw new Error('Supabase storage not available');
            }

            // Use Supabase to authenticate and get JWT token
            const { data, error } = await window.supabaseStorage.supabase.auth.signInWithPassword({
                email: email,
                password: password
            });

            if (error) {
                throw error;
            }

            if (!data.user || !data.session) {
                throw new Error('No user data received');
            }

            // Exchange JWT token for server session (HttpOnly cookie)
            // Exchanging JWT token for server session
            const exchangeResponse = await fetch('https://stripe-deploy.onrender.com/api/auth/exchange', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                credentials: 'include', // Important for cookies
                body: JSON.stringify({
                    idToken: data.session.access_token
                })
            });

            // Exchange response status

            if (!exchangeResponse.ok) {
                const errorText = await exchangeResponse.text();
                // Exchange failed
                throw new Error(`Failed to exchange token for server session: ${exchangeResponse.status}`);
            }

            // Server session created successfully

            return { 
                success: true, 
                user: data.user, 
                session: data.session 
            };
        } catch (error) {
            // SignIn error
            throw error;
        }
    }

    async signUp(email, password, displayName, fullName) {
        // Use the real Supabase implementation
        if (window.supabaseStorage) {
            return await window.supabaseStorage.signUp(email, password, displayName, fullName);
        } else {
            // Supabase storage not available
            throw new Error('Supabase storage not available');
        }
    }

    async signOut() {
        // Clear persistent storage
                    chrome.storage.local.remove(['trontiq_authenticated', 'trontiq_session']);
        return { success: true };
    }

    // DEPRECATED: Create subscription record for user - no longer used with waitlist system
    /*
    async createSubscriptionRecord(userId) {
        try {
            // Validate userId
            if (!userId) {
                // Missing userId in createSubscriptionRecord
                return { success: false, error: 'Missing userId' };
            }


            // First, check if user already has a subscription
            const checkResponse = await fetch(`https://stripe-deploy.onrender.com/api/user-status/${userId}`);
            if (checkResponse.ok) {
                const userStatus = await checkResponse.json();
                // Current user status
                
                if (userStatus.success && userStatus.status === 'active') {
                    // User already has active subscription, skipping creation
                    
                    // Update UI to show Pro status immediately
                    this.updateUIForProUser(userStatus);
                    
                    return { 
                        success: true, 
                        message: 'User already has active subscription',
                        subscription: userStatus
                    };
                }
            }

            // Only create if user doesn't have an active subscription
            const response = await fetch('https://stripe-deploy.onrender.com/api/create-subscription-record', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({
                    userId: userId,
                    status: 'free'
                })
            });

            if (!response.ok) {
                const errorText = await response.text();
                // Server error details
                return { success: false, error: `Server error: ${response.status} - ${errorText}` };
            }

            const result = await response.json();
            // Subscription record created
            return result;
        } catch (error) {
            // Error creating subscription record
            // Don't throw error - just log it and continue
            // Continuing without subscription record creation
            return { success: false, error: error.message };
        }
    }
    */

    // Update UI to show Pro status
    updateUIForProUser(userStatus) {
        // Updating UI for Pro user
        
        // Update subscription status display
        const statusElement = document.getElementById('subscriptionStatus');
        if (statusElement) {
            statusElement.textContent = i18n.t('trontiq_pro');
            statusElement.className = 'status-pro';
            // Status updated to Trontiq Pro
        }

        // Update usage display
        const usageElement = document.getElementById('tokenUsage');
        if (usageElement) {
            usageElement.textContent = i18n.t('unlimited_access');
            // Usage updated to Unlimited access
        }

        // Hide upgrade button
        const upgradeBtn = document.getElementById('upgradeBtn');
        if (upgradeBtn) {
            upgradeBtn.style.display = 'none';
            // Upgrade button hidden
        }

        // Show cancel button for Pro users
        const cancelBtn = document.getElementById('cancelSubscriptionBtn');
        if (cancelBtn) {
            cancelBtn.style.display = 'block';
            // Cancel button shown
        }

        // Store Pro status in storage
        const proSubscriptionData = {
            id: userStatus.stripe_subscription_id || 'pro_subscription',
            status: 'active',
            unlimited: true,
            used: userStatus.requestsUsed || 75,
            limit: -1,
            current_period_end: userStatus.current_period_end,
            cached_at: Date.now()
        };

        // SECURITY: Don't save subscription data to storage to prevent cross-user data leakage
        // Subscription data is now managed server-side only

        // UI updated for Pro user
    }



    async updateUser(data) {
        // Placeholder implementation
        return { data: { user: { user_metadata: data } }, error: null };
    }

    async extractProfileFromResume(resumeText) {
        try {
            // Call the background script's extractProfileFromResume function
            const response = await chrome.runtime.sendMessage({
                action: 'extractProfileFromResume',
                resumeText: resumeText
            });
            
            if (response.success) {
                // Profile extracted successfully
                return response.profile;
            } else {
                throw new Error(response.error || 'Failed to extract profile');
            }
        } catch (error) {
            // Error calling background script for profile extraction
            throw error;
        }
    }

    async saveProfile(profile) {
        // Placeholder implementation
        return { success: true };
    }

    extractDataFromText(text) {
    
        // Simple text parsing to extract display name
    const lines = text.split('\n').map(line => line.trim()).filter(line => line.length > 0);
    // Number of lines
    
        let displayName = '';
    
    // Extract name (usually first line or line with "Name:")
    for (let i = 0; i < Math.min(5, lines.length); i++) {
        const line = lines[i].toLowerCase();
        if (line.includes('name:') || (line.length > 2 && line.length < 50 && !line.includes('@') && !line.includes('http'))) {
                displayName = lines[i].replace('name:', '').trim();
            break;
        }
    }
    
    const result = {
            displayName: displayName || 'User',
            resumeText: text, // Store the complete resume text
        educationLevel: 'none',
        language: 'english',
        preferredTone: 'professional'
    };
    
        // Simplified extraction result
    return result;
}

    saveToBrowserStorage(profileData) {
    try {
        const dataToSave = {
                displayName: profileData.displayName,
                resumeText: profileData.resumeText,
                educationLevel: profileData.educationLevel,
                language: profileData.language,
                preferredTone: profileData.preferredTone,
            extractedAt: new Date().toISOString(),
                version: '2.0'
        };
        
        // Save to chrome.storage.local only
            chrome.storage.local.set({
                'trontiq_userProfile': JSON.stringify(dataToSave),
                'trontiq_profileLastUpdated': new Date().toISOString()
        }, () => {
            if (chrome.runtime.lastError) {
                // Error saving user profile
            } else {
                // User profile saved to chrome.storage.local
            }
        });
        
            // Simplified profile saved to browser storage
        
    } catch (error) {
            // Error saving to browser storage
        }
    }

    populateProfileForm(profile) {
        const displayNameEl = document.getElementById('displayName');
        const educationLevelEl = document.getElementById('educationLevel');
        const languageEl = document.getElementById('language');
        const toneEl = document.getElementById('tone');
        
        if (displayNameEl) displayNameEl.value = profile.displayName || '';
        if (educationLevelEl) educationLevelEl.value = profile.educationLevel || 'none';
        if (languageEl) languageEl.value = profile.language || 'english';
        if (toneEl) toneEl.value = profile.preferredTone || 'professional';
        
        // Simplified profile form populated
    }
}

// Initialize popup when DOM is loaded
document.addEventListener('DOMContentLoaded', () => {
    const popup = new PopupController();
    popup.initialize();
    
    // Clear any old session tokens for security
    popup.clearOldSessionTokens();
    
    // Make popup globally accessible for debugging
    window.trontiqPopup = popup;
    
    // Add test functions for debugging
    window.testPopupLocalization = function() {
        // Testing popup localization
        // Current language
        // Sample translation (account)
        // Sample translation (smart_browser_assistant)
        i18n.apply();
        // Localization test complete
    };
    
    window.checkPopupElements = function() {
    };
    
    window.forceLanguageChange = function(language) {
        // Force changing language to
        i18n.setLanguage(language).then(() => {
            chrome.storage.local.set({ trontiq_language: language });
            i18n.apply();
            setTimeout(() => i18n.apply(), 100);
            setTimeout(() => i18n.apply(), 500);
            // Refresh subscription UI with new language after a short delay
            setTimeout(() => {
                // Stripe subscription UI update moved to separate file
            }, 200);
        });
    };
    
    
    
    

    // Global function to force Pro status update
    window.forceProStatusUpdate = function() {
        if (window.trontiqPopup) {
            // Get user ID from storage first
            chrome.storage.local.get(['trontiq_user'], (result) => {
                if (result.trontiq_user) {
                    try {
                        const userData = JSON.parse(result.trontiq_user);
                        if (userData && userData.id) {
                            // Fetch current user status and update UI
                            fetch(`https://stripe-deploy.onrender.com/api/user-status/${userData.id}`)
                                .then(response => response.json())
                                .then(userStatus => {
                                    if (userStatus.success && userStatus.status === 'active') {
                                        window.trontiqPopup.updateUIForProUser(userStatus);
                                        // Pro status forced via global function
                                    } else {
                                        // User is not Pro
                                    }
                                })
                                .catch(error => {
                                    // Error fetching user status
                                });
                        } else {
                            // No user ID found in storage
                        }
                    } catch (e) {
                        // Error parsing user data
                    }
                } else {
                    // No user data found in storage
                }
            });
        } else {
            // TrontiqPopup not found
        }
    };

    // Global function to force refresh subscription UI
    // Stripe subscription UI refresh moved to separate file
    window.forceRefreshSubscriptionUI = function() {
        // Subscription UI refresh functionality moved to separate file
        console.log('Subscription UI refresh moved to separate file');
    };

    // Stripe payment reinitialization moved to separate file (stripe-payment.js)
    // This functionality is not included in Chrome Web Store submission

    // Global function to debug subscription data flow






});
