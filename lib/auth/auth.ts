import { createClient } from '@/lib/supabase/server'
import { createClient as createBrowserClient } from '@/lib/supabase/client'
import { headers } from 'next/headers'
import type { User } from '@supabase/supabase-js'

/**
 * Authentication utility functions for Bias Buster v1
 * 
 * These functions handle user authentication operations:
 * - Sign up with email/password
 * - Sign in with email/password
 * - Sign out
 * - Get current user (server-side)
 * - Check authentication status
 * 
 * IMPORTANT: Anonymous users can browse but cannot write to the database.
 * All database operations are protected by Row-Level Security (RLS).
 */

// =====================================================
// SERVER-SIDE AUTH FUNCTIONS
// Use these in Server Components and Server Actions
// =====================================================

/**
 * Get the currently authenticated user (server-side)
 * Returns null if no user is authenticated (anonymous)
 */
export async function getCurrentUser(): Promise<User | null> {
    const supabase = await createClient()

    // 1. Try standard cookie-based auth
    const {
        data: { user },
    } = await supabase.auth.getUser()

    if (user) return user

    // 2. Fallback: Check for Authorization header (Bearer token)
    try {
        const headersList = await headers()
        const authHeader = headersList.get('Authorization')

        if (authHeader?.startsWith('Bearer ')) {
            const accessToken = authHeader.replace('Bearer ', '')

            // Set the session with the provided access token
            // This properly initializes the auth state with the token
            const { data: { user: headerUser }, error } = await supabase.auth.getUser(accessToken)

            if (error) {
                console.error('[AUTH] Bearer token validation failed:', error.message)
                return null
            }

            return headerUser
        }
    } catch (error: any) {
        console.error('[AUTH] Error checking Authorization header:', error.message)
        // Ignore error (headers() might throw in some contexts)
    }

    return null
}

/**
 * Check if a user is authenticated (server-side)
 */
export async function isAuthenticated(): Promise<boolean> {
    const user = await getCurrentUser()
    return user !== null
}

/**
 * Get the current user's ID (server-side)
 * Returns null if not authenticated
 */
export async function getCurrentUserId(): Promise<string | null> {
    const user = await getCurrentUser()
    return user?.id ?? null
}

/**
 * Get the current session (server-side)
 */
export async function getSession() {
    const supabase = await createClient()

    const {
        data: { session },
    } = await supabase.auth.getSession()

    return session
}

// =====================================================
// CLIENT-SIDE AUTH FUNCTIONS
// Use these in Client Components
// =====================================================

/**
 * Sign up a new user with email and password
 * 
 * @param email - User's email address
 * @param password - User's password (min 6 characters)
 * @returns Object with user data or error
 */
export async function signUp(email: string, password: string) {
    const supabase = createBrowserClient()

    const { data, error } = await supabase.auth.signUp({
        email,
        password,
        options: {
            // Optional: Add email confirmation
            // emailRedirectTo: `${window.location.origin}/auth/callback`,
        },
    })

    if (error) {
        return { user: null, error: error.message }
    }

    return { user: data.user, error: null }
}

/**
 * Sign in an existing user with email and password
 * 
 * @param email - User's email address
 * @param password - User's password
 * @returns Object with user data or error
 */
export async function signIn(email: string, password: string) {
    const supabase = createBrowserClient()

    const { data, error } = await supabase.auth.signInWithPassword({
        email,
        password,
    })

    if (error) {
        return { user: null, error: error.message }
    }

    return { user: data.user, error: null }
}

/**
 * Sign out the current user
 * 
 * @returns Object with success status or error
 */
export async function signOut() {
    const supabase = createBrowserClient()

    const { error } = await supabase.auth.signOut()

    if (error) {
        return { success: false, error: error.message }
    }

    return { success: true, error: null }
}

/**
 * Get the currently authenticated user (client-side)
 * Returns null if no user is authenticated (anonymous)
 */
export async function getCurrentUserClient(): Promise<User | null> {
    const supabase = createBrowserClient()

    const {
        data: { user },
    } = await supabase.auth.getUser()

    return user
}

/**
 * Listen to auth state changes (client-side)
 * Useful for updating UI when user signs in/out
 * 
 * @param callback - Function to call when auth state changes
 * @returns Unsubscribe function
 */
export function onAuthStateChange(
    callback: (user: User | null) => void
) {
    const supabase = createBrowserClient()

    const {
        data: { subscription },
    } = supabase.auth.onAuthStateChange((_event, session) => {
        callback(session?.user ?? null)
    })

    return () => subscription.unsubscribe()
}

// =====================================================
// PASSWORD RESET FUNCTIONS
// =====================================================

/**
 * Send a password reset email
 * 
 * @param email - User's email address
 * @returns Object with success status or error
 */
export async function resetPassword(email: string) {
    const supabase = createBrowserClient()

    const { error } = await supabase.auth.resetPasswordForEmail(email, {
        redirectTo: `${window.location.origin}/auth/reset-password`,
    })

    if (error) {
        return { success: false, error: error.message }
    }

    return { success: true, error: null }
}

/**
 * Update user's password (must be authenticated)
 * 
 * @param newPassword - New password (min 6 characters)
 * @returns Object with success status or error
 */
export async function updatePassword(newPassword: string) {
    const supabase = createBrowserClient()

    const { error } = await supabase.auth.updateUser({
        password: newPassword,
    })

    if (error) {
        return { success: false, error: error.message }
    }

    return { success: true, error: null }
}

// =====================================================
// HELPER FUNCTIONS
// =====================================================

/**
 * Validate email format
 */
export function isValidEmail(email: string): boolean {
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/
    return emailRegex.test(email)
}

/**
 * Validate password strength
 * Supabase requires minimum 6 characters
 */
export function isValidPassword(password: string): boolean {
    return password.length >= 6
}

/**
 * Get user-friendly error message
 */
export function getAuthErrorMessage(error: string): string {
    const errorMessages: Record<string, string> = {
        'Invalid login credentials': 'Invalid email or password',
        'Email not confirmed': 'Please confirm your email address',
        'User already registered': 'An account with this email already exists',
        'Password should be at least 6 characters': 'Password must be at least 6 characters',
    }

    return errorMessages[error] || error
}
