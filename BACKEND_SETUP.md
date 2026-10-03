# Shrine Backend Setup Guide

This guide explains how to set up Shrine's signup/login backend using Supabase Auth.

## Prerequisites

- A Supabase account (separate project from any test targets)
- Node.js and npm installed

## Step 1: Create a New Supabase Project

1. Go to [supabase.com](https://supabase.com) and create a new project
2. Name it something like "shrine-backend" (this is separate from test-target projects)
3. Wait for the project to be provisioned

## Step 2: Run the Database Schema

1. Open the SQL Editor in your Supabase dashboard
2. Copy the contents of `sql/shrine_backend_schema.sql`
3. Paste and run the SQL in the editor
4. Verify that the `beta_access` table was created successfully

The schema includes:
- `beta_access` table with columns: `id`, `access_key`, `created_at`, `is_active`, `tier`
- Automatic access key generation on user signup (format: `shrine_xxxxxxxxxxxxxxxx`)
- Row Level Security (RLS) policies
- Database trigger to auto-create beta_access rows

## Step 3: Configure the Signup Page

1. Open `public/signup.html`
2. Find these lines near the top of the `<script>` section:
   ```javascript
   const SUPABASE_URL = 'YOUR_SUPABASE_URL';
   const SUPABASE_ANON_KEY = 'YOUR_SUPABASE_ANON_KEY';
   ```
3. Replace with your actual credentials from the Supabase dashboard:
   - URL: Found in Settings > API > Project URL
   - Anon Key: Found in Settings > API > Project API keys > anon/public

4. Update the signup page URL placeholder:
   - Search for `[SIGNUP_PAGE_URL]` in the HTML file
   - Replace with your actual hosted signup page URL (or `file:///path/to/signup.html` for local testing)

## Step 4: Host the Signup Page

### Option A: Local Testing (Quick)

1. Open `public/signup.html` directly in a browser (`file://` protocol)
2. Or run a simple local server:
   ```bash
   # Using Python
   cd public
   python -m http.server 8000
   # Visit http://localhost:8000/signup.html
   
   # Using Node.js
   npx http-server public -p 8000
   # Visit http://localhost:8000/signup.html
   ```

### Option B: Deploy to Hosting (Production)

Deploy `public/signup.html` to any static hosting service:
- **Vercel**: `vercel deploy public`
- **Netlify**: Drag and drop the `public` folder
- **GitHub Pages**: Push to a gh-pages branch
- **Cloudflare Pages**: Connect your repo

## Step 5: Test the Flow

### Test Signup
1. Open the signup page in your browser
2. Enter an email and password (min 6 characters)
3. Click "Create Account"
4. Your access key should appear (format: `shrine_xxxxxxxxxxxxxxxx`)
5. Copy the access key

### Test Login
1. Switch to the "Login" tab on the same page
2. Enter your email and password
3. Click "Login"
4. Your access key should be displayed again

### Test CLI Authentication
1. Try running a scan without logging in:
   ```bash
   shrine scan --path .
   # Should show: "No access key found. Get your access key at: https://shrine.example.com/signup"
   ```

2. Login with your access key (no configuration needed - works out of the box):
   ```bash
   shrine login shrine_xxxxxxxxxxxxxxxx
   # Should show: "Access key validated and saved successfully!"
   ```

3. Run the scan again:
   ```bash
   shrine scan --path .
   # Should work normally
   ```

4. Test logout:
   ```bash
   shrine logout
   # Should show: "Logged out successfully. Access key removed."
   ```

## Troubleshooting

### Signup page shows "Invalid credentials" error
- Verify your Supabase URL and anon key are correct in `signup.html`
- Check the browser console for detailed error messages
- Ensure email confirmation is disabled in Supabase Auth settings (for testing)

### Access key not generated after signup
- Check that the trigger `on_auth_user_created` is created correctly
- Look at the Supabase logs for any errors
- Verify the `handle_new_user()` function exists

### CLI shows "Invalid access key"
- Verify the access key format starts with `shrine_`
- Check that the key exists in the `beta_access` table and is active
- Ensure the key was copied correctly (no extra spaces or characters)

## Security Notes

1. The anon key is safe to expose in the frontend and CLI (it's designed for this)
2. The service role key should NEVER be in the signup.html file or CLI code
3. RLS policies protect the beta_access table from unauthorized access
4. Access keys act as bearer tokens - treat them like passwords

## Advanced Configuration

### Override Backend Credentials (Optional)

For development or testing against a different backend, you can override the built-in credentials:

```bash
# Windows PowerShell
$env:SHRINE_BACKEND_URL = "https://your-project.supabase.co"
$env:SHRINE_BACKEND_ANON_KEY = "your-anon-key"

# Linux/Mac
export SHRINE_BACKEND_URL="https://your-project.supabase.co"
export SHRINE_BACKEND_ANON_KEY="your-anon-key"
```

### Skip Validation (Development Only)

To skip validation during development:

```bash
# Windows PowerShell
$env:SHRINE_DEV_SKIP_VALIDATION = "1"

# Linux/Mac
export SHRINE_DEV_SKIP_VALIDATION="1"
```

**Warning**: Never ship this in production - it bypasses all access control.

## Next Steps

- Deploy signup.html to production hosting
- Update all `[SIGNUP_PAGE_URL]` placeholders with the real URL
- Consider adding email verification (currently disabled for testing)
- Add password reset functionality using Supabase Auth
- Monitor signups in the Supabase dashboard
