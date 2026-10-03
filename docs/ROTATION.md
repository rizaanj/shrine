# Secret Rotation Guide

## Generic API Key
1. Revoke the old API key in the dashboard
2. Generate a new API key
3. Update the API key in your environment variables
4. Purge the old API key from git history using BFG or filter-repo
5. Rotate the API key in any downstream services

## Supabase
1. Revoke the old Supabase key in the dashboard
2. Generate a new Supabase key
3. Update the Supabase key in your environment variables
4. Purge the old Supabase key from git history using BFG or filter-repo
5. Rotate the Supabase key in any downstream services

## Stripe
1. Revoke the old Stripe key in the dashboard
2. Generate a new Stripe key
3. Update the Stripe key in your environment variables
4. Purge the old Stripe key from git history using BFG or filter-repo
5. Rotate the Stripe key in any downstream services

## OpenAI
1. Revoke the old OpenAI key in the dashboard
2. Generate a new OpenAI key
3. Update the OpenAI key in your environment variables
4. Purge the old OpenAI key from git history using BFG or filter-repo
5. Rotate the OpenAI key in any downstream services

## GitHub
1. Revoke the old GitHub token in the dashboard
2. Generate a new GitHub token
3. Update the GitHub token in your environment variables
4. Purge the old GitHub token from git history using BFG or filter-repo
5. Rotate the GitHub token in any downstream services
