# Stroller Spa × KidsCompany.co.in — Shopify Integration Starter

## Contents
- `shopify/sections/stroller-spa-booking.liquid`: responsive Online Store 2.0 storefront section with service prices, customer booking request, and Shopify membership-product links.
- `backend/server.js`: Node/Express/SQLite starter API for booking requests, job cards, membership creation from verified paid Shopify order webhooks, and atomic entitlement deduction on completion.
- `backend/.env.example`: required configuration.
- `docs/IMPLEMENTATION.md`: launch instructions and important production gaps.
- `stroller-spa-manager.html`: existing offline staff prototype, included for reference only (not linked to Shopify API).

## What works after deployment/configuration
1. Storefront booking requests post to `/api/public/bookings` and create a booking reference.
2. Membership purchase links use the Shopify product configured in theme editor.
3. Verified `orders/paid` webhooks create membership records for mapped variant IDs.
4. Staff API can confirm booking, create job, assign membership and complete a job with atomic credit deduction.

## What is NOT live or production ready
No changes have been made to the live Shopify store. This is starter source code. It has not been connected to Shopify, deployed, or end-to-end tested. Staff endpoints currently use a shared API key; production needs Shopify embedded app OAuth/session tokens, roles and audit logs. Customer-facing membership portal, payments reconciliation, pickup scheduling, photo uploads, WhatsApp delivery, data deletion workflows and backups are not implemented. Do not store real customer data until security review and proper hosting are complete.
