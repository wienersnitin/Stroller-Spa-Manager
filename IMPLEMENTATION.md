# Implementation guide

## 1. Shopify admin setup
1. Back up the current Shopify theme, and use a duplicate unpublished theme.
2. Add `shopify/sections/stroller-spa-booking.liquid` to the theme's `sections/` directory.
3. In Shopify Admin, create a page named `Stroller Spa` with an Online Store 2.0 page template that includes the Stroller Spa Booking section. Add it under Services in the navigation.
4. Create two **non-shipping** membership products: `Standard Travel System Care – ₹12,999` and `Premium Travel System Care – ₹18,999`. Set taxes, refund terms, inventory and payment settings as required by your accountant/merchant setup. Assign products to the section in theme editor.
5. Confirm whether Premium validity is 15 or 18 months. The latest poster says 18; earlier instruction says 15. Set the section's `Premium plan validity` and backend `PREMIUM_MONTHS` consistently.
6. Confirm service prices and savings shown in the section before publishing. All promotional savings must be supportable by the current standalone service rates.

## 2. Backend hosting
1. Deploy `backend/` on a Node 20+ HTTPS hosting environment with persistent encrypted storage; for real production use, migrate SQLite to a managed database with automated backups.
2. Set secrets using hosting environment variables; never put `ADMIN_API_KEY` or `SHOPIFY_WEBHOOK_SECRET` in Liquid/JavaScript.
3. `cd backend && npm install && npm start` (for local development only).
4. Set `PUBLIC_ORIGIN=https://kidscompany.co.in` (add the www origin if required) and configure the theme section's `Secure booking API URL` to the HTTPS backend origin.
5. Configure a Shopify `orders/paid` webhook to `https://YOUR-API/webhooks/shopify/orders-paid` using the Shopify app's webhook secret. Use the correct variant IDs for both plans. Confirm the supported webhook topic and API version in your Shopify app configuration.
6. Test paid orders, duplicate webhooks, refunds, cancellations, partial payments, failed payment, service redemption, membership expiry, CORS, and failed requests before launch.

## 3. Recommended production architecture
- Shopify storefront: booking, services, plan purchase, checkout.
- Custom embedded Shopify admin app: authenticated staff dashboard, permissions, jobs, pickups, repair approvals, photos, audit trail.
- Backend API: Shopify webhook processing, customer/product matching, prepaid service ledger, scheduling, pricing and customer portal.
- Notifications: WhatsApp Business provider with consent and approved templates.
- Secure customer portal: authenticated Shopify Customer Accounts integration or separate OTP verification.

## 4. Business rules to decide
- Travel System = registered stroller + infant car seat (0+), not carry cot.
- One entitlement means one visit servicing both registered items, not one credit per item.
- Essential and Deep balances are separate; deduct only after job completion.
- Validate gear ownership, active dates and credit balance server-side.
- Extra services, parts, pickup and drop are separately billable.
- Inspection ₹299 adjustable against approved repair work; repairs from ₹499 plus parts.
- Decide package transfer, cancellations, no-shows, partial refunds, damage claims and cleaning exclusions before launch.
- Manufacturer restrictions: avoid pressure washing or steaming safety-critical car seat harnesses or components unless the manufacturer explicitly permits it. UV and steam do not guarantee sterilization.

## 5. Production blockers in starter
- Staff API uses static API key, not Shopify OAuth or staff roles.
- No customer deduplication or verified linkage of Shopify order to registered gear.
- Refund/chargeback webhook handling, membership suspension and cancellations not implemented.
- No photo uploads, reminders, WhatsApp integration, invoice synchronization or tax calculations.
- No complete admin user interface linked to the backend.
- No automated test suite or deployment pipeline.
- Customer booking is a *request*, not confirmed slot availability.

## 6. Suggested initial acceptance tests
- Valid public booking returns reference; invalid request rejected.
- Paid Shopify membership order creates correct 2+2 or 4+2 balance.
- Duplicate webhook does not create duplicate memberships.
- Two simultaneous completion requests cannot redeem same job twice.
- Expired plan and exhausted balance are rejected.
- Completing a job without a membership does not deduct a credit.
- A membership cannot be assigned to another customer's job.
