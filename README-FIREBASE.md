# VG CHEATS SHOP — Secure Firebase + GitHub + Vercel

The visual design of the existing site is preserved.

## Architecture

- **Firebase Authentication**
  - Owner: Google identity + server-side `OWNER_EMAILS`
  - Admin/Reseller: username + password → Firebase custom token
  - Public users: Firebase email/password
- **Realtime Database**
  - Public shop/catalog/settings
  - Per-user wallet/orders/profile
  - Owner-only user account metadata
  - Owner-only key pool
- **Security Rules**
  - Owner: full backend management
  - Admin: read-only access to allowed operational data
  - Reseller/Public: only their own user data + public catalog
- **Cloud Functions**
  - secure login/registration
  - user creation and role management
  - wallet balance changes
  - wallet purchases
  - manual orders/top-ups
  - Razorpay order creation
  - Razorpay signature verification
  - secure key delivery
  - owner order approval/rejection/deletion
  - key-pool management
- **Vercel**
  - static frontend only
- **GitHub**
  - source repository

## IMPORTANT: Vercel does not host Firebase Cloud Functions

The website frontend is deployed on Vercel, while the secure backend functions are deployed to Firebase.

## Firebase setup

1. Create a Firebase project.
2. Add a Web App.
3. Enable Authentication:
   - Google
   - Email/Password
   - Anonymous (only for public catalog bootstrap)
4. Create Realtime Database.
5. Copy the Web SDK config into `FIREBASE_CFG` in `index.html`.
6. In Firebase Authentication → Settings → Authorized domains, add your Vercel domain.

## Install Firebase CLI

```bash
npm install -g firebase-tools
firebase login
firebase use YOUR_FIREBASE_PROJECT_ID
```

## Set backend secrets

Run from the project root:

```bash
firebase functions:secrets:set OWNER_EMAILS
firebase functions:secrets:set RAZORPAY_KEY_ID
firebase functions:secrets:set RAZORPAY_KEY_SECRET
```

For `OWNER_EMAILS`, enter one or more owner email addresses separated by commas.

For Razorpay:
- `RAZORPAY_KEY_ID` = public Key ID
- `RAZORPAY_KEY_SECRET` = secret key

Never put the Razorpay secret in `index.html`.

## Deploy Firebase backend

```bash
cd functions
npm install
cd ..
firebase deploy --only functions,database
```

## Deploy frontend to Vercel

Push the project files to GitHub and import the repository in Vercel.

Recommended Vercel settings:
- Framework Preset: Other
- Build Command: empty
- Output Directory: `.`
- Install Command: empty

## First Owner login

The Owner button still uses the existing modal visual. The final authentication authority is Google + the server-side `OWNER_EMAILS` secret.

The email typed into localStorage is NOT trusted for Owner privileges.

## Existing data migration

The old website used browser localStorage. This secure version keeps localStorage as a UI cache, but authoritative user/wallet/order/key data is moved to Firebase when the new authenticated flow is used.

For old users:
1. Log in as Owner using the new Firebase Owner flow.
2. Existing local user records can be synchronized through the Owner Users panel.
3. For production, create fresh Admin/Reseller accounts from the Owner panel so Firebase Auth credentials are generated securely.

## Security model

### Owner
Can:
- manage users
- assign Admin/Reseller roles
- change discount
- block/unblock
- change wallet balances
- manage panels/rates/site settings
- manage key pool
- approve/reject orders
- delete orders

### Admin
Can:
- authenticate
- access public catalog
- read operational order data through secured backend permissions

Admin cannot:
- change wallet balances
- manage Owner
- manage the key pool
- change Owner settings

### Reseller/Public
Can:
- authenticate
- read public shop data
- read/write only their own allowed profile/order data
- use their own wallet through server-side transactions

They cannot:
- read another user's wallet
- read another user's private orders
- access key pool
- approve orders
- change roles
- change prices
- access Owner data

## Payment security

Razorpay flow is now:
1. Client asks Cloud Function to create an order.
2. Cloud Function calculates the amount.
3. Razorpay checkout opens with the server-created order.
4. Razorpay returns payment data.
5. Cloud Function verifies the HMAC signature.
6. Only after verification does the backend mark payment successful and consume keys.

Wallet purchases are server-side transactions.

## Key security

Keys are stored in:
`vgcheats/secure/keypool/...`

Only Owner can read/write the key pool through database rules.

Key delivery happens inside Cloud Functions and uses an atomic transaction to avoid the same key being delivered to two customers.

## Secret handling

Do NOT commit:
- Razorpay Key Secret
- KeyAuth seller secret
- Firebase Admin credentials
- `.env` files

The old `kaseller` value is deliberately not uploaded to Firebase public settings.

## Design

No visual redesign was intentionally made. The secure backend is layered underneath the existing UI.


## Firebase project already configured
This package is preconfigured for Firebase project `vgshop-6009a`. Do not add the Firebase web config again.

Before production use, enable Authentication providers (Anonymous/Google as used by the UI), create Realtime Database, deploy the supplied rules and Cloud Functions, and add the Vercel domain under Firebase Authentication → Settings → Authorized domains.


## Owner Gmail OTP (secure)
The Owner OTP is server-side verified. The browser no longer decides whether an OTP is valid and does not launch Google Login after OTP.

Before deploying Functions, configure the Owner Gmail:
```bash
firebase functions:secrets:set OWNER_EMAILS
```
When prompted, enter the allowed owner email(s), comma-separated if needed.

The EmailJS service/template/public key used by the existing site are used by the `sendOwnerOtp` Cloud Function to send the OTP. The OTP is generated, hashed, stored with a 10-minute expiry and max 5 attempts, then verified server-side.

The Owner OTP input is 6 digits.

## Deploy
```bash
firebase use vgshop-6009a
firebase deploy --only functions,database
```

After changing Functions, Vercel only needs the updated `index.html` from GitHub. Firebase Functions are deployed separately with the Firebase CLI.
