    # ⚡ SETUP AND RUN GUIDE - Complete Step-by-Step

    This is your **single source of truth** for getting the application running.

    ---

    ## ✅ Current Status

    I've verified your project. Here's what you have:

    ✅ Backend code (25 files in `server/`)  
    ✅ Frontend code (26 files in `client/`)  
    ✅ Both `package.json` files  
    ✅ All documentation  

    ❌ Missing: `.env` file (we'll create this)  
    ❌ Missing: `node_modules` (we'll install)  
    ❌ Missing: MongoDB Atlas setup (cloud database - no installation needed!)  

    ---

    ## 🚀 STEP-BY-STEP SETUP

    Follow these steps **in order**. Don't skip any!

    ---

    ### STEP 1: Create .env File

    **Action:** Create a file named `.env` in the root folder (same level as `package.json`)

    **Location:** `E:\7 semester\info sec\Project\.env`

**Content:** Create a `.env` file with these variables:

```env
# Server Configuration
PORT=5000
NODE_ENV=development

# MongoDB Configuration
# You'll update this in STEP 4 with your MongoDB Atlas connection string
MONGODB_URI=mongodb+srv://YOUR_USERNAME:YOUR_PASSWORD@YOUR_CLUSTER.mongodb.net/infosec_project

# JWT Configuration
# Generate a strong random secret (use online generator or command: openssl rand -base64 32)
JWT_SECRET=GENERATE_YOUR_OWN_RANDOM_SECRET_HERE
JWT_EXPIRE=7d

# CORS Configuration
CORS_ORIGIN=http://localhost:3000

# Rate Limiting
RATE_LIMIT_WINDOW_MS=900000
RATE_LIMIT_MAX=100
```

**Important Security Notes:**
- Replace `YOUR_USERNAME`, `YOUR_PASSWORD`, and `YOUR_CLUSTER` with your MongoDB Atlas credentials (Step 4)
- Generate a strong JWT secret (at least 32 characters, random string)
- NEVER commit this file to Git (already protected by `.gitignore`)

    **Why:** Backend needs these environment variables to run.

    **Verify:** 
    ```bash
    # File should exist at:
    E:\7 semester\info sec\Project\.env
    ```

    ---

    ### STEP 2: Install Backend Dependencies

    **Action:** Open terminal/PowerShell in the project root folder and run:

    ```bash
    npm install
    ```

    **Expected output:**
    ```
    added 150+ packages in 30s
    ```

    **What this does:** Installs all Node.js packages (Express, MongoDB driver, Socket.io, etc.)

    **Verify:** You should now see a `node_modules` folder in the root directory.

    ---

    ### STEP 3: Install Frontend Dependencies

    **Action:** Open a NEW terminal/PowerShell, navigate to the client folder, and run:

    ```bash
    cd client
    npm install
    ```

    **Expected output:**
    ```
    added 200+ packages in 45s
    ```

    **What this does:** Installs all React packages (React, Vite, Axios, Socket.io client, etc.)

    **Verify:** You should now see a `node_modules` folder inside the `client` directory.

    ---

    ### STEP 4: Setup MongoDB Atlas (Cloud Database)

    **Why MongoDB Atlas?** No installation needed! It's free, cloud-hosted, and works on all platforms.

    **Action:** Follow these sub-steps:

    #### 4a. Create MongoDB Atlas Account

    1. Go to: https://www.mongodb.com/cloud/atlas/register
    2. Sign up with:
    - Email address
    - OR Google account
    - OR GitHub account
    3. Click **"Create your Atlas account"**

    #### 4b. Create a Free Cluster

    1. After login, you'll see **"Create a deployment"** or **"Build a Database"**
    2. Choose **"M0 FREE"** option (no credit card required!)
    3. Settings:
    - **Provider:** AWS, Google Cloud, or Azure (any is fine)
    - **Region:** Choose closest to you
    - **Cluster Name:** Leave as default or name it `SecureChat`
    4. Click **"Create Deployment"** or **"Create Cluster"**
    5. Wait 1-3 minutes for cluster to deploy

    #### 4c. Create Database User

    A modal will appear asking to create a database user:

1. **Username:** `admin` (or your choice)
2. **Password:** Create a strong password (copy it somewhere safe!)
   - Use a strong password with letters, numbers, and special characters
   - **Important**: Do NOT use common passwords
3. Click **"Create User"**

    **IMPORTANT:** Save this password! You'll need it in Step 4e.

    #### 4d. Setup Network Access

    1. The modal will ask **"Where would you like to connect from?"**
    2. Choose **"My Local Environment"**
    3. Click **"Add My Current IP Address"**
    4. For development, you can also add `0.0.0.0/0` (allows access from anywhere)
    - Click **"Add IP Address"**
    - Enter IP: `0.0.0.0/0`
    - Description: `Allow all (development only)`
    5. Click **"Finish and Close"**

    #### 4e. Get Your Connection String

    1. Click **"Connect"** button on your cluster
    2. Choose **"Connect your application"**
    3. Select:
    - **Driver:** Node.js
    - **Version:** 5.5 or later
4. Copy the connection string. It looks like:
   ```
   mongodb+srv://admin:<password>@clusterXXXXX.xxxxx.mongodb.net/?retryWrites=true&w=majority
   ```
5. **IMPORTANT:** Replace `<password>` with your actual password from step 4c
   
   Your final string will look like:
   ```
   mongodb+srv://admin:YOUR_ACTUAL_PASSWORD@clusterXXXXX.xxxxx.mongodb.net/?retryWrites=true&w=majority
   ```
   (Replace YOUR_ACTUAL_PASSWORD and clusterXXXXX with your real values)

    #### 4f. Update Your .env File

    1. Open your `.env` file (created in Step 1)
    2. Update the `MONGODB_URI` line:
    
    **Replace this:**
    ```env
    MONGODB_URI=mongodb://localhost:27017/infosec_project
    ```
    
**With this** (use YOUR connection string from step 4e):
   ```env
   MONGODB_URI=mongodb+srv://YOUR_USERNAME:YOUR_PASSWORD@YOUR_CLUSTER.xxxxx.mongodb.net/infosec_project?retryWrites=true&w=majority
   ```
   
   **Note:** 
   - Replace YOUR_USERNAME, YOUR_PASSWORD, and YOUR_CLUSTER with your actual values
   - Add `/infosec_project` before the `?` to specify the database name

    3. Save the `.env` file

**Verify:** Your `.env` should now have:
```env
MONGODB_URI=mongodb+srv://YOUR_USERNAME:YOUR_PASSWORD@YOUR_CLUSTER.xxxxx.mongodb.net/infosec_project?retryWrites=true&w=majority
```
(With your actual credentials filled in)

    ✅ **MongoDB Atlas is now setup!** No local installation needed!

    ---

    ### STEP 5: Start the Backend Server

    **Action:** Open Terminal 1 (in project root) and run:

    ```bash
    npm run dev
    ```

    **Expected output:**
    ```
    [INFO] MongoDB connected successfully
    [INFO] Server running on port 5000
    [INFO] Socket.io server initialized
    ```

    **Verify:** Open browser and go to: http://localhost:5000/health

    **Expected response:**
    ```json
    {
    "success": true,
    "message": "Server is running",
    "timestamp": "2024-12-01T12:00:00.000Z"
    }
    ```

    ✅ **If you see this, backend is running!**

    ❌ **If you get errors:**

    **Error: "MongoDB connection failed"**
    - Check your connection string in `.env`
    - Make sure you replaced `<password>` with your actual password
    - Verify your IP address is whitelisted in Atlas (or use 0.0.0.0/0)
    - Check MongoDB Atlas dashboard to ensure cluster is running

    **Error: "Port 5000 is already in use"**
    - Change `PORT=5000` to `PORT=5001` in `.env`
    - Remember to use port 5001 everywhere

    **Error: "Cannot find module"**
    - Run `npm install` again

    ---

    ### STEP 6: Start the Frontend

    **Action:** Open Terminal 2 (in project root) and run:

    ```bash
    cd client
    npm run dev
    ```

    **Expected output:**
    ```
    VITE v5.0.8  ready in 500 ms

    ➜  Local:   http://localhost:3000/
    ➜  Network: use --host to expose
    ➜  press h + enter to show help
    ```

    **Verify:** Open browser and go to: http://localhost:3000

    **Expected:** You should see a beautiful login page with gradient background.

    ✅ **If you see the login page, frontend is running!**

    ❌ **If you get errors:**

    **Error: "VITE manifest not found"**
    - Delete `client/node_modules` and `client/package-lock.json`
    - Run `npm install` again

    **Error: "Port 3000 is already in use"**
    - Vite will automatically use port 3001
    - Just use whatever port Vite shows

    **Error: "Failed to fetch"**
    - Make sure backend is running on port 5000
    - Check `client/src/services/api.js` has correct API URL

    ---

    ### STEP 7: Test Registration

    **Action:** In the browser at http://localhost:3000:

    1. Click **"Register"** link
    2. Fill in the form:
    - **Username:** `alice`
    - **Email:** `alice@example.com`
    - **Password:** `Alice@1234`
    3. Click **"Register"** button

    **Expected result:**
    - ✅ Redirected to `/chat` page
    - ✅ See "Welcome, alice!" message
    - ✅ See left sidebar with search box
    - ✅ See "🟢 Connected" at bottom right

    **Backend Terminal 1 should show:**
    ```
    [INFO] User registered: alice@example.com
    [INFO] Socket.io: User connected: alice
    ```

    **If successful, you're now logged in!**

    ---

    ### STEP 8: Create Second User

    **Action:** Open a NEW **incognito/private** browser window:

    1. Go to http://localhost:3000/register
    2. Fill in the form:
    - **Username:** `bob`
    - **Email:** `bob@example.com`
    - **Password:** `Bob@1234`
    3. Click **"Register"**

    **Expected result:**
    - ✅ Redirected to `/chat` page
    - ✅ See "Welcome, bob!"
    - ✅ Two users are now online

    **Both terminals should show:**
    ```
    [INFO] Socket.io: User connected: bob
    ```

    ---

    ### STEP 9: Send Your First Message!

    **Action:** In Bob's window (incognito):

    1. In the left sidebar search box, type: `alice`
    2. Click on **"alice"** in the user list
    3. In the message input at the bottom, type: `Hello Alice!`
    4. Press **Enter**

    **Expected result:**

    ✅ **Bob's window:**
    - Message appears: "bob: Hello Alice!"
    - Shows timestamp
    - Shows 🔒 encryption badge

    ✅ **Alice's window (normal browser):**
    - Message appears **instantly** (no refresh needed!)
    - Shows: "bob: Hello Alice!"
    - Shows timestamp
    - Shows 🔒 encryption badge

    ✅ **Backend Terminal 1:**
    ```
    [INFO] Message sent: msg_123456789
    [INFO] Socket.io: Message relayed from bob to alice
    ```

    **🎉 If you see the message in both windows, IT'S WORKING!**

    ---

    ### STEP 10: Test Message Persistence

    **Action:** In Alice's window:

    1. Click the **logout button** (🚪 icon in top right)
    2. Login again with `alice@example.com` / `Alice@1234`
    3. Click on **"bob"** in the sidebar

    **Expected result:**
    - ✅ Shows "Loading messages..." spinner (briefly)
    - ✅ Previous message loads: "bob: Hello Alice!"
    - ✅ Message persisted in database!

    **Backend Terminal 1:**
    ```
    [INFO] GET /api/messages/conversation/bob_id
    [INFO] Returned 1 message(s)
    ```

    ---

    ## ✅ SUCCESS CHECKLIST

    If all steps worked, you should have:

    - ✅ Backend running on http://localhost:5000
    - ✅ Frontend running on http://localhost:3000
    - ✅ MongoDB Atlas connected (check Atlas dashboard)
    - ✅ Two users registered (alice and bob)
    - ✅ Real-time messaging working
    - ✅ Messages persisting in database
    - ✅ Socket.io connected (🟢 Connected)

    ---

    ## 📊 Verify Everything Works

    ### Quick Test Commands:

    **1. Test Backend Health:**
    ```bash
    curl http://localhost:5000/health
    ```
    **Expected:** `{"success":true,"message":"Server is running"}`

    **2. Check MongoDB Atlas Dashboard:**
    - Go to: https://cloud.mongodb.com
    - Click on your cluster
    - Click **"Browse Collections"**
    - You should see database `infosec_project` with collections:
    - `users` (should have 2 documents: alice and bob)
    - `messages` (should have 1+ documents)
    - `logs` (should have multiple documents)

    **3. View Backend Logs:**
    ```bash
    cat server/logs/combined.log
    # Windows PowerShell:
    Get-Content server/logs/combined.log -Tail 20
    ```

    ---

    ## 🆘 TROUBLESHOOTING

    ### Problem: "MongoDB connection failed"

    **Solution:**

1. **Check your MongoDB Atlas connection string in `.env`:**
   ```env
   MONGODB_URI=mongodb+srv://YOUR_USERNAME:YOUR_PASSWORD@YOUR_CLUSTER.xxxxx.mongodb.net/infosec_project?retryWrites=true&w=majority
   ```
   (Make sure you've replaced the placeholders with your actual credentials)

    2. **Common issues:**
    - ❌ Forgot to replace `<password>` with actual password
    - ❌ Password contains special characters (URL encode them)
    - ❌ IP address not whitelisted in Atlas
    - ❌ Cluster is paused (check Atlas dashboard)

    3. **Quick fixes:**
    - Go to MongoDB Atlas → Network Access → Add `0.0.0.0/0`
    - Go to MongoDB Atlas → Database Access → Verify user exists
    - Restart your backend server: `npm run dev`

    4. **Test connection:**
    - Go to MongoDB Atlas dashboard
    - Click "Connect" → "Connect using MongoDB Compass"
    - Or use the connection string in your app

    ---

    ### Problem: "Port 5000 already in use"

    **Solution:**
    1. Edit `.env` file:
    ```env
    PORT=5001
    ```
    2. Restart backend: `npm run dev`
    3. Edit `client/src/services/api.js` line 3:
    ```javascript
    const API_URL = import.meta.env.VITE_API_URL || 'http://localhost:5001/api';
    ```
    4. Restart frontend

    ---

    ### Problem: "Cannot GET /" or 404 errors

    **Solution:**
    1. Make sure backend is running
    2. Check console for errors
    3. Verify `.env` file exists
    4. Run `npm install` again

    ---

    ### Problem: "Socket not connecting"

    **Solution:**
    1. Check browser console (F12)
    2. Should see: "✅ Socket connected"
    3. If not:
    - Make sure you're logged in (token in localStorage)
    - Check backend is running
    - Check CORS settings in `.env`: `CORS_ORIGIN=http://localhost:3000`

    ---

    ### Problem: "Messages not appearing"

    **Solution:**
    1. Check both browser consoles (F12)
    2. Bob should see: "✅ Message sent"
    3. Alice should see: "📨 Encrypted message received"
    4. If not, check both users are online
    5. Make sure both users have 🟢 Connected status

    ---

    ### Problem: "Cannot find module" errors

    **Solution:**
    ```bash
    # Backend:
    rm -rf node_modules package-lock.json
    npm install

    # Frontend:
    cd client
    rm -rf node_modules package-lock.json
    npm install
    ```

    ---

    ## 🎯 What to Do Next

    ### Your app is now running! Here's what you can do:

    1. **Send more messages** between alice and bob
    2. **Test file upload** (click 📎 icon)
    3. **Test multiple conversations** (register a 3rd user)
    4. **Check security logs** in MongoDB Atlas:
    - Go to your cluster → Browse Collections
    - Open `infosec_project` database → `logs` collection
    - See all security events logged!
    5. **View all documentation** (18+ MD files in project root)

    ### For Members 1 & 2: Implement Real Encryption

    **Current state:** Messages are encrypted with Base64 (placeholder - NOT SECURE!)

    **File to edit:** `client/src/utils/crypto.js`

    **What to implement:**
    - Real AES-GCM encryption
    - ECDH key exchange
    - RSA digital signatures

    **Backend is ready** - it will work seamlessly once you add real encryption!

    ---

    ## 📁 Project Structure (What You Have)

    ```
    Project/
    ├── .env                          ← YOU CREATED THIS
    ├── package.json                  ← Backend dependencies
    ├── node_modules/                 ← YOU INSTALLED THIS
    │
    ├── server/                       ← Backend (25 files)
    │   ├── server.js                 ← Main entry point
    │   ├── config/                   ← DB, CORS, rate limiting
    │   ├── controllers/              ← Auth, messages, files
    │   ├── routes/                   ← API endpoints
    │   ├── models/                   ← User, Message, Log schemas
    │   ├── middlewares/              ← Auth, validation, logging
    │   ├── sockets/                  ← Socket.io server
    │   ├── utils/                    ← Logger, JWT, validation
    │   └── logs/                     ← Auto-generated logs
    │
    ├── client/                       ← Frontend (26 files)
    │   ├── package.json              ← Frontend dependencies
    │   ├── node_modules/             ← YOU INSTALLED THIS
    │   ├── index.html                ← HTML entry point
    │   ├── vite.config.js            ← Vite config
    │   └── src/
    │       ├── main.jsx              ← React entry point
    │       ├── App.jsx               ← Main component + router
    │       ├── pages/                ← Login, Register, Chat
    │       ├── components/           ← MessageList, Input, etc.
    │       ├── store/                ← State management (Zustand)
    │       ├── services/             ← API calls (Axios)
    │       ├── utils/                ← Crypto functions (placeholder)
    │       └── styles/               ← CSS files
    │
    └── Documentation/                ← 18 markdown files
        ├── ⚡_SETUP_AND_RUN.md       ← THIS FILE (follow this!)
        ├── START_HERE.md             ← Quick start
        ├── INTEGRATION_GUIDE.md      ← How backend/frontend connect
        ├── API_EXAMPLES.md           ← Test APIs with curl
        ├── TESTING_GUIDE.md          ← 12 test scenarios
        └── ... more docs
    ```

    ---

    ## 📚 Documentation Files (Optional Reading)

    You have 18+ markdown files. Here's when to read them:

    | File | When to Read |
    |------|--------------|
    | **⚡_SETUP_AND_RUN.md** | **Now! (This file)** |
    | START_HERE.md | Quick overview |
    | INTEGRATION_GUIDE.md | Want to understand how backend/frontend connect |
    | API_EXAMPLES.md | Want to test APIs with curl/Postman |
    | TESTING_GUIDE.md | Want to test all 12 scenarios |
    | WEBSOCKET_IMPLEMENTATION.md | Want to understand Socket.io events |
    | LOGGING_IMPLEMENTATION.md | Want to understand security logging |
    | QUICK_REFERENCE.md | Daily development commands |

    **You don't need to read all of them to get started!** This file is enough.

    ---

    ## ✅ FINAL VERIFICATION

    Run these commands to verify everything:

    ```bash
    # 1. Check backend is running
    curl http://localhost:5000/health

    # 2. Check frontend is running
    # Open: http://localhost:3000

    # 3. Check MongoDB Atlas
    # Go to: https://cloud.mongodb.com
    # Click your cluster → Browse Collections
    # Verify collections: users, messages, logs
    ```

    ---

    ## 🎉 YOU'RE DONE!

    If you completed all 10 steps successfully, you now have:

    ✅ Complete backend server  
    ✅ Complete frontend UI  
    ✅ Real-time messaging working  
    ✅ Database persistence working  
    ✅ Security logging working  
    ✅ Zero-knowledge architecture maintained  

    **Your full-stack secure messaging application is LIVE!** 🚀

    ---

    ## 🔥 Quick Start (After Setup)

    **Next time you want to run the app:**

    ```bash
    # Terminal 1: Start Backend
    npm run dev

    # Terminal 2: Start Frontend
    cd client
    npm run dev

    # Open browser: http://localhost:3000
    ```

    **That's it!** 2 commands and you're running (MongoDB Atlas is always online!).

    ---

    **Date:** December 2, 2024  
    **Status:** ✅ READY TO RUN  
    **Next Step:** Follow STEP 1 above!

