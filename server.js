import express from "express";
import axios from "axios";
import dotenv from "dotenv";
import { createClient } from "@supabase/supabase-js";

dotenv.config();

const app = express();

// =====================================================
// MIDDLEWARE
// =====================================================

app.use(express.json());

// CORS
app.use((req, res, next) => {
    res.header("Access-Control-Allow-Origin", "*");
    res.header(
        "Access-Control-Allow-Headers",
        "Content-Type, Authorization, ngrok-skip-browser-warning"
    );
    res.header(
        "Access-Control-Allow-Methods",
        "GET, POST, OPTIONS"
    );

    if (req.method === "OPTIONS") {
        return res.sendStatus(200);
    }

    next();
});

// ngrok / Cloudflare bypass
app.use((req, res, next) => {
    res.setHeader("ngrok-skip-browser-warning", "true");
    next();
});

// =====================================================
// CONFIG
// =====================================================

const CLIENT_ID = process.env.CLIENT_ID;

const supabase = createClient(
    process.env.SUPABASE_URL,
    process.env.SUPABASE_SERVICE_KEY
);

// Active verification sessions
const sessions = new Map();

// =====================================================
// LOGGER
// =====================================================

const colors = {
    reset: "\x1b[0m",
    bright: "\x1b[1m",

    red: "\x1b[31m",
    green: "\x1b[32m",
    yellow: "\x1b[33m",
    blue: "\x1b[34m",
    magenta: "\x1b[35m",
    cyan: "\x1b[36m",
    white: "\x1b[37m"
};

function timestamp() {
    return new Date().toLocaleString();
}

function logInfo(msg) {
    console.log(`${colors.cyan}[INFO]${colors.reset} ${timestamp()} | ${msg}`);
}

function logSuccess(msg) {
    console.log(`${colors.green}[SUCCESS]${colors.reset} ${timestamp()} | ${msg}`);
}

function logWarn(msg) {
    console.log(`${colors.yellow}[WARNING]${colors.reset} ${timestamp()} | ${msg}`);
}

function logError(msg) {
    console.log(`${colors.red}[ERROR]${colors.reset} ${timestamp()} | ${msg}`);
}

function logVerify(msg) {
    console.log(`${colors.magenta}[VERIFY]${colors.reset} ${timestamp()} | ${msg}`);
}

// =====================================================
// HEALTH CHECK
// =====================================================

app.get("/", (req, res) => {

    logInfo("Health check requested.");

    res.send("✅ Backend is running");

});

// =====================================================
// START VERIFICATION
// =====================================================

app.post("/api/start", async (req, res) => {

    const discordId = String(req.body.discordId);

    if (!discordId || !/^\d{17,20}$/.test(discordId)) {

        logWarn(`Invalid Discord ID received: ${discordId}`);

        return res.status(400).json({
            error: "Invalid discordId"
        });

    }

    logVerify(`Verification started for Discord ID: ${discordId}`);

    try {

        const response = await axios.post(
            "https://login.microsoftonline.com/consumers/oauth2/v2.0/devicecode",
            new URLSearchParams({
                client_id: CLIENT_ID,
                scope: "XboxLive.signin offline_access"
            }),
            {
                headers: {
                    "Content-Type": "application/x-www-form-urlencoded"
                }
            }
        );

        const data = response.data;

        sessions.set(discordId, {

            status: "pending",
            device_code: data.device_code,
            createdAt: Date.now()

        });

        logSuccess("Microsoft Device Code generated successfully.");

        res.json({

            user_code: data.user_code,
            verification_uri: data.verification_uri

        });

    } catch (err) {

        logError(
            `START ERROR: ${
                JSON.stringify(err.response?.data || err.message)
            }`
        );

        return res.status(500).json({
            error: "Failed to start verification"
        });

    }

});

// =====================================================
// STATUS
// =====================================================

app.get("/api/status", async (req, res) => {

    const discordId = String(req.query.discordId);

    const session = sessions.get(discordId);

    if (!session) {

        return res.json({
            status: "not_found"
        });

    }

    // Session timeout (5 minutes)

    if (Date.now() - session.createdAt > 5 * 60 * 1000) {

        sessions.delete(discordId);

        logWarn(`Session expired for ${discordId}`);

        return res.json({
            status: "timeout"
        });

    }

    // Already verified

    if (session.status === "success") {

        return res.json(session);

    }

    try {

        logInfo("Checking Microsoft Device Flow status...");

        const tokenRes = await axios.post(
            "https://login.microsoftonline.com/consumers/oauth2/v2.0/token",
            new URLSearchParams({

                grant_type: "urn:ietf:params:oauth:grant-type:device_code",

                client_id: CLIENT_ID,

                device_code: session.device_code

            }),
            {

                headers: {
                    "Content-Type": "application/x-www-form-urlencoded"
                }

            }
        );

        const access_token = tokenRes.data.access_token;

        logSuccess("Microsoft login successful.");
        // =====================================================
        // XBOX AUTH
        // =====================================================

        const xbox = await axios.post(
            "https://user.auth.xboxlive.com/user/authenticate",
            {
                Properties: {
                    AuthMethod: "RPS",
                    SiteName: "user.auth.xboxlive.com",
                    RpsTicket: `d=${access_token}`
                },
                RelyingParty: "http://auth.xboxlive.com",
                TokenType: "JWT"
            }
        );

        const xblToken = xbox.data.Token;
        const uhs = xbox.data.DisplayClaims.xui[0].uhs;

        logSuccess("Xbox authentication successful.");

        // =====================================================
        // XSTS AUTH
        // =====================================================

        const xsts = await axios.post(
            "https://xsts.auth.xboxlive.com/xsts/authorize",
            {
                Properties: {
                    SandboxId: "RETAIL",
                    UserTokens: [xblToken]
                },
                RelyingParty: "rp://api.minecraftservices.com/",
                TokenType: "JWT"
            }
        );

        const xstsToken = xsts.data.Token;

        logSuccess("XSTS authentication successful.");

        // =====================================================
        // MINECRAFT LOGIN
        // =====================================================

        const mcAuth = await axios.post(
            "https://api.minecraftservices.com/authentication/login_with_xbox",
            {
                identityToken: `XBL3.0 x=${uhs};${xstsToken}`
            }
        );

        const mcToken = mcAuth.data.access_token;

        logSuccess("Minecraft authentication successful.");

        // =====================================================
        // FETCH PROFILE
        // =====================================================

        let profileData;

        try {

            const profile = await axios.get(
                "https://api.minecraftservices.com/minecraft/profile",
                {
                    headers: {
                        Authorization: `Bearer ${mcToken}`
                    }
                }
            );

            profileData = profile.data;

        } catch {

            sessions.set(discordId, {
                status: "no_minecraft"
            });

            logWarn(`Discord ${discordId} does not own Minecraft.`);

            return res.json({
                status: "no_minecraft"
            });

        }

        const username = profileData.name;
        const uuid = profileData.id;

        logInfo(`Minecraft Username : ${username}`);
        logInfo(`Minecraft UUID     : ${uuid}`);

        // =====================================================
        // SAVE TO SUPABASE
        // =====================================================

        logInfo("Saving verification to Supabase...");

        const { error } = await supabase
            .from("verifications")
            .upsert(
                {
                    discord_id: discordId,
                    minecraft_username: username,
                    minecraft_uuid: uuid,
                    verified_at: new Date().toISOString()
                },
                {
                    onConflict: "discord_id"
                }
            );

        if (error) {

            logError(
                `SUPABASE ERROR:\n${JSON.stringify(error, null, 2)}`
            );

            return res.json({
                status: "db_error"
            });

        }

        logSuccess("Verification stored successfully.");

        sessions.set(discordId, {

            status: "success",

            username,

            uuid

        });

        logVerify(`${username} has been verified successfully.`);

        return res.json({

            status: "success",

            username,

            uuid

        });

    } catch (err) {

        if (err.response?.data?.error === "authorization_pending") {

            return res.json({
                status: "pending"
            });

        }

        if (err.response?.data?.error === "authorization_declined") {

            sessions.delete(discordId);

            logWarn(`User cancelled Microsoft verification.`);

            return res.json({
                status: "cancelled"
            });

        }

        if (err.response?.data?.error === "expired_token") {

            sessions.delete(discordId);

            logWarn(`Device code expired.`);

            return res.json({
                status: "expired"
            });

        }

        if (err.response?.data?.error === "invalid_grant") {

            sessions.delete(discordId);

            logWarn("Device code has already been used.");

            return res.json({
                status: "expired"
            });

        }

        logError(
            `STATUS ERROR:\n${JSON.stringify(
                err.response?.data || err.message,
                null,
                2
            )}`
        );

        sessions.delete(discordId);

        return res.json({
            status: "error"
        });

    }

});
// =====================================================
// PROFILE
// =====================================================

app.get("/api/profile", async (req, res) => {

    const discordId = String(req.query.discordId);

    if (!discordId) {

        return res.status(400).json({
            error: "Missing discordId"
        });

    }

    logInfo(`Profile lookup requested for Discord ID: ${discordId}`);

    const { data, error } = await supabase
        .from("verifications")
        .select("*")
        .eq("discord_id", discordId)
        .single();

    if (error || !data) {

        logWarn(`No verification found for ${discordId}`);

        return res.json({
            status: "not_found"
        });

    }

    logSuccess(
        `Profile found -> ${data.minecraft_username} (${data.minecraft_uuid})`
    );

    return res.json({

        status: "success",

        username: data.minecraft_username,

        uuid: data.minecraft_uuid

    });

});

// =====================================================
// CLEANUP OLD SESSIONS
// =====================================================

// Remove expired sessions every minute
setInterval(() => {

    const now = Date.now();

    for (const [discordId, session] of sessions.entries()) {

        if (now - session.createdAt > 10 * 60 * 1000) {

            sessions.delete(discordId);

            logInfo(`Removed expired session for ${discordId}`);

        }

    }

}, 60 * 1000);

// =====================================================
// START SERVER
// =====================================================

const PORT = Number(process.env.PORT) || 25682;

app.listen(PORT, () => {

    console.clear();

    console.log("");
    console.log("==================================================");
    console.log("            Minecraft Verify Backend");
    console.log("==================================================");
    console.log("");

    logSuccess("Backend started successfully.");
    logInfo(`Listening on port ${PORT}`);
    logInfo(`Microsoft Client ID: ${CLIENT_ID}`);

    if (process.env.SUPABASE_URL) {
        logSuccess("Supabase connected.");
    } else {
        logWarn("SUPABASE_URL is missing.");
    }

    console.log("");
    console.log("Endpoints:");
    console.log(`GET    http://localhost:${PORT}/`);
    console.log(`POST   http://localhost:${PORT}/api/start`);
    console.log(`GET    http://localhost:${PORT}/api/status`);
    console.log(`GET    http://localhost:${PORT}/api/profile`);
    console.log("");
    console.log("==================================================");
    console.log("");

});

// =====================================================
// GLOBAL ERROR HANDLERS
// =====================================================

process.on("unhandledRejection", (reason) => {

    logError(
        `Unhandled Promise Rejection:\n${
            reason?.stack || JSON.stringify(reason, null, 2)
        }`
    );

});

process.on("uncaughtException", (err) => {

    logError(
        `Uncaught Exception:\n${
            err?.stack || JSON.stringify(err, null, 2)
        }`
    );

});