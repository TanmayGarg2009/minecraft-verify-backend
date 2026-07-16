import express from "express";
import axios from "axios";
import dotenv from "dotenv";
import crypto from "crypto";
import { createClient } from "@supabase/supabase-js";

dotenv.config();

// =====================================================
// CONFIG
// =====================================================

const PORT = Number(process.env.PORT) || 25682;

const CLIENT_ID = process.env.CLIENT_ID;
const BOT_SECRET = process.env.BOT_SECRET;
const FRONTEND_URL = process.env.FRONTEND_URL || "https://frontend.com";

const TOKEN_TTL_MINUTES = Number(process.env.TOKEN_TTL_MINUTES) || 15;
const SESSION_TTL_MINUTES = Number(process.env.SESSION_TTL_MINUTES) || 10;
const CLEANUP_INTERVAL_MS = Number(process.env.CLEANUP_INTERVAL_MS) || 60 * 1000;

const supabase = createClient(
    process.env.SUPABASE_URL,
    process.env.SUPABASE_SERVICE_KEY
);

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
// APP
// =====================================================

const app = express();

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
// HELPERS
// =====================================================

function generateToken() {
    return crypto.randomBytes(32).toString("hex");
}

function isValidDiscordId(id) {
    return typeof id === "string" && /^\d{17,20}$/.test(id);
}

function isExpired(expiresAtStr) {
    return new Date(expiresAtStr).getTime() < Date.now();
}

// =====================================================
// BOT AUTH MIDDLEWARE
// =====================================================

function botAuth(req, res, next) {
    const auth = req.headers.authorization || "";
    const [scheme, value] = auth.split(" ");

    if (scheme !== "Bearer" || !value || value !== BOT_SECRET) {
        logWarn("Unauthorized bot request rejected.");
        return res.status(401).json({ error: "Unauthorized" });
    }

    next();
}

// =====================================================
// HEALTH CHECK
// =====================================================

app.get("/", (req, res) => {
    logInfo("Health check requested.");
    res.send("✅ Backend is running");
});

// =====================================================
// POST /api/create-token  (Discord bot only)
// =====================================================

app.post("/api/create-token", botAuth, async (req, res) => {
    try {
        const discordId = req.body?.discordId;

        if (!isValidDiscordId(discordId)) {
            logWarn(`Invalid Discord ID received: ${discordId}`);
            return res.status(400).json({ error: "Invalid discordId" });
        }

        const token = generateToken();
        const now = new Date();
        const expiresAt = new Date(now.getTime() + TOKEN_TTL_MINUTES * 60 * 1000);

        const { error } = await supabase
            .from("verification_tokens")
            .insert({
                token,
                discord_id: discordId,
                used: false,
                created_at: now.toISOString(),
                expires_at: expiresAt.toISOString()
            });

        if (error) {
            logError(`Create token DB error: ${JSON.stringify(error)}`);
            return res.status(500).json({ error: "Failed to create token" });
        }

        const verifyUrl = `${FRONTEND_URL}/verify?token=${token}`;

        logVerify(`Token created for Discord ID: ${discordId}`);

        return res.json({
            success: true,
            token,
            verifyUrl,
            expiresAt: expiresAt.toISOString()
        });
    } catch (err) {
        logError(`Create token error: ${err?.message || err}`);
        return res.status(500).json({ error: "Internal server error" });
    }
});

// =====================================================
// POST /api/start  (frontend, token only)
// =====================================================

app.post("/api/start", async (req, res) => {
    try {
        const token = req.body?.token;

        if (!token || typeof token !== "string") {
            return res.status(400).json({ error: "Missing token" });
        }

        // Validate token + resolve discord_id
        const { data: tokenRow, error: tokenErr } = await supabase
            .from("verification_tokens")
            .select("*")
            .eq("token", token)
            .single();

        if (tokenErr || !tokenRow) {
            logWarn("Start: token not found");
            return res.status(404).json({ error: "Invalid token" });
        }

        if (tokenRow.used) {
            logWarn("Start: token already used");
            return res.status(410).json({ error: "Token already used" });
        }

        if (isExpired(tokenRow.expires_at)) {
            logWarn("Start: token expired");
            return res.status(410).json({ error: "Token expired" });
        }

        const discordId = tokenRow.discord_id;

        logVerify(`Verification started for Discord ID: ${discordId} (via token)`);

        // Create Microsoft device code
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
        const now = new Date();
        const sessionExpiresAt = new Date(now.getTime() + SESSION_TTL_MINUTES * 60 * 1000);

        // Save session in Supabase
        const { error: sessionErr } = await supabase
            .from("verification_sessions")
            .insert({
                token,
                discord_id: discordId,
                device_code: data.device_code,
                status: "pending",
                created_at: now.toISOString(),
                expires_at: sessionExpiresAt.toISOString()
            });

        if (sessionErr) {
            logError(`Session insert error: ${JSON.stringify(sessionErr)}`);
            return res.status(500).json({ error: "Failed to create session" });
        }

        logSuccess("Microsoft Device Code generated successfully.");

        return res.json({
            verification_uri: data.verification_uri,
            user_code: data.user_code
        });
    } catch (err) {
        logError(
            `START ERROR: ${JSON.stringify(err.response?.data || err.message)}`
        );
        return res.status(500).json({ error: "Failed to start verification" });
    }
});

// =====================================================
// GET /api/status?token=  (frontend, token only)
// =====================================================

app.get("/api/status", async (req, res) => {
    try {
        const token = req.query.token;

        if (!token || typeof token !== "string") {
            return res.status(400).json({ error: "Missing token" });
        }

        // Find session
        const { data: session, error: sessionErr } = await supabase
            .from("verification_sessions")
            .select("*")
            .eq("token", token)
            .order("created_at", { ascending: false })
            .limit(1)
            .single();

        if (sessionErr || !session) {
            return res.json({ status: "not_found" });
        }

        // Already completed
        if (session.status === "success") {
            return res.json({
                status: "success",
                username: session.minecraft_username,
                uuid: session.minecraft_uuid
            });
        }

        if (session.status === "cancelled") {
            return res.json({ status: "cancelled" });
        }

        if (session.status === "expired") {
            return res.json({ status: "expired" });
        }

        if (session.status === "error") {
            return res.json({ status: "error" });
        }

        // Session timeout
        if (isExpired(session.expires_at)) {
            await supabase
                .from("verification_sessions")
                .update({ status: "expired" })
                .eq("id", session.id);

            logWarn("Session expired for token");
            return res.json({ status: "expired" });
        }

        // Poll Microsoft
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

        // =================================================
        // XBOX AUTH
        // =================================================

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

        // =================================================
        // XSTS AUTH
        // =================================================

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

        // =================================================
        // MINECRAFT LOGIN
        // =================================================

        const mcAuth = await axios.post(
            "https://api.minecraftservices.com/authentication/login_with_xbox",
            {
                identityToken: `XBL3.0 x=${uhs};${xstsToken}`
            }
        );

        const mcToken = mcAuth.data.access_token;

        logSuccess("Minecraft authentication successful.");

        // =================================================
        // FETCH PROFILE
        // =================================================

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
            await supabase
                .from("verification_sessions")
                .update({ status: "error" })
                .eq("id", session.id);

            logWarn(`Discord ${session.discord_id} does not own Minecraft.`);

            return res.json({ status: "no_minecraft" });
        }

        const username = profileData.name;
        const uuid = profileData.id;

        logInfo(`Minecraft Username : ${username}`);
        logInfo(`Minecraft UUID     : ${uuid}`);

        // =================================================
        // SAVE TO SUPABASE (verifications)
        // =================================================

        logInfo("Saving verification to Supabase...");

        const { error: upsertErr } = await supabase
            .from("verifications")
            .upsert(
                {
                    discord_id: session.discord_id,
                    minecraft_username: username,
                    minecraft_uuid: uuid,
                    verified_at: new Date().toISOString(),
                    verification_method: "microsoft",
                    updated_at: new Date().toISOString()
                },
                { onConflict: "discord_id" }
            );

        if (upsertErr) {
            logError(`SUPABASE ERROR:\n${JSON.stringify(upsertErr, null, 2)}`);

            await supabase
                .from("verification_sessions")
                .update({ status: "error" })
                .eq("id", session.id);

            return res.json({ status: "db_error" });
        }

        logSuccess("Verification stored successfully.");

        // Update session
        await supabase
            .from("verification_sessions")
            .update({
                status: "success",
                minecraft_uuid: uuid,
                minecraft_username: username,
                completed_at: new Date().toISOString()
            })
            .eq("id", session.id);

        // Mark token as used
        await supabase
            .from("verification_tokens")
            .update({
                used: true,
                used_at: new Date().toISOString()
            })
            .eq("token", token);

        logVerify(`${username} has been verified successfully.`);

        return res.json({
            status: "success",
            username,
            uuid
        });
    } catch (err) {
        const msError = err.response?.data?.error;

        if (msError === "authorization_pending") {
            return res.json({ status: "pending" });
        }

        if (msError === "authorization_declined") {
            await updateSessionStatusByToken(req.query.token, "cancelled");
            logWarn("User cancelled Microsoft verification.");
            return res.json({ status: "cancelled" });
        }

        if (msError === "expired_token" || msError === "invalid_grant") {
            await updateSessionStatusByToken(req.query.token, "expired");
            logWarn("Device code expired or already used.");
            return res.json({ status: "expired" });
        }

        logError(
            `STATUS ERROR:\n${JSON.stringify(
                err.response?.data || err.message,
                null,
                2
            )}`
        );

        await updateSessionStatusByToken(req.query.token, "error");

        return res.json({ status: "error" });
    }
});

// Helper to update session status by token
async function updateSessionStatusByToken(token, status) {
    try {
        await supabase
            .from("verification_sessions")
            .update({ status })
            .eq("token", token);
    } catch (e) {
        logError(`Failed to update session status: ${e?.message || e}`);
    }
}

// =====================================================
// GET /api/profile?discordId=  (compatibility)
// =====================================================

app.get("/api/profile", async (req, res) => {
    const discordId = String(req.query.discordId);

    if (!discordId) {
        return res.status(400).json({ error: "Missing discordId" });
    }

    logInfo(`Profile lookup requested for Discord ID: ${discordId}`);

    const { data, error } = await supabase
        .from("verifications")
        .select("*")
        .eq("discord_id", discordId)
        .single();

    if (error || !data) {
        logWarn(`No verification found for ${discordId}`);
        return res.json({ status: "not_found" });
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
// CLEANUP JOBS
// =====================================================

setInterval(async () => {
    try {
        const now = new Date().toISOString();

        // Expire pending sessions
        const { error: sessErr } = await supabase
            .from("verification_sessions")
            .update({ status: "expired" })
            .lt("expires_at", now)
            .eq("status", "pending");

        if (sessErr) {
            logError(`Cleanup sessions error: ${JSON.stringify(sessErr)}`);
        }

        // Delete old tokens (older than 24h)
        const cutoff = new Date(Date.now() - 24 * 60 * 60 * 1000).toISOString();
        const { error: tokErr } = await supabase
            .from("verification_tokens")
            .delete()
            .lt("expires_at", cutoff);

        if (tokErr) {
            logError(`Cleanup tokens error: ${JSON.stringify(tokErr)}`);
        }

        logInfo("Cleanup job completed.");
    } catch (e) {
        logError(`Cleanup job failed: ${e?.message || e}`);
    }
}, CLEANUP_INTERVAL_MS);

// =====================================================
// START SERVER
// =====================================================

const server = app.listen(PORT, () => {
    console.clear();

    console.log("");
    console.log("==================================================");
    console.log("            Minecraft Verify Backend");
    console.log("==================================================");
    console.log("");

    logSuccess("Backend started successfully.");
    logInfo(`Listening on port ${PORT}`);
    logInfo(`Microsoft Client ID: ${CLIENT_ID}`);
    logInfo(`Frontend URL: ${FRONTEND_URL}`);

    if (process.env.SUPABASE_URL) {
        logSuccess("Supabase configured.");
    } else {
        logWarn("SUPABASE_URL is missing.");
    }

    if (!BOT_SECRET) {
        logWarn("BOT_SECRET is missing — /api/create-token will reject all requests.");
    }

    console.log("");
    console.log("Endpoints:");
    console.log(`GET    http://localhost:${PORT}/`);
    console.log(`POST   http://localhost:${PORT}/api/create-token  (bot only)`);
    console.log(`POST   http://localhost:${PORT}/api/start`);
    console.log(`GET    http://localhost:${PORT}/api/status`);
    console.log(`GET    http://localhost:${PORT}/api/profile`);
    console.log("");
    console.log("==================================================");
    console.log("");
});

// =====================================================
// GRACEFUL SHUTDOWN
// =====================================================

function shutdown(signal) {
    logWarn(`Received ${signal}. Shutting down gracefully...`);

    server.close(() => {
        logSuccess("Server closed successfully.");
        process.exit(0);
    });

    // Force exit after 10s
    setTimeout(() => {
        logError("Forced shutdown after timeout.");
        process.exit(1);
    }, 10000);
}

process.on("SIGINT", () => shutdown("SIGINT"));
process.on("SIGTERM", () => shutdown("SIGTERM"));

// =====================================================
// GLOBAL ERROR HANDLERS
// =====================================================

process.on("unhandledRejection", (reason) => {
    logError(
        `Unhandled Promise Rejection:\n${reason?.stack || JSON.stringify(reason, null, 2)}`
    );
});

process.on("uncaughtException", (err) => {
    logError(
        `Uncaught Exception:\n${err?.stack || JSON.stringify(err, null, 2)}`
    );
});