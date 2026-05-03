import type { ExportedHandler, ExecutionContext } from "cloudflare:workers";

// ── Types ──────────────────────────────────────────────────────────
export interface Env {
  DB: D1Database;
  BOT_TOKEN: string;          // Secret: Telegram Bot Token
  ADMIN_SETUP_TOKEN: string;  // Secret: Password to trigger the /setup endpoint
  WEBHOOK_SECRET: string;     // Var: Passed to Telegram, checked on incoming requests
}

interface TelegramUser {
  id: number;
  is_bot: boolean;
  first_name: string;
  last_name?: string;
  username?: string;
}

interface TelegramUpdate {
  update_id: number;
  message?: {
    message_id: number;
    from?: TelegramUser;
    chat: { id: number; type: string };
    text?: string;
    new_chat_members?: TelegramUser[];
  };
}

// ── Main Worker Entry Point ────────────────────────────────────────
export default {
  async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    const url = new URL(request.url);

    // 1. Setup Endpoint (Convenience route to register webhook)
    if (request.method === "GET" && url.pathname === "/setup") {
      const token = url.searchParams.get("token");
      if (token !== env.ADMIN_SETUP_TOKEN) return new Response("Unauthorized", { status: 401 });

      const webhookUrl = `https://${url.hostname}/webhook`;
      const setupReq = await fetch(`https://api.telegram.org/bot${env.BOT_TOKEN}/setWebhook`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          url: webhookUrl,
          secret_token: env.WEBHOOK_SECRET,
          allowed_updates: ["message"]
        })
      });
      
      const result = await setupReq.json();
      return Response.json({ success: true, webhookUrl, telegram_response: result });
    }

    // 2. Webhook Endpoint (Receives updates from Telegram)
    if (request.method === "POST" && url.pathname === "/webhook") {
      // Validate request is genuinely from Telegram using constant-time comparison
      const providedSecret = request.headers.get("X-Telegram-Bot-Api-Secret-Token") || "";
      if (!(await timingSafeEqual(providedSecret, env.WEBHOOK_SECRET))) {
        return new Response("Unauthorized", { status: 401 });
      }

      try {
        const update = await request.json<TelegramUpdate>();
        
        // Pass processing to background so Telegram gets a 200 OK instantly (prevents retries)
        ctx.waitUntil(processUpdate(update, env));
        
        return new Response("OK");
      } catch (e) {
        console.error("Webhook processing error:", e);
        return new Response("Bad Request", { status: 400 });
      }
    }

    return new Response("EPIC Guardian Online", { status: 200 });
  },
} satisfies ExportedHandler<Env>;

// ── Core Logic ─────────────────────────────────────────────────────

async function processUpdate(update: TelegramUpdate, env: Env): Promise<void> {
  const msg = update.message;
  if (!msg) return;

  const chatId = msg.chat.id;

  // Track the sender
  if (msg.from) {
    await trackUserIdentity(msg.from, chatId, env);
  }

  // Track newly joined members
  if (msg.new_chat_members) {
    for (const member of msg.new_chat_members) {
      await trackUserIdentity(member, chatId, env);
    }
  }

  // Handle Text Commands
  if (msg.text && msg.from) {
    const text = msg.text.trim();
    
    if (text.startsWith("/start")) {
      const welcomeText = `🛡 *EPIC Guardian*\n\nWhat can this bot do?\n\nI identify community members altering their Telegram username or handle, sending notifications for each change\\. This helps spot scammers early, allowing for potential banning and ensuring community safety\\.\n\nUse \`/history @username\` to check a member's past names\\.`;
      await sendTelegramMessage(env, chatId, welcomeText, msg.message_id);
    } 
    else if (text.startsWith("/history")) {
      const parts = text.split(/\s+/);
      const target = parts[1]?.replace("@", "");
      
      if (!target) {
        await sendTelegramMessage(env, chatId, "Please provide a username\\. Example: `/history @username`");
        return;
      }
      await checkHistory(target, chatId, env);
    }
  }
}

async function trackUserIdentity(user: TelegramUser, chatId: number, env: Env) {
  if (user.is_bot) return; // Do not track other bots

  // Use prepared statements to prevent SQL injection
  const dbUser = await env.DB.prepare("SELECT * FROM users WHERE id = ?")
    .bind(user.id)
    .first<{ username: string | null; first_name: string | null; last_name: string | null }>();

  // If user doesn't exist, insert them silently
  if (!dbUser) {
    await env.DB.prepare(
      "INSERT INTO users (id, username, first_name, last_name) VALUES (?, ?, ?, ?)"
    ).bind(user.id, user.username || null, user.first_name || null, user.last_name || null).run();
    return;
  }

  const changes: { type: string; old: string; new: string }[] = [];
  const safeStr = (val?: string | null) => val || "";

  if (safeStr(dbUser.username) !== safeStr(user.username)) {
    changes.push({ type: "username", old: safeStr(dbUser.username), new: safeStr(user.username) });
  }
  if (safeStr(dbUser.first_name) !== safeStr(user.first_name)) {
    changes.push({ type: "first_name", old: safeStr(dbUser.first_name), new: safeStr(user.first_name) });
  }
  if (safeStr(dbUser.last_name) !== safeStr(user.last_name)) {
    changes.push({ type: "last_name", old: safeStr(dbUser.last_name), new: safeStr(user.last_name) });
  }

  // Execute updates if changes were found
  if (changes.length > 0) {
    const batchStatements = [];
    const escapedFirstName = escapeMarkdown(user.first_name);
    let alertMessage = `🚨 *Identity Change Detected\\!*\nUser: [${escapedFirstName}](tg://user?id=${user.id})\n\n`;

    for (const change of changes) {
      batchStatements.push(
        env.DB.prepare(
          "INSERT INTO name_history (user_id, change_type, old_value, new_value) VALUES (?, ?, ?, ?)"
        ).bind(user.id, change.type, change.old, change.new)
      );

      const oldEscaped = change.old ? `\`${escapeMarkdown(change.old)}\`` : '\\<None\\>';
      const newEscaped = change.new ? `\`${escapeMarkdown(change.new)}\`` : '\\<None\\>';
      alertMessage += `• *${escapeMarkdown(change.type)}*: ${oldEscaped} ➡️ ${newEscaped}\n`;
    }

    batchStatements.push(
      env.DB.prepare(
        "UPDATE users SET username = ?, first_name = ?, last_name = ?, last_seen_at = unixepoch() WHERE id = ?"
      ).bind(user.username || null, user.first_name || null, user.last_name || null, user.id)
    );

    // D1 Batch executes all statements atomically
    await env.DB.batch(batchStatements);

    // Notify the community
    await sendTelegramMessage(env, chatId, alertMessage);
  } else {
    // Just update the last_seen_at timestamp
    await env.DB.prepare("UPDATE users SET last_seen_at = unixepoch() WHERE id = ?").bind(user.id).run();
  }
}

async function checkHistory(targetUsername: string, chatId: number, env: Env) {
  const targetUser = await env.DB.prepare("SELECT id, first_name FROM users WHERE username = COLLATE NOCASE ?")
    .bind(targetUsername)
    .first<{ id: number, first_name: string }>();

  if (!targetUser) {
    await sendTelegramMessage(env, chatId, `❌ I haven't seen any user with the username @${escapeMarkdown(targetUsername)}\\.`);
    return;
  }

  const { results } = await env.DB.prepare(
    "SELECT change_type, old_value, new_value, datetime(changed_at, 'unixepoch') as date FROM name_history WHERE user_id = ? ORDER BY changed_at DESC LIMIT 15"
  )
  .bind(targetUser.id)
  .all<{ change_type: string, old_value: string, new_value: string, date: string }>();

  if (results.length === 0) {
    await sendTelegramMessage(env, chatId, `✅ No historical name changes recorded for @${escapeMarkdown(targetUsername)}\\.`);
    return;
  }

  let historyMsg = `📖 *Identity History for* [${escapeMarkdown(targetUser.first_name)}](tg://user?id=${targetUser.id}):\n\n`;
  for (const record of results) {
    historyMsg += `📅 ${escapeMarkdown(record.date)}\n`;
    
    const oldEscaped = record.old_value ? `\`${escapeMarkdown(record.old_value)}\`` : '\\<None\\>';
    const newEscaped = record.new_value ? `\`${escapeMarkdown(record.new_value)}\`` : '\\<None\\>';
    
    historyMsg += `• Changed *${escapeMarkdown(record.change_type)}*: ${oldEscaped} ➡️ ${newEscaped}\n\n`;
  }

  await sendTelegramMessage(env, chatId, historyMsg);
}

// ── Utilities ──────────────────────────────────────────────────────

async function sendTelegramMessage(env: Env, chatId: number, text: string, replyToMessageId?: number) {
  const url = `https://api.telegram.org/bot${env.BOT_TOKEN}/sendMessage`;
  const body: any = {
    chat_id: chatId,
    text: text,
    parse_mode: "MarkdownV2",
    disable_web_page_preview: true
  };

  if (replyToMessageId) {
    body.reply_to_message_id = replyToMessageId;
  }

  await fetch(url, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
}

/**
 * Escapes characters reserved by Telegram's MarkdownV2
 * _ * [ ] ( ) ~ ` > # + - = | { } . !
 */
function escapeMarkdown(text: string | null | undefined): string {
  if (!text) return "";
  return text.replace(/[_*[\]()~`>#+\-=|{}.!]/g, '\\$&');
}

/**
 * Prevents timing attacks when comparing secrets
 */
async function timingSafeEqual(a: string, b: string): Promise<boolean> {
  const encoder = new TextEncoder();
  const aBytes = encoder.encode(a);
  const bBytes = encoder.encode(b);
  
  if (aBytes.byteLength !== bBytes.byteLength) return false;
  return await crypto.subtle.timingSafeEqual(aBytes, bBytes);
}
