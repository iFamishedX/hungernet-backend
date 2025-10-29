export interface Env {
  DB: D1Database;
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);
    const path = url.pathname;
    const method = request.method;

    if (path === "/signup" && method === "POST") return signup(request, env);
    if (path === "/login" && method === "POST") return login(request, env);
    if (path === "/settings" && method === "GET") return getSettings(request, env);
    if (path === "/settings" && method === "POST") return updateSettings(request, env);

    return new Response("Not found", { status: 404 });
  }
};

async function hashPassword(password: string): Promise<string> {
  const buffer = new TextEncoder().encode(password);
  const hashBuffer = await crypto.subtle.digest("SHA-256", buffer);
  return Array.from(new Uint8Array(hashBuffer)).map(b => b.toString(16).padStart(2, "0")).join("");
}

async function signup(request: Request, env: Env): Promise<Response> {
  const { email, password } = await request.json() as { email: string; password: string };
  if (!email || !password) return json({ error: "Missing email or password" }, 400);

  const hash = await hashPassword(password);

  try {
    const user = await env.DB.prepare(
      "INSERT INTO users (email, password_hash) VALUES (?, ?) RETURNING id"
    ).bind(email, hash).first();

    await env.DB.prepare(
      "INSERT INTO user_settings (user_id, theme) VALUES (?, ?)"
    ).bind(user.id, "light").run();

    return json({ message: "User created", userId: user.id });
  } catch {
    return json({ error: "Email already exists or DB error" }, 500);
  }
}

async function login(request: Request, env: Env): Promise<Response> {
  const { email, password } = await request.json() as { email: string; password: string };
  if (!email || !password) return json({ error: "Missing credentials" }, 400);

  const user = await env.DB.prepare(
    "SELECT id, password_hash FROM users WHERE email = ?"
  ).bind(email).first();

  if (!user) return json({ error: "User not found" }, 404);

  const inputHash = await hashPassword(password);
  if (inputHash !== user.password_hash) return json({ error: "Invalid password" }, 401);

  return json({ message: "Login successful", userId: user.id });
}

async function getSettings(request: Request, env: Env): Promise<Response> {
  const userId = request.headers.get("X-User-ID");
  if (!userId) return json({ error: "Missing user ID" }, 400);

  const settings = await env.DB.prepare(
    "SELECT theme FROM user_settings WHERE user_id = ?"
  ).bind(userId).first();

  return json({ theme: settings?.theme || "light" });
}

async function updateSettings(request: Request, env: Env): Promise<Response> {
  const userId = request.headers.get("X-User-ID");
  const { theme } = await request.json() as { theme: string };
  if (!userId || !theme) return json({ error: "Missing data" }, 400);

  await env.DB.prepare(
    "UPDATE user_settings SET theme = ? WHERE user_id = ?"
  ).bind(theme, userId).run();

  return json({ message: "Theme updated", theme });
}

function json(data: object, status = 200): Response {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "Content-Type": "application/json" }
  });
}
