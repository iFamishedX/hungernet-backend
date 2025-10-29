async function login(request: Request, env: Env): Promise<Response> {
  let email: string, password: string;

  // Safely parse JSON body
  try {
    const body = await request.json();
    email = body.email;
    password = body.password;
  } catch {
    return json({ error: "Invalid JSON body" }, 400);
  }

  // Validate input
  if (!email || !password) {
    return json({ error: "Missing credentials" }, 400);
  }

  // Look up user
  const user = await env.DB.prepare(
    "SELECT id, password_hash FROM users WHERE email = ?"
  ).bind(email).first();

  if (!user) {
    return json({ error: "User not found" }, 404);
  }

  // Compare password hashes
  const inputHash = await hashPassword(password);
  if (inputHash !== user.password_hash) {
    return json({ error: "Invalid password" }, 401);
  }

  // Success
  return json({ message: "Login successful", userId: user.id });
}
