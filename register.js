const crypto = require("crypto");

// in-memory demo store
global.users = global.users || [];

exports.handler = async (event) => {
  try{
    const { name, email, password } = JSON.parse(event.body || "{}");
    if(!name || !email || !password) return { statusCode: 400, body: "Missing fields" };

    const exists = global.users.find(u => u.email === email);
    if(exists) return { statusCode: 409, body: "Email already exists" };

    const salt = crypto.randomBytes(16).toString("hex");
    const hash = crypto.pbkdf2Sync(password, salt, 100000, 32, "sha256").toString("hex");

    global.users.push({ id: crypto.randomUUID(), name, email, salt, hash });
    return { statusCode: 200, body: "OK" };
  }catch(e){
    return { statusCode: 500, body: "Server error" };
  }
};
