const crypto = require("crypto");

global.otps = global.otps || []; // { tempToken, email, otp, exp, attempts }

exports.handler = async (event) => {
  try{
    const { email, password } = JSON.parse(event.body || "{}");
    if(!email || !password) return { statusCode: 400, body: JSON.stringify({ error:"Missing fields" }) };

    global.users = global.users || [];
    const user = global.users.find(u => u.email === email);
    if(!user) return { statusCode: 404, body: JSON.stringify({ error:"User not found" }) };

    const check = crypto.pbkdf2Sync(password, user.salt, 100000, 32, "sha256").toString("hex");
    if(check !== user.hash) return { statusCode: 401, body: JSON.stringify({ error:"Wrong password" }) };

    const otp = String(Math.floor(100000 + Math.random()*900000));
    const tempToken = crypto.randomUUID();
    const exp = Date.now() + 5*60*1000;

    global.otps.push({ tempToken, email, otp, exp, attempts:0 });

    // Demo: email send optional. If you want real email, use sendOtp.js with SMTP.
    // For now, return otp in response ONLY for testing.
    return { statusCode: 200, body: JSON.stringify({ tempToken, debugOtp: otp }) };
  }catch(e){
    return { statusCode: 500, body: JSON.stringify({ error:"Server error" }) };
  }
};
