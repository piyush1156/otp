const crypto = require("crypto");

exports.handler = async (event) => {
  try{
    const { otp, tempToken } = JSON.parse(event.body || "{}");
    if(!otp || !tempToken) return { statusCode: 400, body: JSON.stringify({ error:"Missing fields" }) };

    global.otps = global.otps || [];
    const rec = global.otps.find(x => x.tempToken === tempToken);
    if(!rec) return { statusCode: 401, body: JSON.stringify({ error:"Invalid temp session" }) };

    if(rec.attempts >= 3) return { statusCode: 429, body: JSON.stringify({ error:"Too many attempts" }) };
    rec.attempts++;

    if(Date.now() > rec.exp) return { statusCode: 410, body: JSON.stringify({ error:"OTP expired" }) };
    if(String(otp) !== rec.otp) return { statusCode: 401, body: JSON.stringify({ error:"Wrong OTP" }) };

    // success -> auth token
    const authToken = crypto.randomUUID();
    return { statusCode: 200, body: JSON.stringify({ authToken }) };
  }catch(e){
    return { statusCode: 500, body: JSON.stringify({ error:"Server error" }) };
  }
};
