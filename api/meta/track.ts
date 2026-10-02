import type { VercelRequest, VercelResponse } from "@vercel/node";
import crypto from "node:crypto";

function hash(value) {
  return crypto.createHash("sha256").update(value.trim().toLowerCase()).digest("hex");
}

export default async function handler(req: VercelRequest, res: VercelResponse) {
  if (req.method !== "POST") return res.status(405).json({ error: "METHOD_NOT_ALLOWED" });

  const pixelId = process.env.META_PIXEL_ID;
  const accessToken = process.env.META_CAPI_ACCESS_TOKEN;
  if (!pixelId || !accessToken) {
    return res.status(200).json({ ok: false, enabled: false, reason: "META_CAPI_NOT_CONFIGURED" });
  }

  const { eventName, eventId, targetDomain } = req.body || {};
  if (typeof eventName !== "string" || typeof eventId !== "string") {
    return res.status(400).json({ error: "INVALID_EVENT" });
  }

  const userAgent = req.headers["user-agent"] || "";
  const clientIp = (req.headers["x-forwarded-for"] || "").toString().split(",")[0].trim();

  const payload = {
    data: [{
      event_name: eventName,
      event_time: Math.floor(Date.now() / 1000),
      event_id: eventId,
      action_source: "website",
      user_data: {
        ...(clientIp ? { client_ip_address: clientIp } : {}),
        ...(userAgent ? { client_user_agent: userAgent } : {}),
      },
      custom_data: {
        ...(targetDomain ? { target_domain: String(targetDomain).slice(0, 253) } : {}),
      },
    }],
  };

  const response = await fetch(
    `https://graph.facebook.com/v20.0/${encodeURIComponent(pixelId)}/events?access_token=${encodeURIComponent(accessToken)}`,
    {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    }
  );

  if (!response.ok) {
    return res.status(200).json({ ok: false, enabled: true, providerStatus: response.status });
  }

  return res.status(200).json({ ok: true, enabled: true });
}
