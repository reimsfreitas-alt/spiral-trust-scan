import crypto from "node:crypto";

export function isValidCheckoutUrl(value) {
  try {
    const url = new URL(String(value).trim());
    return url.protocol === "https:" || url.protocol === "http:";
  } catch {
    return false;
  }
}

export function buildMetaEvent({ eventName, eventId, sourceUrl }) {
  const target = new URL(sourceUrl);
  return {
    event_name: eventName,
    event_id: eventId,
    event_time: Math.floor(Date.now() / 1000),
    action_source: "website",
    custom_data: {
      target_domain: target.hostname,
    },
  };
}

export function sha256(value) {
  return crypto.createHash("sha256").update(value).digest("hex");
}
