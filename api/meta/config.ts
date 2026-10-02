import type { VercelRequest, VercelResponse } from "@vercel/node";

export default function handler(_req: VercelRequest, res: VercelResponse) {
  res.setHeader("Cache-Control", "no-store");
  res.status(200).json({
    pixelId: process.env.META_PIXEL_ID || null,
    enabled: Boolean(process.env.META_PIXEL_ID),
  });
}
