import test from "node:test";
import assert from "node:assert/strict";
import { buildMetaEvent, isValidCheckoutUrl } from "../web/analytics.mjs";

test("accepts http(s) checkout URLs only", () => {
  assert.equal(isValidCheckoutUrl("https://pay.kiwify.com.br/example"), true);
  assert.equal(isValidCheckoutUrl("https://checkout.stripe.com/c/pay/example"), true);
  assert.equal(isValidCheckoutUrl("javascript:alert(1)"), false);
  assert.equal(isValidCheckoutUrl("nota-url"), false);
});

test("builds a stable scan event without sending the target URL to Meta", () => {
  const event = buildMetaEvent({
    eventName: "ExecutouScan",
    eventId: "scan_test_123",
    sourceUrl: "https://example.com",
  });
  assert.equal(event.event_name, "ExecutouScan");
  assert.equal(event.event_id, "scan_test_123");
  assert.equal(event.custom_data.target_domain, "example.com");
  assert.equal(event.custom_data.target_url, undefined);
});
