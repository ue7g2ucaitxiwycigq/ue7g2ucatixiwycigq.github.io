export async function onRequestGet(context) {

  const ip =
    context.request.headers.get("CF-Connecting-IP") ||
    "Unknown";

  return new Response(
    JSON.stringify({
      ip: ip
    }),
    {
      headers: {
        "Content-Type": "application/json"
      }
    }
  );
}
