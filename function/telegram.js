export async function onRequestPost(context) {
  try {
    const body = await context.request.json();
    const ip = body.ip;
    if (!ip) {
      return new Response(
        JSON.stringify({
          error: "IP is missing"
        }),
        {
          status: 400,
          headers: {
            "Content-Type": "application/json"
          }
        }
      );
    }
    const botToken = context.env.TELEGRAM_BOT_TOKEN;
    const chatId = context.env.TELEGRAM_CHAT_ID;
    if (!botToken || !chatId) {
      return new Response(
        JSON.stringify({
          error: "Telegram secrets are not configured"
        }),
        {
          status: 500,
          headers: {
            "Content-Type": "application/json"
          }
        }
      );
    }
    const telegramURL =
      `https://api.telegram.org/bot${botToken}/sendMessage`;
    const message =
      "👀 New visitor\n\n" +
      "IP: " + ip;
    const response = await fetch(telegramURL, {
      method: "POST",
      headers: {
        "Content-Type": "application/json"
      },
      body: JSON.stringify({
        chat_id: chatId,
        text: message
      })
    });
    const data = await response.json();
    if (!response.ok) {
      return new Response(
        JSON.stringify({
          error: "Telegram API error",
          details: data
        }),
        {
          status: 500,
          headers: {
            "Content-Type": "application/json"
          }
        }
      );
    }
    return new Response(
      JSON.stringify({
        success: true
      }),
      {
        status: 200,
        headers: {
          "Content-Type": "application/json"
        }
      }
    );
  } catch (error) {
    console.error(error);
    return new Response(
      JSON.stringify({
        error: "Internal server error"
      }),
      {
        status: 500,
        headers: {
          "Content-Type": "application/json"
        }
      }
    );
  }
}
