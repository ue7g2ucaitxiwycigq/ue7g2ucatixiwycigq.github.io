const fetch = require('node-fetch');

exports.handler = async (event) => {
  // Only allow POST requests
  if (event.httpMethod !== 'POST') {
    return {
      statusCode: 405,
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        error: 'Method not allowed'
      })
    };
  }

  // Telegram bot token from Netlify Environment Variables
  const BOT_TOKEN = process.env.TELEGRAM_BOT_TOKEN;

  if (!BOT_TOKEN) {
    return {
      statusCode: 500,
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        error: 'Telegram bot token is not configured'
      })
    };
  }

  try {
    const body = JSON.parse(event.body || '{}');

    const { chat_id, text } = body;

    // Validate input
    if (!chat_id || !text) {
      return {
        statusCode: 400,
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          error: 'Missing chat_id or text'
        })
      };
    }

    // Telegram API URL
    const telegramUrl =
      `https://api.telegram.org/bot${BOT_TOKEN}/sendMessage`;

    // Send message to Telegram
    const response = await fetch(telegramUrl, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        chat_id: chat_id,
        text: text,
        disable_web_page_preview: true
      })
    });

    const data = await response.json();

    // Telegram returned an error
    if (!response.ok || !data.ok) {
      console.error('Telegram API error:', data);

      return {
        statusCode: 502,
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          error: 'Telegram API error'
        })
      };
    }

    // Success
    return {
      statusCode: 200,
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        success: true
      })
    };

  } catch (error) {
    console.error('Function error:', error);

    return {
      statusCode: 500,
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        error: 'Internal server error'
      })
    };
  }
};
