// netlify/functions/telegram.js
const fetch = require('node-fetch');

exports.handler = async (event) => {
  if (event.httpMethod !== 'POST') {
    return {
      statusCode: 405,
      body: JSON.stringify({ error: 'Method not allowed' })
    };
  }

  const BOT_TOKEN = process.env.TELEGRAM_BOT_TOKEN;
  
  if (!BOT_TOKEN) {
    return {
      statusCode: 500,
      body: JSON.stringify({ error: 'Bot token not configured' })
    };
  }

  try {
    const { chat_id, text } = JSON.parse(event.body);

    if (!chat_id || !text) {
      return {
        statusCode: 400,
        body: JSON.stringify({ error: 'Missing chat_id or text' })
      };
    }

    const telegramUrl = `https://api.telegram.org/bot${BOT_TOKEN}/sendMessage`;
    
    const response = await fetch(telegramUrl, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        chat_id: chat_id,
        text: text,
        parse_mode: 'Markdown',
        disable_web_page_preview: true
      })
    });

    const data = await response.json();

    if (!data.ok) {
      return {
        statusCode: 500,
        body: JSON.stringify({ error: 'Telegram API error', details: data })
      };
    }

    return {
      statusCode: 200,
      body: JSON.stringify({ success: true })
    };

  } catch (error) {
    return {
      statusCode: 500,
      body: JSON.stringify({ error: 'Internal server error', details: error.message })
    };
  }
};
