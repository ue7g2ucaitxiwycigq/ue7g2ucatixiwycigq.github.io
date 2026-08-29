// netlify/functions/telegram.js
const fetch = require('node-fetch');

// احتفظ بالتوكن في متغيرات البيئة
const BOT_TOKEN = process.env.TELEGRAM_BOT_TOKEN;

exports.handler = async (event) => {
  // التحقق من الطريقة
  if (event.httpMethod !== 'POST') {
    return {
      statusCode: 405,
      body: JSON.stringify({ error: 'Method not allowed' })
    };
  }

  // التحقق من وجود التوكن
  if (!BOT_TOKEN) {
    console.error('TELEGRAM_BOT_TOKEN not set in environment variables');
    return {
      statusCode: 500,
      body: JSON.stringify({ error: 'Bot token not configured' })
    };
  }

  try {
    // قراءة البيانات
    const { chat_id, text } = JSON.parse(event.body);

    if (!chat_id || !text) {
      return {
        statusCode: 400,
        body: JSON.stringify({ error: 'Missing chat_id or text' })
      };
    }

    // إرسال الرسالة إلى تلغرام
    const telegramUrl = `https://api.telegram.org/bot${BOT_TOKEN}/sendMessage`;
    
    const response = await fetch(telegramUrl, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        chat_id: chat_id,
        text: text,
        parse_mode: 'Markdown', // لدعم التنسيق
        disable_web_page_preview: true
      })
    });

    const data = await response.json();

    if (!data.ok) {
      console.error('Telegram API error:', data);
      return {
        statusCode: 500,
        body: JSON.stringify({ error: 'Failed to send message to Telegram', details: data })
      };
    }

    return {
      statusCode: 200,
      body: JSON.stringify({ success: true, result: data })
    };

  } catch (error) {
    console.error('Error:', error);
    return {
      statusCode: 500,
      body: JSON.stringify({ error: 'Internal server error', details: error.message })
    };
  }
};
