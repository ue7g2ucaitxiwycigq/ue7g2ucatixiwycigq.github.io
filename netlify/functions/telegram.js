// netlify/functions/telegram.js
const fetch = require('node-fetch');

exports.handler = async (event) => {
  // 1. التحقق من الطريقة
  if (event.httpMethod !== 'POST') {
    return {
      statusCode: 405,
      body: JSON.stringify({ error: 'Method not allowed' })
    };
  }

  // 2. جلب التوكن من متغيرات البيئة (آمن تماماً)
  const BOT_TOKEN = process.env.TELEGRAM_BOT_TOKEN;
  
  // 3. التحقق من وجود التوكن
  if (!BOT_TOKEN) {
    console.error('❌ TELEGRAM_BOT_TOKEN not found in environment variables');
    return {
      statusCode: 500,
      body: JSON.stringify({ 
        error: 'Bot token not configured. Please set TELEGRAM_BOT_TOKEN in Netlify environment variables.' 
      })
    };
  }

  try {
    // 4. قراءة البيانات من الطلب
    const { chat_id, text } = JSON.parse(event.body);

    if (!chat_id || !text) {
      return {
        statusCode: 400,
        body: JSON.stringify({ error: 'Missing chat_id or text' })
      };
    }

    // 5. إرسال الرسالة إلى تلغرام
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

    // 6. التحقق من نجاح الإرسال
    if (!data.ok) {
      console.error('❌ Telegram API error:', data);
      return {
        statusCode: 500,
        body: JSON.stringify({ 
          error: 'Failed to send message to Telegram', 
          details: data 
        })
      };
    }

    // 7. نجاح العملية
    console.log('✅ Message sent successfully to chat:', chat_id);
    return {
      statusCode: 200,
      body: JSON.stringify({ 
        success: true, 
        result: data 
      })
    };

  } catch (error) {
    console.error('❌ Error in function:', error);
    return {
      statusCode: 500,
      body: JSON.stringify({ 
        error: 'Internal server error', 
        details: error.message 
      })
    };
  }
};
