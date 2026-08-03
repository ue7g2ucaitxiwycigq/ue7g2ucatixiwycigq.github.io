// ============================================================
// Netlify Function: Telegram notification proxy
// المسار الصح لهذا الملف داخل مشروعك هو بالضبط:
//   netlify/functions/telegram.js
// ============================================================
//
// خطوات التركيب:
// 1. سوّي مجلدين متداخلين بمشروعك بهذا الشكل بالضبط:
//      netlify/functions/
// 2. حط هذا الملف جوا هيك: netlify/functions/telegram.js
// 3. بلوحة تحكم Netlify: Site settings -> Environment variables -> Add a variable
//      Key:   TELEGRAM_BOT_TOKEN
//      Value: التوكن الحقيقي تبعك (يلي أخدته من BotFather)
// 4. اعمل Deploy (أو Redeploy إذا الموقع منشور أصلاً) -- هذا ضروري
//    عشان المتغيّر البيئي الجديد يتفعّل.
// 5. صفحتك أصلاً عم تنادي: /.netlify/functions/telegram
//    فما رح تحتاج تغيّر شي إضافي بالـ HTML.

exports.handler = async (event) => {
  // نسمح فقط بطلبات POST
  if (event.httpMethod !== "POST") {
    return {
      statusCode: 405,
      body: JSON.stringify({ error: "Method Not Allowed" })
    };
  }

  // تأكد إن التوكن موجود قبل ما نكمل
  const BOT_TOKEN = process.env.TELEGRAM_BOT_TOKEN;
  if (!BOT_TOKEN) {
    return {
      statusCode: 500,
      body: JSON.stringify({
        error: "TELEGRAM_BOT_TOKEN is not set in environment variables"
      })
    };
  }

  // تأكد إن البيانات المرسلة صحيحة (JSON سليم)
  let body;
  try {
    body = JSON.parse(event.body);
  } catch (err) {
    return {
      statusCode: 400,
      body: JSON.stringify({ error: "Invalid JSON body" })
    };
  }

  const { chat_id, text } = body;
  if (!chat_id || !text) {
    return {
      statusCode: 400,
      body: JSON.stringify({ error: "chat_id and text are required" })
    };
  }

  try {
    const response = await fetch(
      `https://api.telegram.org/bot${BOT_TOKEN}/sendMessage`,
      {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ chat_id, text })
      }
    );

    const data = await response.json();

    if (!data.ok) {
      // Telegram نفسه رجع خطأ (مثلاً توكن غلط أو chat_id غلط)
      return {
        statusCode: 502,
        body: JSON.stringify({ error: "Telegram API error", details: data })
      };
    }

    return {
      statusCode: 200,
      body: JSON.stringify({ success: true })
    };
  } catch (err) {
    return {
      statusCode: 500,
      body: JSON.stringify({ error: "Failed to reach Telegram", details: String(err) })
    };
  }
};
