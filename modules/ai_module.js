/**
 * AI Module - Handles OpenAI integration and Chat History
 * (Django-style modular app)
 */

const { OpenAI } = require('openai');

let db;

/**
 * Initialize the AI module with the database instance
 * @param {object} databaseInstance - The SQLite database instance
 */
function init(databaseInstance) {
    db = databaseInstance;
}

/**
 * Helper to get settings (mimics the one in server.js)
 */
async function getSetting(key, defaultValue) {
    const row = await db.get('SELECT value FROM settings WHERE key = ?', [key]);
    if (!row) return defaultValue;
    return row.value;
}

/**
 * Save message to chat history
 */
async function saveChatHistory(customerId, role, content) {
    await db.run(
        'INSERT INTO chat_history (customer_id, role, content, created_at) VALUES (?, ?, ?, ?)',
        [customerId, role, content, new Date().toISOString()]
    );
}

/**
 * Retrieve recent chat history
 */
async function getChatHistory(customerId, limit = 10) {
    return db.all(
        'SELECT role, content FROM chat_history WHERE customer_id = ? ORDER BY id DESC LIMIT ?',
        [customerId, limit]
    );
}

/**
 * Generate AI response using OpenAI
 */
async function getAIResponse(customerId, userMessage) {
    const apiKey = await getSetting('openai_api_key', '');
    const aiEnabled = (await getSetting('ai_enabled', 'false')) === 'true';
    const businessProfile = await getSetting('business_profile', 'A professional business service.');

    if (!apiKey || !aiEnabled) return null;

    try {
        const openai = new OpenAI({ apiKey });
        const history = await getChatHistory(customerId);
        const catalog = await db.all('SELECT name, price FROM catalog_items WHERE active = 1');

        const catalogText = catalog.map(i => `- ${i.name}: ₹${i.price}`).join('\n');

        // Reverse to get chronological order for the model
        const messages = history.reverse().map(h => ({
            role: h.role,
            content: h.content
        }));

        const systemPrompt = `### IDENTITY & ROLE
You are a human-like Sales Assistant for the business described below. 
BUSINESS PROFILE:
"""
${businessProfile}
"""

### DYNAMIC CATALOG (Products & Prices):
${catalogText}

### CORE CONVERSATION RULES:
1. **Language**: ALWAYS use Hinglish (Hindi + English mix).
2. **Style**: Short, 1-3 line messages. No long paragraphs. Use emojis occasionally 🙂.
3. **Flow**: Greet -> Understand Problem -> Recommend Catalog Item -> Offer Solution -> Get Address -> Confirm Order.

### AUTOMATION CRITICAL (INTERNAL PROCESS):
- **Tool Trigger**: You have a special capacity to process orders.
- **When to call 'confirm_order'**: As soon as the customer provides their Address AND says "Yes/Confirm" to the order.
- **Calculation**: Use the exact names and prices from the Catalog above.
- **Confirmation**: After calling the tool, tell the customer their order is confirmed and will arrive in 3-5 days.

### DO NOT:
- Do not mention 'tools' or 'functions' to the customer. Just use them.
- Do not confirm the order in text WITHOUT calling the 'confirm_order' tool.`;

        const tools = [
            {
                type: "function",
                function: {
                    name: "confirm_order",
                    description: "Processes the order and marks lead as mature.",
                    parameters: {
                        type: "object",
                        properties: {
                            items: {
                                type: "array",
                                items: {
                                    type: "object",
                                    properties: {
                                        name: { type: "string" },
                                        qty: { type: "number" },
                                        price: { type: "number" }
                                    }
                                }
                            },
                            address: { type: "string" },
                            total_price: { type: "number" },
                            customer_name: { type: "string" }
                        },
                        required: ["items", "address", "total_price"]
                    }
                }
            }
        ];

        const response = await openai.chat.completions.create({
            model: "gpt-3.5-turbo",
            messages: [
                { role: "system", content: systemPrompt },
                ...messages
            ],
            tools: tools,
            tool_choice: "auto",
            max_tokens: 500,
        });

        const responseMessage = response.choices[0].message;

        // Handle Tool Calls
        if (responseMessage.tool_calls) {
            for (const toolCall of responseMessage.tool_calls) {
                if (toolCall.function.name === 'confirm_order') {
                    const args = JSON.parse(toolCall.function.arguments);
                    console.log('[AI Module] Confirming order for customer:', customerId, args);

                    // Update Customer in DB
                    await db.run(
                        `UPDATE customers 
                         SET mature = 1, 
                             address = ?, 
                             items_json = ?, 
                             name = COALESCE(?, name)
                         WHERE id = ?`,
                        [
                            args.address,
                            JSON.stringify(args.items),
                            args.customer_name || null,
                            customerId
                        ]
                    );

                    // Optional: Return a confirmation message as the AI
                    return `Shukriya! Aapka order confirm ho gaya hai. Humne aapka address "${args.address}" note kar liya hai. Total amount ₹${args.total_price} hai.`;
                }
            }
        }

        return responseMessage.content;
    } catch (err) {
        console.error('[AI Module] Error:', err.message);
        return null;
    }
}

module.exports = {
    init,
    saveChatHistory,
    getChatHistory,
    getAIResponse
};
