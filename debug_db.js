const sqlite3 = require('sqlite3');
const { open } = require('sqlite');
const path = require('path');

async function wipeDatabase() {
    try {
        const db = await open({ filename: path.join(__dirname, 'crm.db'), driver: sqlite3.Database });
        await db.run('DELETE FROM chat_history');
        await db.run('DELETE FROM lead_audit');
        await db.run('UPDATE customers SET assigned_user_id = NULL');
        await db.run('DELETE FROM customers');
        console.log('Database Wipe Successful!');
        await db.close();
    } catch (err) {
        console.error('Database Wipe Error:', err.message);
    }
}
wipeDatabase();
