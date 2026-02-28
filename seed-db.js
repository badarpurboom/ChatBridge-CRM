const sqlite3 = require('sqlite3').verbose();
const db = new sqlite3.Database('./crm.db');

let stmt = db.prepare(`INSERT INTO customers 
    (phone, name, address, note, items_json, selected_items_json, selection_type, time, lastMessage, lastMessageTime, messageCount, isNew, contacted, source) 
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`);

for (let i = 0; i < 105; i++) {
    stmt.run(
        '9199990' + i.toString().padStart(3, '0'),
        'Test Customer ' + i,
        'Address ' + i,
        'Dummy note ' + i,
        '[]',
        '[]',
        'product',
        new Date().toISOString(),
        'Hi',
        new Date().toISOString(),
        1,
        1,
        0,
        'script'
    );
}

stmt.finalize();
console.log("105 dummy leads seeded.");
