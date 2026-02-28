const sqlite3 = require('sqlite3').verbose();
const db = new sqlite3.Database('crm.db');
db.all("SELECT id, name, items_json, selected_items_json FROM customers WHERE name = 'rohit' OR mature = 1 ORDER BY id DESC LIMIT 5", (err, rows) => {
    if (err) console.error(err);
    else console.log(JSON.stringify(rows, null, 2));
});
