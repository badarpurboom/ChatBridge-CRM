const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcryptjs');
const db = new sqlite3.Database('./crm.db');

async function runSimulation() {
    console.log("Starting Simulation...");

    // 1. Create 10 Agents
    const agents = [];
    const hash = bcrypt.hashSync('password123', 10);

    for (let i = 1; i <= 10; i++) {
        const email = `agent${i}@example.com`;
        const name = `Test Agent ${i}`;

        await new Promise((resolve) => {
            db.run('INSERT OR IGNORE INTO users (email, name, password_hash, role, active, created_at) VALUES (?, ?, ?, ?, 1, ?)',
                [email, name, hash, 'agent', new Date().toISOString()],
                function (err) {
                    if (err) console.error(err);

                    db.get('SELECT id FROM users WHERE email = ?', [email], (err, row) => {
                        if (row) agents.push(row.id);
                        resolve();
                    });
                });
        });
    }

    console.log(`Created/Verified ${agents.length} agents.`);

    // 2. Create 1000 Leads & Assign them randomly
    let insertedLeads = 0;
    let matureLeads = 0;

    const stmt = db.prepare(`INSERT INTO customers 
        (phone, name, address, note, items_json, selected_items_json, selection_type, time, lastMessage, lastMessageTime, messageCount, isNew, contacted, source, assigned_user_id, assigned_at, mature, mature_at) 
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`);

    for (let i = 1; i <= 1000; i++) {
        // Randomly assign to an agent (or leave unassigned ~10% of the time)
        const isAssigned = Math.random() > 0.1;
        const assignedAgentId = isAssigned ? agents[Math.floor(Math.random() * agents.length)] : null;

        // If assigned, randomly mark as mature (order placed) ~30% of the time
        const isMature = isAssigned && Math.random() > 0.7;

        stmt.run(
            '9188880' + i.toString().padStart(4, '0'),
            'Sim Lead ' + i,
            'Sim Address ' + i,
            'Simulated note',
            '[]',
            '[]',
            'product',
            new Date().toISOString(),
            'Hello from sim',
            new Date().toISOString(),
            1,
            isAssigned ? 0 : 1, // Not new if assigned
            0,
            'simulation',
            assignedAgentId,
            isAssigned ? new Date().toISOString() : null,
            isMature ? 1 : 0,
            isMature ? new Date().toISOString() : null
        );

        insertedLeads++;
        if (isMature) matureLeads++;
    }

    stmt.finalize();
    console.log(`Inserted ${insertedLeads} leads. ${matureLeads} marked as mature (ordered).`);

    // 3. Print the resulting Admin stats directly from DB to verify what the Admin panel should show
    setTimeout(() => {
        console.log("\n--- SIMULATION RESULTS (Expected Admin Panel Stats) ---");
        db.all('SELECT assigned_user_id, COUNT(*) as lead_count, SUM(mature) as order_count FROM customers WHERE assigned_user_id IS NOT NULL GROUP BY assigned_user_id', [], (err, rows) => {
            if (err) throw err;
            let totalOrders = 0;
            let totalAssigned = 0;
            rows.forEach(r => {
                console.log(`Agent ID ${r.assigned_user_id}: ${r.lead_count} total leads, ${r.order_count || 0} orders.`);
                totalOrders += (r.order_count || 0);
                totalAssigned += r.lead_count;
            });
            console.log(`-----------------------------------------------------`);
            console.log(`TOTAL AGENT LEADS: ${totalAssigned}`);
            console.log(`TOTAL MATURE (ORDERS): ${totalOrders}`);

            db.get('SELECT COUNT(*) as unassigned FROM customers WHERE assigned_user_id IS NULL', [], (err, row) => {
                console.log(`TOTAL UNASSIGNED NEW LEADS: ${row.unassigned}`);
                console.log(`-----------------------------------------------------`);
                db.close();
            });
        });
    }, 1000);
}

runSimulation();
