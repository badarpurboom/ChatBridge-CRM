const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcryptjs');
const db = new sqlite3.Database('./crm.db');

async function runQASimulation() {
    console.log("Starting QA Simulation...");

    // 1. Create 3 Agents
    const agents = [];
    const hash = bcrypt.hashSync('password123', 10);
    const ts = new Date().toISOString();

    for (let i = 1; i <= 3; i++) {
        const email = `qa_agent${i}@test.com`;
        const name = `QA Agent ${i}`;

        await new Promise((resolve) => {
            db.run('INSERT OR IGNORE INTO users (email, name, password_hash, role, active, created_at) VALUES (?, ?, ?, ?, 1, ?)',
                [email, name, hash, 'agent', ts],
                function (err) {
                    if (err) console.error(err);

                    db.get('SELECT id FROM users WHERE email = ?', [email], (err, row) => {
                        if (row) agents.push(row.id);
                        resolve();
                    });
                });
        });
    }

    console.log(`Created/Verified ${agents.length} agents. IDs: ${agents.join(', ')}`);

    // 2. Create 300 Leads & Assign them
    let insertedLeads = 0;
    let matureLeads = 0;

    const stmt = db.prepare(`INSERT INTO customers 
        (phone, name, address, note, items_json, selected_items_json, selection_type, time, lastMessage, lastMessageTime, messageCount, isNew, contacted, source, assigned_user_id, assigned_at, mature, mature_at) 
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`);

    for (let i = 1; i <= 300; i++) {
        // Assign evenly or randomly? Let's assign evenly among the 3 agents
        const assignedAgentId = agents[i % 3];

        // Let's mature exactly 30% of them
        const isMature = (i % 10 < 3); // 3 out of 10 will be mature

        stmt.run(
            '9199990' + i.toString().padStart(4, '0'),
            'QA Lead ' + i,
            'QA Address ' + i,
            'QA Note',
            '[]',
            '[]',
            'product',
            new Date().toISOString(),
            'QA Hello',
            new Date().toISOString(),
            1,
            0, // Not new since assigned
            0,
            'qa_test',
            assignedAgentId,
            new Date().toISOString(),
            isMature ? 1 : 0,
            isMature ? new Date().toISOString() : null
        );

        insertedLeads++;
        if (isMature) matureLeads++;
    }

    stmt.finalize();
    console.log(`Inserted ${insertedLeads} leads. ${matureLeads} marked as mature (ordered).`);

    // 3. Print the DB state directly
    setTimeout(() => {
        console.log("\n--- DB STATE AFTER SIMULATION ---");
        db.all('SELECT assigned_user_id, COUNT(*) as total_leads, SUM(mature) as mature_leads FROM customers WHERE source = "qa_test" GROUP BY assigned_user_id', [], (err, rows) => {
            if (err) throw err;
            rows.forEach(r => {
                console.log(`Agent ID ${r.assigned_user_id}: ${r.total_leads} leads assigned, ${r.mature_leads || 0} mature (ordered).`);
            });
            console.log(`---------------------------------`);
            db.close();
        });
    }, 1000);
}

runQASimulation();
