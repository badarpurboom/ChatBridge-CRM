const axios = require('axios');

async function run() {
    try {
        const loginRes = await axios.post('http://localhost:3000/api/auth/login', {
            email: 'admin@example.com',
            password: 'admin123'
        });

        const cookie = loginRes.headers['set-cookie'] ? loginRes.headers['set-cookie'][0] : null;

        const res = await axios.get('http://localhost:3000/api/customers/paginated?page=1&limit=5', {
            headers: { 'Cookie': cookie }
        });

        console.log("Total Count:", res.data.pagination.total);
        console.log("Returned Leads:", res.data.data.length);
        console.log("First Lead:", res.data.data[0]?.name);
    } catch (e) {
        console.error("Error:", e.response ? e.response.data : e.message);
    }
}

run();
