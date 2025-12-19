'use strict';

const jwt = require("jsonwebtoken");
const bcrypt = require('bcryptjs');

module.exports = (app, db) => {

    /* ===========================
       ADMIN – LIST USERS
    ============================ */
    app.get('/v1/admin/users/', (req, res) => {
        if (!req.headers.authorization) {
            return res.status(401).json({ error: "Missing token" });
        }

        try {
            const decoded = jwt.verify(
                req.headers.authorization.split(' ')[1],
                "SuperSecret",
                { algorithms: ['HS256'] }
            );

            if (decoded.role !== 'admin') {
                return res.status(403).json({ error: "Admin access required" });
            }

            db.user.findAll({ include: "beers" })
                .then(users => res.json(users))
                .catch(e => res.status(500).json({ error: e.message }));

        } catch (err) {
            return res.status(401).json({ error: "Invalid or expired token" });
        }
    });

    /* ===========================
       LOGIN – JWT TOKEN
       FIXED V7 (NO ENUMERATION)
    ============================ */
    app.post('/v1/user/token', async (req, res) => {
        try {
            const { email, password } = req.body;

            if (!email || !password) {
                return res.status(401).json({
                    error: "Invalid email or password"
                });
            }

            const users = await db.user.findAll({ where: { email } });
            const user = users[0];

            if (!user || !(await bcrypt.compare(password, user.password))) {
                return res.status(401).json({
                    error: "Invalid email or password"
                });
            }

            const token = jwt.sign(
                { id: user.id, role: user.role },
                "SuperSecret",
                {
                    algorithm: 'HS256',
                    expiresIn: '1h',
                    issuer: 'beer-api',
                    audience: 'beer-api'
                }
            );

            res.status(200).json({
                token,
                user: {
                    id: user.id,
                    email: user.email,
                    role: user.role
                }
            });

        } catch (err) {
            res.status(500).json({ error: "Authentication failed" });
        }
    });

    /* ===========================
       LOGIN – SESSION
       FIXED V7 (NO ENUMERATION)
    ============================ */
    app.post('/v1/user/login', async (req, res) => {
        try {
            const { email, password } = req.body;

            if (!email || !password) {
                return res.status(401).json({
                    error: "Invalid email or password"
                });
            }

            const users = await db.user.findAll({ where: { email } });
            const user = users[0];

            if (!user || !(await bcrypt.compare(password, user.password))) {
                return res.status(401).json({
                    error: "Invalid email or password"
                });
            }

            res.status(200).json({
                id: user.id,
                email: user.email,
                role: user.role
            });

        } catch (err) {
            res.status(500).json({ error: "Login failed" });
        }
    });

};
