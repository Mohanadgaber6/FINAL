'use strict';

const xss = require("xss");
const bcrypt = require("bcrypt");

module.exports = (app, db) => {

    /**
     * GET /
     * Frontend entry page
     * FIXED: XSS
     */
    app.get('/', (req, res) => {
        const message = xss(req.query.message || "Please log in to continue");
        res.render('user.html', { message });
    });

    /**
     * GET /register
     * Frontend register page
     * FIXED: XSS
     */
    app.get('/register', (req, res) => {
        const message = xss(req.query.message || "Please register to continue");
        res.render('user-register.html', { message });
    });

    /**
     * GET /registerform
     * User registration
     * FIXED: Weak password hashing (MD5 → bcrypt)
     */
    app.get('/registerform', async (req, res) => {
        try {
            const { email, name, password, address } = req.query;

            // Basic validation
            if (!email || !name || !password) {
                return res.redirect('/register?message=Missing required fields');
            }

            // Email validation
            const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
            if (!emailRegex.test(email)) {
                return res.redirect('/register?message=Invalid email address');
            }

            // Hash password
            const hashedPassword = await bcrypt.hash(password, 12);

            // Create user
            const newUser = await db.user.create({
                name,
                email,
                role: 'user',
                address,
                password: hashedPassword
            });

            // Regenerate session (important)
            req.session.regenerate(() => {
                req.session.logged = true;
                req.session.userId = newUser.id;
                res.redirect('/profile?id=' + newUser.id);
            });

        } catch (error) {
            console.error("REGISTER ERROR:", error);
            res.redirect('/?message=Error registering user');
        }
    });

    /**
     * GET /login
     * Frontend login
     * FIXED: User Enumeration + Weak Password
     */
    app.get('/login', async (req, res) => {
        try {
            const { email, password } = req.query;

            if (!email || !password) {
                return res.redirect('/?message=Invalid email or password');
            }

            const users = await db.user.findAll({
                where: { email }
            });

            if (users.length === 0) {
                return res.redirect('/?message=Invalid email or password');
            }

            const isValid = await bcrypt.compare(password, users[0].password);

            if (!isValid) {
                return res.redirect('/?message=Invalid email or password');
            }

            req.session.regenerate(() => {
                req.session.logged = true;
                req.session.userId = users[0].id;
                res.redirect('/profile?id=' + users[0].id);
            });

        } catch (error) {
            console.error("LOGIN ERROR:", error);
            res.redirect('/?message=Login failed');
        }
    });

    /**
     * GET /profile
     * FIXED: IDOR
     */
    app.get('/profile', async (req, res) => {

        if (!req.session.logged) {
            return res.redirect('/?message=Please login first');
        }

        if (Number(req.query.id) !== req.session.userId) {
            return res.status(403).send("Forbidden");
        }

        try {
            const user = await db.user.findOne({
                where: { id: req.session.userId },
                include: 'beers'
            });

            if (!user) {
                return res.redirect('/?message=User not found');
            }

            const beers = await db.beer.findAll();

            res.render('profile.html', {
                user,
                beers
            });

        } catch (error) {
            console.error("PROFILE ERROR:", error);
            res.redirect('/?message=Profile error');
        }
    });

};
