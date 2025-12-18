'use strict';

module.exports = (app, db) => {

    const xss = require("xss");

    /**
     * GET /
     * Frontend entry page
     * FIXED: XSS + SSTI
     */
    app.get('/', (req, res) => {
        console.log(req.session);

        const message = xss(req.query.message || "Please log in to continue");

        res.render('user.html', {
            message: message
        });
    });

    /**
     * GET /register
     * Frontend register page
     * FIXED: XSS + SSTI
     */
    app.get('/register', (req, res) => {

        const message = xss(req.query.message || "Please register to continue");

        res.render('user-register.html', {
            message: message
        });
    });

    /**
     * GET /registerform
     * User registration
     * FIXED: Weak password hashing (MD5 → bcrypt)
     */
    app.get('/registerform', async (req, res) => {

        const userEmail = req.query.email;
        const userName = req.query.name;
        const userPassword = req.query.password;
        const userAddress = req.query.address;
        const userRole = 'user';

        const emailExpression = /^([a-zA-Z0-9_\.\-])+\@(([a-zA-Z0-9\-])+\.)+([a-zA-Z0-9]{2,4})+$/;

        if (!emailExpression.test(userEmail)) {
            return res.redirect("/register?message=Invalid email address");
        }

        try {
            const bcrypt = require("bcrypt");
            const hashedPassword = await bcrypt.hash(userPassword, 12);

            const newUser = await db.user.create({
                name: userName,
                email: userEmail,
                role: userRole,
                address: userAddress,
                password: hashedPassword
            });

            res.redirect('/profile?id=' + newUser.id);

        } catch (error) {
            console.error(error);
            res.redirect('/?message=Error registering user');
        }
    });

    /**
     * GET /login
     * Frontend login
     * FIXED: User Enumeration + Weak Password
     */
    app.get('/login', async (req, res) => {

        const userEmail = req.query.email;
        const userPassword = req.query.password;

        try {
            const users = await db.user.findAll({
                where: { email: userEmail }
            });

            if (users.length === 0) {
                return res.redirect('/?message=Invalid email or password');
            }

            const bcrypt = require("bcrypt");
            const isValid = await bcrypt.compare(userPassword, users[0].password);

            if (!isValid) {
                return res.redirect('/?message=Invalid email or password');
            }

            req.session.logged = true;
            req.session.userId = users[0].id;

            res.redirect('/profile?id=' + users[0].id);

        } catch (error) {
            console.error(error);
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
                user: user,
                beers: beers
            });

        } catch (error) {
            console.error(error);
            res.redirect('/?message=Profile error');
        }
    });

};

