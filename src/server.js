'use strict';

const express = require('express');
const bodyParser = require('body-parser');
const cookieParser = require('cookie-parser');
const session = require('express-session');

const config = require('./config');
const router = require('./router');
const db = require('./orm');

const expressJSDocSwagger = require('express-jsdoc-swagger');
const expressNunjucks = require('express-nunjucks');
const formidableMiddleware = require('express-formidable');
const sjs = require('sequelize-json-schema');

const app = express();
const PORT = config.PORT;

/* ===============================
   Body parsing
================================ */
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

/* ===============================
   Session configuration
   FIXED: V5 – Excessive Session Lifetime
================================ */
app.use(cookieParser());

app.use(session({
    name: 'sessionID',
    secret: process.env.SESSION_SECRET || 'dev_secret',
    resave: false,
    saveUninitialized: false,
    cookie: {
        httpOnly: true,
        secure: false, // must be false for localhost (HTTP)
        sameSite: 'strict',
        maxAge: 1000 * 60 * 30 // 30 minutes
    }
}));

/* ===============================
   Routes
================================ */
router(app, db);

/* ===============================
   Database
================================ */
db.sequelize.sync({ alter: true }).then(() => {
    app.listen(PORT, () => {
        console.log('Express listening on port:', PORT);
    });
});

/* ===============================
   Swagger Docs
================================ */
const docOptions = {
    info: {
        version: '1.0.0',
        title: 'Damn Vulnerable App',
        license: { name: 'MIT' }
    },
    security: {
        BearerAuth: {
            type: 'http',
            scheme: 'bearer'
        }
    },
    baseDir: __dirname,
    filesPattern: './../**/*.js',
    swaggerUIPath: '/api-docs',
    exposeSwaggerUI: true,
    exposeApiDocs: true,
    apiDocsPath: '/v1/api-docs'
};

expressJSDocSwagger(app)(docOptions);

/* ===============================
   Templates (Nunjucks)
================================ */
app.set('views', __dirname + '/templates');

expressNunjucks(app, {
    watch: true,
    noCache: true
});

/* ===============================
   Static files
================================ */
app.use(express.static('src/public'));

/* ===============================
   Form handling
================================ */
app.use(formidableMiddleware());

/* ===============================
   Generate Sequelize Schemas
================================ */
const options = { exclude: ['id', 'createdAt', 'updatedAt'] };
sjs.getSequelizeSchema(db.sequelize, options);
