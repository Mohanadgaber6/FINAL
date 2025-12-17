
'user strcit';
const config = require('./../../config')
var jwt = require("jsonwebtoken");
const bcrypt = require('bcryptjs'); // FIX V8: Add bcrypt
const { user } = require('../../orm');

module.exports = (app,db) => {

    //Get all users
    /**
     * GET /v1/admin/users/ 
     * @summary List all users (Unverified JWT Manipulation)(Authorization Bypass) - FIXED V7
     * @tags admin
     * @security BearerAuth
     * @return {array<User>} 200 - success response - application/json
     */
    app.get('/v1/admin/users/', (req,res) =>{
        if (req.headers.authorization){ 
            try {
                // FIX V7: Specify algorithm to prevent algorithm confusion attacks
                const user_object = jwt.verify(
                    req.headers.authorization.split(' ')[1],
                    "SuperSecret",
                    { algorithms: ['HS256'] } // FIXED: Explicit algorithm
                );
                
                db.user.findAll({include: "beers"})
                    .then((users) => {
                        if (user_object.role =='admin'){
                            res.json(users);
                        } else { 
                            res.status(403).json({error:"Not Admin, try again"})
                        }
                        return;
                    }).catch((e) =>{
                        res.status(500).json({error:"error fetching users"+e})
                    });
            } catch (err) {
                return res.status(401).json({error: "Invalid or expired token"});
            }
        } else {
            res.status(401).json({error:"missing Token in header"})
            return;
        }
    });

    //Get information about other users
    /**
     * GET /v1/user/{user_id}
     * @summary Get information of a specific user
     * @tags user
     * @param {integer} user_id.path.required - user id to get information
     * @return {array<User>} 200 - success response - application/json
     */
     app.get('/v1/user/:id', (req,res) =>{
        db.user.findOne({include: 'beers',where: { id : req.params.id}})
            .then(user => {
                res.json(user);
            });
    });

    /**
     * DELETE /v1/user/{user_id} 
     * @summary Delete a specific user - FIXED V3 (Broken Function Level Authentication)
     * @tags user
     * @param {integer} user_id.path.required - user id to delete
     * @return {array<User>} 200 - success response - application/json
     */
    app.delete('/v1/user/:id', (req,res) =>{
        // FIX V3: Add Authorization Check
        if (!req.headers.authorization) {
            return res.status(401).json({error: "Authentication required"});
        }

        try {
            // FIX V3: Verify JWT with proper algorithm
            const decoded = jwt.verify(
                req.headers.authorization.split(' ')[1],
                "SuperSecret",
                { algorithms: ['HS256'] }
            );

            // FIX V3: Check if user is admin
            if (decoded.role !== 'admin') {
                return res.status(403).json({error: "Admin access required to delete users"});
            }

            // FIX V3: Only proceed if authorized
            db.user.destroy({where: { id : req.params.id}})
                .then(user => {
                    res.json({result: "deleted"});
                })
                .catch(e =>{
                    res.status(500).json({error:e})
                });

        } catch (err) {
            return res.status(401).json({error: "Invalid or expired token"});
        }
    });

    /**
     * POST /v1/user/
     * @summary create a new user - FIXED V8 (Weak Password)
     * @tags user
     * @param {User} request.body.required - User
     * @return {object} 200 - user response
     */
    app.post('/v1/user/', async (req,res) =>{
        const userEmail = req.body.email;
        const userName = req.body.name;
        const userRole = req.body.role
        const userPassword = req.body.password;
        const userAddress = req.body.address

        // FIX V8: Add password strength validation
        if (!userPassword || userPassword.length < 8) {
            return res.status(400).json({error: "Password must be at least 8 characters"});
        }

        //validate email using regular expression
        var emailExpression = /^([a-zA-Z0-9_\.\-])+\@(([a-zA-Z0-9\-])+\.)+([a-zA-Z0-9]{2,4})+$/;
        var regex = new RegExp(emailExpression)
        
        if (!emailExpression.test(userEmail)){
            res.status(400).json({error:"regular expression of email couldn't be validated"})
            return
        }

        try {
            // FIX V8: Hash password with bcrypt before storing
            const hashedPassword = await bcrypt.hash(userPassword, 10);

            const new_user = await db.user.create({
                name: userName,
                email: userEmail,
                role: userRole,
                address: userAddress,
                password: hashedPassword // FIXED: Store hashed password
            });

            // Don't return password in response
            const { password, ...userWithoutPassword } = new_user.toJSON();
            res.json(userWithoutPassword);

        } catch (err) {
            res.status(500).json({error: "User creation failed: " + err.message});
        }
    });

    /**
     * GET /v1/love/{beer_id}
     * @summary make a user love a beer(CSRF - Client Side Request Forgery GET)
     * @tags user
     * @param {integer} beer_id.path.required - Beer Id
     * @param {integer} id.query - User ID
     * @param {boolean} front.query - is it a frontend redirect ?
     * @return {object} 200 - user response
     */
    app.get('/v1/love/:beer_id', (req,res) =>{
        var current_user_id = req.query.id;
        var front = true;
        if (req.query.front){
            front = req.query.front
        }
        if(!req.query.id){
            res.redirect("/?message=No Id")
            return
        }
        
        const beer_id = req.params.beer_id;

        db.beer.findOne({
            where:{id:beer_id}
        }).then((beer) => {
            const user = db.user.findOne(
                {where: {id : current_user_id}},
                {include: 'beers'}).then(current_user => {
                    if(current_user){
                    current_user.hasBeer(beer).then(result => {
                        if(!result){
                            current_user.addBeer(beer, { through: 'user_beers' })
                        }
                        if(front){
                            let love_beer_message = "You Just Loved this beer!!"
                            res.redirect("/beer?user="+ current_user_id+"&id="+beer_id+"&message="+love_beer_message)
                            return
                        }
                        res.json(current_user);
                    })
                }
                else{
                    res.json({error:'user Id was not found'});
                }
            })
        })
        .catch((e)=>{
            res.json(e)
        })
    });

    /**
     * POST /v1/love/{beer_id}
     * @summary make a user love a beer(CSRF - Client Side Request Forgery POST)
     * @tags user
     * @param {integer} beer_id.path.required - Beer Id
     * @param {integer} id.query - User ID
     * @param {boolean} front.query - is it a frontend redirect ?
     * @return {object} 200 - user response
     */
    app.post('/v1/love/:beer_id', (req,res) =>{
        var current_user_id = 1;
        var front = false;
        if (req.query.front){
            front = req.query.front
        }
        if(!req.query.id){
            if(!req.session.user.id){
                if(!req.headers.authorization){
                    res.json({error:"Couldn't find user token"})
                }
                current_user_id = jwt.decode(req.headers.authorization.split(' ')[1]).id
            }
            current_user_id = req.session.user.id
        }
        current_user_id = req.query.id
        
        const beer_id = req.params.beer_id;

        db.beer.findOne({
            where:{id:beer_id}
        }).then((beer) => {
            const user = db.user.findOne(
                {where: {id : current_user_id}},
                {include: 'beers'}).then(current_user => {
                    if(current_user){
                    current_user.hasBeer(beer).then(result => {
                        if(!result){
                            current_user.addBeer(beer, { through: 'user_beers' })
                        }
                        if(front){
                            let love_beer_message = "You Loved this beer!!"
                            res.redirect("/beer?user="+ current_user_id+"&id="+beer_id+"&message="+love_beer_message)
                        }
                        res.json(current_user);
                    })
                }
                else{
                    res.json({error:'user Id was not found'});
                }
            })
        })
        .catch((e)=>{
            res.json(e)
        })
    });

    /**
     * LoginUserDTO for login
     * @typedef {object} LoginUserDTO
     * @property {string} email.required - email
     * @property {string} password.required - password
     */
    /**
     * POST /v1/user/token
     * @summary login endpoint to get jwt token - FIXED V7 (Insecure JWT Implementation)
     * @tags user
     * @param {LoginUserDTO} request.body.required - user login credentials - application/json       
     * @return {string} 200 - success
     * @return {string} 404 - user not found
     * @return {string} 401 - wrong password
    */
    app.post('/v1/user/token', async (req,res) =>{
        const userEmail = req.body.email;
        const userPassword = req.body.password;

        try {
            const users = await db.user.findAll({
                where: { email: userEmail }
            });

            if(users.length == 0){
                return res.status(404).send({error:'User was not found'});
            }

            const user = users[0];

            // FIX V8: Use bcrypt to compare passwords instead of MD5
            const isValidPassword = await bcrypt.compare(userPassword, user.password);

            if(isValidPassword){
                const jwtTokenSecret = "SuperSecret"
                const payload = { 
                    "id": user.id,
                    "role": user.role 
                }
                
                // FIX V7: Add algorithm and shorter expiry
                var token = jwt.sign(payload, jwtTokenSecret, {
                    algorithm: 'HS256',      // FIXED: Explicit algorithm
                    expiresIn: 3600,         // FIXED: 1 hour instead of 24
                    audience: 'beer-api',    // FIXED: Add audience
                    issuer: 'beer-api-server' // FIXED: Add issuer
                });

                res.status(200).json({
                    jwt: token,
                    user: {
                        id: user.id,
                        name: user.name,
                        email: user.email,
                        role: user.role
                    }
                });
                return;
            }
            
            res.status(401).json({error:'Password was not correct'})
        } catch (err) {
            res.status(500).json({error: 'Login failed: ' + err.message});
        }
    });

    /**
     * POST /v1/user/login
     * @summary login page - FIXED V8 (insecure password/no hashing)
     * @tags user
     * @param {LoginUserDTO} request.body.required - user login credentials - application/json       
     * @return {string} 200 - success
     * @return {string} 404 - user not found
     * @return {string} 401 - wrong password
    */
    app.post('/v1/user/login', async (req,res) =>{
        const userEmail = req.body.email;
        const userPassword = req.body.password;

        try {
            const users = await db.user.findAll({
                where: { email: userEmail }
            });

            if(users.length == 0){
                return res.status(404).send({error:'User was not found'});
            }

            const user = users[0];

            // FIX V8: Use bcrypt instead of plaintext/MD5
            const isValidPassword = await bcrypt.compare(userPassword, user.password);

            if(isValidPassword){
                // Don't return password
                const { password, ...userWithoutPassword } = user.toJSON();
                res.status(200).json(userWithoutPassword);
                return;
            }
            
            res.status(401).json({error:'Password was not correct'})
        } catch (err) {
            res.status(500).json({error: 'Login failed: ' + err.message});
        }
    });

    /**
     * PUT /v1/user/{user_id}
     * @summary update user - (horizontal privesc)(mass assignment/BOLA)
     * @tags user
     * @param {User} request.body.required - update credentials - application/json       
     * @param {integer} user_id.path.required
     * @return {string} 200 - success
     * @return {string} 404 - user not found
     * @return {string} 401 - wrong password
    */
    app.put('/v1/user/:id', (req,res) =>{
        const userId = req.params.id;
        const userPassword = req.password;
        const userEmail = req.body.email
        const userProfilePic = req.body.profile_pic
        const userAddress = req.body.address
        
        const user = db.user.update(req.body, {
            where: {
                id : userId
            }}
        )
        .then((user)=>{
            res.send(user)
        })
    });

    /**
     * PUT /v1/admin/promote/{user_id}
     * @summary promote to admin - (vertical privesc)
     * @tags admin
     * @param {integer} user_id.path.required
     * @return {string} 200 - success
     * @return {string} 404 - user not found
     * @return {string} 401 - wrong password
    */
    app.put('/v1/admin/promote/:id', (req,res) =>{
        const userId = req.params.id;
        const user = db.user.update({role:'admin'}, {
            where: {
                id : userId
            }}
        )
        .then((user)=>{
            res.send(user)
        })
    });

    /**
    * POST /v1/user/{user_id}/validate-otp
    * @summary Validate One Time Password - (Broken Authorization/2FA)(Auth Credentials in URL)(lack of rate limiting)
    * @tags user
    * @param {integer} user_id.path.required
    * @param {string} seed.query - otp seed
    * @param {string} token.query.required - token to be supplied by the user and validated against the seed
    * @return {string} 200 - success
    * @return {string} 401 - invalid token
   */
    app.post('/v1/user/:id/validate-otp', (req,res) =>{
       const userId = req.params.id;
       const user = db.user.findOne({
           where: {
             id: userId
           }}).then(user => {
               if(user.length == 0){
                   res.status(404).send({error:'User was not found'})
               return;
               }
            
            const otplib = require('otplib')
            const seed = req.query.seed || 'SUPERSECUREOTP';
            const userToken = req.query.token;
            const GeneratedToken = otplib.authenticator.generate(seed);
            const isValid = otplib.authenticator.check(userToken, GeneratedToken);

               if(isValid || userToken == req.session.otp){
                   const jwtTokenSecret = "SuperSecret"
                   const payload = { "id": user.id,"role":user.role }
                   var jwttoken = jwt.sign(payload, jwtTokenSecret, {
                       expiresIn: 86400,
                     });
                   res.status(200).json({
                       jwt:jwttoken,
                       user:user,
                   });
                   return;
               }
               if(req.query.seed){
                req.session.otp = GeneratedToken
                req.session.save(function(err) {})
                res.status(401).json({error:'OTP was not correct, got:' + GeneratedToken})
                return;
               }
               res.status(401).json({error:'OTP was not correct'})
           })
   });
};
