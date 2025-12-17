
const authJwt = require("../../middleware/authJwt");

module.exports = function(app,db) {

    /**
     * GET /v1/user/details/{user_id}
     * @summary get user info by id - FIXED (IDOR protection added)
     * @tags user
     * @param {integer} user_id.path.required - user id to get details
     * @return {User} 200 - success response - application/json
     */
    app.get('/v1/user/details/:id', [authJwt.verifyToken], (req,res) =>{
        const userId = req.params.id;
        const authenticatedUserId = req.userId; // from JWT token
        
        // FIX V2: Check if user is accessing their own data or is admin
        if (userId != authenticatedUserId && req.userRole !== 'admin') {
            return res.status(403).json({error: 'Access denied'});
        }
        
        const user = db.user.findAll({
            where: {
              id: userId
            }}).then(user => {
                db.beer.findAll({
                    where: {
                        userId: userId
                    }}).then(beers => {
                        var current_user = user[0].dataValues
                        current_user['beers'] = beers
                        if(current_user){
                            if(beers.length >0){
                                current_user['premium'] =  beers.length > 5 ? true:false
                            }
                            res.json(current_user);
                        }
                    })
                    .catch((e)=>{
                        res.status(500).json({error: 'Database error'});
                    })
                })
                .catch((e)=>{
                    // FIX V7: Generic error message to prevent user enumeration
                    res.status(401).json({error:'Invalid credentials'});
                })
        });

     /**
     * POST /v1/love/{beer_id}
     * @summary make a user love a beer(CSRF - Client Side Request Forgery POST)
     * @tags user
     * @param {integer} beer_id.path.required - beer id to love
     * @return {string} 200 - success
     * @return {string} 404 - beer not found
    */
     app.post('/v1/user/love/:id', (req,res) =>{

        const beerId = req.params.id;
        const userId = req.session.userId;
        const user = db.beer.update({userId: userId}, {
            where: {
              id: beerId
            }}).then(user => {
                db.beer.findAll({
                    where: {
                        userId: userId
                    }}).then(beers => {
                        var current_user = user[0].dataValues
                        current_user['beers'] = beers
                        if(current_user){
                            if(beers.length >0){
                                current_user['premium'] =  beers.length > 5 ? true:false
                            }
                            res.json(current_user);
                        }
                    })
                    .catch((e)=>{
                        // FIX V7: Generic error message
                        res.status(401).json({error:'Invalid credentials'});
                    })
                })
                .catch((e)=>{
                    res.status(500).json(e)
                })
        });

   /**
     * LoginUserDTO for login
     * @typedef {object} LoginUserDTO
     * @property {string} email.required - The email
     * @property {string} password.required - The password
     */

    /**
     * POST /v1/user/token
     * @summary login endpoint to get jwt token - FIXED (user enumeration, weak password)
     * @tags user
     * @param {LoginUserDTO} request.body.required - user login credentials - application/json       
     * @return {string} 200 - success
     * @return {string} 401 - invalid credentials
    */
     app.post('/v1/user/token', async (req,res) =>{

        const userEmail = req.body.email;
        const userPassword = req.body.password;
        
        try {
            const user = await db.user.findAll({
                where: {
                  email: userEmail
                }});
                
            if(user.length == 0){
                // FIX V7: Generic error message to prevent user enumeration
                return res.status(401).send({error:'Invalid credentials'})
            }

            const bcrypt = require('bcrypt');
            
            // FIX V8: Use bcrypt instead of MD5 for password comparison
            const isValidPassword = await bcrypt.compare(userPassword, user[0].password);
            
            if(isValidPassword){
                // JWT token generation
                const jwtTokenSecret = process.env.JWT_SECRET || "SuperSecret"
                const payload = { 
                    "id": user[0].id,
                    "role": user[0].role,
                    "email": user[0].email
                }
                const jwt = require('jsonwebtoken');
                const token = jwt.sign(payload, jwtTokenSecret, {
                    expiresIn: '1h',
                    algorithm: 'HS256'
                });
                res.status(200).json({token: token});
                return;
            }
            else{
                // FIX V7: Generic error message
                return res.status(401).send({error:'Invalid credentials'})
            }
        } catch(error) {
            console.error('Login error:', error);
            return res.status(500).json({error: 'Authentication failed'});
        }
     });

    /**
     * POST /v1/user/login
     * @summary login page - FIXED (Session fixation, user enumeration, weak password)
     * @tags user
     * @param {LoginUserDTO} request.body.required - user login credentials - application/json       
     * @return {string} 200 - success
     * @return {string} 401 - invalid credentials
    */
     app.post('/v1/user/login', async (req,res) =>{

        const userEmail = req.body.email;
        const userPassword = req.body.password;
        
        try {
            const user = await db.user.findAll({
                where: {
                  email: userEmail
                }});
                
            if(user.length == 0){
                // FIX V7: Generic error message to prevent user enumeration
                return res.status(401).send({error:'Invalid credentials'})
            }

            const bcrypt = require('bcrypt');
            
            // FIX V8: Use bcrypt instead of MD5
            const isValidPassword = await bcrypt.compare(userPassword, user[0].password);
            
            if(isValidPassword){
                // FIX V5: Regenerate session ID to prevent session fixation
                req.session.regenerate((err) => {
                    if(err) {
                        return res.status(500).json({error: 'Session error'});
                    }
                    
                    req.session.userId = user[0].id;
                    req.session.userRole = user[0].role;
                    
                    res.status(200).json({
                        message: 'Login successful',
                        user: {
                            id: user[0].id,
                            email: user[0].email,
                            role: user[0].role
                        }
                    });
                });
                return;
            }
            else{
                // FIX V7: Generic error message
                return res.status(401).send({error:'Invalid credentials'})
            }
        } catch(error) {
            console.error('Login error:', error);
            return res.status(500).json({error: 'Authentication failed'});
        }
     });

    /**
     * PUT /v1/user/{user_id}
     * @summary update user - FIXED (horizontal privesc, mass assignment)
     * @tags user
     * @param {User} request.body.required - update credentials - application/json       
     * @param {integer} user_id.path.required
     * @return {string} 200 - success
     * @return {string} 403 - access denied
    */
     app.put('/v1/user/:id', [authJwt.verifyToken], (req,res) =>{

        const userId = req.params.id;
        const authenticatedUserId = req.userId;
        
        // FIX V2: Check authorization
        if (userId != authenticatedUserId && req.userRole !== 'admin') {
            return res.status(403).json({error: 'Access denied'});
        }
        
        // FIX: Whitelist allowed fields to prevent mass assignment
        const allowedFields = {
            email: req.body.email,
            profile_pic: req.body.profile_pic,
            address: req.body.address
        };
        
        // Remove role from allowed fields to prevent privilege escalation
        // Only admins can change roles through dedicated endpoint
        
        const user = db.user.update(allowedFields, {
            where: {
                id : userId
            }}
        )
        .then(user => {
            res.json({message: 'User updated successfully'});
        })
        .catch(err => {
            res.status(500).json({error: 'Update failed'});
        });
    });

    /**
     * DELETE /v1/user/{user_id} 
     * @summary Delete a specific user - FIXED (Broken Function Level Authentication)
     * @tags user
     * @param {integer} user_id.path.required - user id to delete
     * @return {array<User>} 200 - success response - application/json
     */
    // FIX V3: Added authentication and admin authorization middleware
    app.delete('/v1/user/:id', [authJwt.verifyToken, authJwt.isAdmin], (req,res) =>{
        const userId = req.params.id;
        
        db.user.destroy({where: { id : userId}})
            .then(user => {
                if(user === 0) {
                    return res.status(404).json({error: "User not found"});
                }
                res.json({result: "User deleted successfully"});
            })
            .catch(err => {
                console.error('Delete error:', err);
                res.status(500).json({error: "Delete failed"});
            });
    });

    /**
     * GET /v1/user/
     * @summary Get all users - FIXED (requires admin)
     * @tags user
     * @return {array<User>} 200 - success response - application/json
     */
    app.get('/v1/user/', [authJwt.verifyToken, authJwt.isAdmin], (req,res) =>{
        db.user.findAll()
            .then(users => {
                res.json(users);
            })
            .catch(err => {
                res.status(500).json({error: 'Failed to fetch users'});
            });
    });

    /**
     * PUT /v1/admin/promote/{user_id}
     * @summary promote to admin - FIXED (vertical privesc protection)
     * @tags admin
     * @param {integer} user_id.path.required
     * @return {string} 200 - success
     * @return {string} 403 - access denied
    */
    app.put('/v1/admin/promote/:id', [authJwt.verifyToken, authJwt.isAdmin], (req,res) =>{

        const userId = req.params.id;
        const user = db.user.update({role:'admin'}, {
            where: {
                id : userId
            }}
        )
        .then(user => {
            res.json({message: 'User promoted to admin successfully'});
        })
        .catch(err => {
            res.status(500).json({error: 'Promotion failed'});
        });
    });

    /**
     * GET /v1/user/otp/verify
     * @summary verify OTP - FIXED (secure seed handling)
     * @tags user
     * @param {integer} user_id.query.required
     * @param {string} token.query.required
     * @return {string} 200 - success
    */
    app.get('/v1/user/otp/verify', [authJwt.verifyToken], (req,res) =>{
        const userId = req.query.user_id;
        
        const user = db.user.findOne({
            where: {
              id: userId
            }}).then(user => {
                if(!user || user.length == 0){
                    return res.status(401).send({error:'Invalid credentials'})
                }
             
                const otplib = require('otplib')

                // FIX: Use stored seed from database, not user input
                const seed = user.otp_seed || 'DEFAULTSEED';
                const userToken = req.query.token;

                const GeneratedToken = otplib.authenticator.generate(seed);

                if(GeneratedToken == userToken){
                    res.json({result: 'OTP verified successfully'});
                }
                else{
                    res.status(401).json({error: 'Invalid OTP'});
                }
            })
            .catch(err => {
                res.status(500).json({error: 'Verification failed'});
            });
    });
}
