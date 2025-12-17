
'user strcit';
module.exports = (app,db) => {
    
    /**
     * GET /v1/status/{brand}
     * @summary Check if brand website is available - FIXED V6 (Command Injection)
     * @tags system
     * @param {string} brand.path.required - the beer brand you want to test
     */
    app.get('/v1/status/:brand', (req,res) =>{
        var execSync = require('child_process').execSync;
        
        // FIX V6: Input validation with whitelist to prevent Command Injection
        const allowedBrands = [
            'heineken', 
            'corona', 
            'budweiser', 
            'stella', 
            'carlsberg',
            'guinness',
            'corona extra'
        ];
        
        const brand = req.params.brand.toLowerCase().trim();
        
        if (!allowedBrands.includes(brand)) {
            return res.status(400).json({
                error: 'Invalid brand name',
                allowed: allowedBrands
            });
        }
        
        try {
            // Safe to execute since brand is validated against whitelist
            const test = execSync("curl https://letmegooglethat.com/?q=" + brand, {
                timeout: 5000,
                encoding: 'utf8'
            });
            res.send(test);
        } catch (e) {
            console.error(e);
            res.status(500).json({error: 'Request failed'});
        }
    });

    /**
     * GET /v1/redirect/
     * @summary Redirect the user to beer brand website (Insecure redirect)
     * @tags system
     * @param {string} url.query.required - the beer brand you want to redirect to
     */
    app.get('/v1/redirect/', (req,res) =>{
        var url = req.query.url
        console.log(url)
        if(url){
            res.redirect(url);
        } else{
            next()
        }
    });

    /**
     * POST /v1/init/
     * @summary Initialize beers from object (Insecure Object Deserialization)
     * @tags system
     * @param {object} request.body.required - the beer brand you want to test
     */
    app.post('/v1/init', (req,res) =>{
        var serialize = require('node-serialize');
        const body = req.body.object;
        var deser = serialize.unserialize(body)
        console.log(deser)
    });

    /**
     * GET /v1/test/
     * @summary Perform a get request on another url - FIXED V4 (SSRF)
     * @tags system
     * @param {string} url.query.required - the URL to test
     */
    app.get('/v1/test/', (req,res) =>{
        var requests = require('axios')
        var url = req.query.url
        
        // FIX V4: SSRF Protection with URL validation
        if(!url){
            return res.status(400).json({error: "URL parameter required"});
        }
        
        try {
            // FIX V4: Parse and validate URL
            const urlObj = new URL(url);
            
            // FIX V4: Whitelist allowed domains
            const allowedDomains = [
                'api.example.com',
                'trusted-service.com',
                'safe-api.org',
                'httpbin.org',
                'jsonplaceholder.typicode.com'
            ];
            
            if (!allowedDomains.includes(urlObj.hostname)) {
                return res.status(403).json({
                    error: 'Domain not allowed',
                    allowed: allowedDomains
                });
            }
            
            // FIX V4: Block internal/private IP ranges
            const blockedHosts = [
                'localhost', 
                '127.0.0.1', 
                '0.0.0.0', 
                '::1',
                '169.254.169.254' // AWS metadata
            ];
            
            if (blockedHosts.includes(urlObj.hostname)) {
                return res.status(403).json({
                    error: 'Cannot access internal resources'
                });
            }
            
            // FIX V4: Block private IP ranges (10.x.x.x, 172.16-31.x.x, 192.168.x.x)
            const ipRegex = /^(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.)/;
            if (ipRegex.test(urlObj.hostname)) {
                return res.status(403).json({
                    error: 'Cannot access private IP ranges'
                });
            }
            
            console.log('Fetching URL:', url);
            
            // FIX V4: Add timeout and prevent redirects
            requests.get(url, {
                timeout: 5000,        // 5 second timeout
                maxRedirects: 0       // Prevent redirect abuse
            })
            .then(Ares => {
                res.json({
                    response: Ares.status,
                    message: 'Request successful'
                });
                console.log(`statusCode: ${Ares.status}`);
            })
            .catch(error => {
                console.error(error);
                res.status(500).json({
                    error: 'Request failed',
                    details: error.message
                });
            });
            
        } catch (err) {
            // Invalid URL format
            if (err.code === 'ERR_INVALID_URL') {
                return res.status(400).json({error: 'Invalid URL format'});
            }
            console.error(err);
            res.status(400).json({error: 'Invalid URL'});
        }
    });
};
