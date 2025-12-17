
module.exports = function(app,db) {

    /**
     * GET /v1/status/{brand}
     * @summary Test a status of a beer brand website - FIXED (Command Injection & XSS)
     * @tags system
     * @param {string} brand.path.required - the beer brand you want to test
     */
    app.get('/v1/status/:brand', (req,res) =>{
        var execSync = require('child_process').execSync;
        
        // FIX V1: Input validation with whitelist approach
        const allowedBrands = ['heineken', 'corona', 'budweiser', 'stella', 'carlsberg', 'guinness', 'becks'];
        const brand = req.params.brand;
        
        // Validate input against whitelist
        if (!brand || !allowedBrands.includes(brand.toLowerCase())) {
            return res.status(400).json({
                error: 'Invalid brand name',
                allowed_brands: allowedBrands
            });
        }
        
        // Additional validation: alphanumeric only
        if (!/^[a-zA-Z]+$/.test(brand)) {
            return res.status(400).json({error: 'Brand name must contain only letters'});
        }
        
        try{
            // Safe: validated input from whitelist
            const test = execSync("curl https://letmegooglethat.com/?q=" + brand, {
                timeout: 5000,
                maxBuffer: 1024 * 1024
            });
            
            // Send sanitized response
            res.json({
                status: 'success',
                brand: brand,
                message: 'Brand lookup completed'
            });
        }
        catch (e){
            console.error('Command execution error:', e);
            res.status(500).json({error: 'Request failed'});
        }
    });

    /**
     * GET /v1/redirect/
     * @summary Redirect the user to beer brand website - FIXED (Open Redirect)
     * @tags system
     * @param {string} url.query.required - the beer brand you want to redirect to
     */
    app.get('/v1/redirect/', (req,res) =>{
        var url = req.query.url;
        
        // FIX: Validate redirect URL
        if (!url) {
            return res.status(400).json({error: 'URL parameter required'});
        }
        
        try {
            const urlObj = new URL(url);
            
            // Whitelist allowed domains for redirect
            const allowedDomains = [
                'heineken.com',
                'corona.com',
                'budweiser.com',
                'example.com'
            ];
            
            // Check if hostname is in whitelist
            const isAllowed = allowedDomains.some(domain => 
                urlObj.hostname === domain || urlObj.hostname.endsWith('.' + domain)
            );
            
            if (!isAllowed) {
                return res.status(403).json({
                    error: 'Redirect to this domain is not allowed',
                    allowed_domains: allowedDomains
                });
            }
            
            console.log('Redirecting to:', url);
            res.redirect(url);
            
        } catch(e) {
            console.error('Invalid URL:', e);
            return res.status(400).json({error: 'Invalid URL format'});
        }
    });

    /**
     * GET /v1/app/
     * @summary get insecure object - FIXED (Insecure deserialization)
     * @tags system
     */
    app.get('/v1/app/', (req,res) =>{
        // FIX: Use JSON.parse instead of node-serialize for deserialization
        // or completely remove this endpoint if not needed
        
        var obj = req.query.code;
        
        if (!obj) {
            return res.status(400).json({error: 'Code parameter required'});
        }
        
        try {
            // Use safe JSON parsing instead of node-serialize
            var parsed = JSON.parse(obj);
            
            // Validate the parsed object structure
            if (typeof parsed !== 'object') {
                return res.status(400).json({error: 'Invalid object format'});
            }
            
            console.log('Parsed object:', parsed);
            res.json({
                status: 'success',
                data: parsed
            });
            
        } catch(e) {
            console.error('Deserialization error:', e);
            return res.status(400).json({error: 'Invalid JSON format'});
        }
    });

    /**
     * GET /v1/test/
     * @summary Perform a get request on another url - FIXED (SSRF)
     * @tags system
     * @param {string} url.query.required - the URL to test
     */
    app.get('/v1/test/', (req,res) =>{
        var requests = require('axios');
        var url = req.query.url;
        
        // FIX V6: SSRF Protection with comprehensive validation
        if(!url){
            return res.status(400).json({error: 'URL parameter required'});
        }
        
        try {
            const urlObj = new URL(url);
            
            // Whitelist allowed domains
            const allowedDomains = [
                'api.example.com',
                'trusted-service.com',
                'safe-api.org',
                'public-api.example.net'
            ];
            
            // Block private IP ranges
            const hostname = urlObj.hostname;
            const blockedPatterns = [
                /^localhost$/i,
                /^127\./,
                /^10\./,
                /^172\.(1[6-9]|2[0-9]|3[01])\./,
                /^192\.168\./,
                /^169\.254\./,
                /^0\.0\.0\.0$/,
                /^\[?::1\]?$/,
                /^\[?fe80:/i
            ];
            
            // Check if hostname matches blocked patterns
            const isBlocked = blockedPatterns.some(pattern => pattern.test(hostname));
            
            if (isBlocked) {
                return res.status(403).json({error: 'Access to private IP ranges is not allowed'});
            }
            
            // Check if domain is in whitelist
            const isAllowed = allowedDomains.some(domain => 
                hostname === domain || hostname.endsWith('.' + domain)
            );
            
            if (!isAllowed) {
                return res.status(403).json({
                    error: 'Domain not allowed',
                    allowed_domains: allowedDomains
                });
            }
            
            // Only allow http and https protocols
            if (!['http:', 'https:'].includes(urlObj.protocol)) {
                return res.status(400).json({error: 'Only HTTP and HTTPS protocols are allowed'});
            }
            
            console.log('Making request to:', url);
            
            // Make request with timeout
            requests.get(url, {
                timeout: 5000,
                maxRedirects: 3
            })
            .then(Ares => {
                res.json({
                    status: 'success',
                    response_code: Ares.status,
                    message: 'Request completed successfully'
                });
                console.log(`statusCode: ${Ares.status}`);
            })
            .catch(err => {
                console.error('Request error:', err.message);
                res.status(500).json({
                    error: 'External request failed',
                    details: err.message
                });
            });
            
        } catch(e) {
            console.error('URL validation error:', e);
            return res.status(400).json({error: 'Invalid URL format'});
        }
    });

    /**
     * GET /v1/health
     * @summary Health check endpoint
     * @tags system
     */
    app.get('/v1/health', (req,res) =>{
        res.json({
            status: 'healthy',
            timestamp: new Date().toISOString(),
            uptime: process.uptime()
        });
    });
}
