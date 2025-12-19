'use strict';

const path = require('path');
const fs = require('fs');

module.exports = function (app, db) {

    /**
     * GET /v1/beer-pic/
     * FIXED: Path Traversal
     */
    app.get('/v1/beer-pic/', (req, res) => {

        const picture = req.query.picture;

        // 1️⃣ لازم picture
        if (!picture) {
            return res.status(400).json({ error: "Missing picture parameter" });
        }

        // 2️⃣ Allowlist للامتدادات
        const allowedExtensions = ['.png', '.jpg', '.jpeg', '.gif'];
        const ext = path.extname(picture).toLowerCase();

        if (!allowedExtensions.includes(ext)) {
            return res.status(403).json({ error: "Invalid file type" });
        }

        // 3️⃣ فولدر الصور المسموح
        const baseDir = path.join(__dirname, '../../public/images');

        // 4️⃣ Normalize
        const safePath = path.normalize(path.join(baseDir, picture));

        // 5️⃣ منع الخروج برا الفولدر
        if (!safePath.startsWith(baseDir)) {
            return res.status(403).json({ error: "Access denied" });
        }

        // 6️⃣ الملف لازم يكون موجود
        if (!fs.existsSync(safePath)) {
            return res.status(404).json({ error: "File not found" });
        }

        // 7️⃣ رجّع الصورة
        res.sendFile(safePath);
    });

};
