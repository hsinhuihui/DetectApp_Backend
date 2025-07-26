const express = require('express');
const mysql = require('mysql2');
const cors = require('cors');
const nodemailer = require('nodemailer');
const bcrypt = require('bcrypt');

const app = express();
app.use(cors());
app.use(express.json());

const verificationCodes = {};

const db = mysql.createConnection({
    host: 'localhost',
    user: 'root',
    password: '1128',
    database: 'Traffic_Detect_System'
});

db.connect(err => {
    if (err) {
        console.error('連線失敗:', err);
    } else {
        console.log('連線成功');
    }
});

// 寄出驗證碼
app.post('/precheck', (req, res) => {
    const { user_id, email } = req.body;
    const checkSql = 'SELECT * FROM user WHERE email = ? OR user_id = ?';

    db.query(checkSql, [email, user_id], (err, results) => {
        if (err) return res.status(500).send({ message: '查詢失敗', error: err });
        if (results.length > 0) return res.status(400).send({ message: '帳號或使用者ID已存在' });

        const code = Math.floor(100000 + Math.random() * 900000);
        verificationCodes[email] = { code, user_id, createdAt: Date.now() };

        const transporter = nodemailer.createTransport({
            service: 'gmail',
            auth: { user: 'trafficdetect@gmail.com', pass: 'azfxksjucsladpri' }
        });

        const mailOptions = {
            from: 'trafficdetect@gmail.com',
            to: email,
            subject: '註冊驗證碼',
            text: `您的驗證碼為：${code}`
        };

        transporter.sendMail(mailOptions, error => {
            if (error) return res.status(500).send({ message: '驗證信寄送失敗', error });
            res.status(200).send({ message: '驗證碼已寄出' });
        });
    });
});

// 註冊
app.post('/signup', (req, res) => {
    const { email, user_id, password, code } = req.body;

    if (!verificationCodes[email] || verificationCodes[email].code != code) {
        return res.status(400).send({ message: '驗證碼錯誤或已過期' });
    }

    const sqlSensitivity = 'INSERT INTO sensitivity (value) VALUES (2)';
    db.query(sqlSensitivity, (err, sensitivityResult) => {
        if (err) return res.status(500).send({ message: '新增 sensitivity 失敗', error: err });

        const sensitivityId = sensitivityResult.insertId;
        const sqlReminder = 'INSERT INTO reminder (voice_reminder, shock_reminder) VALUES (1, 1)';
        db.query(sqlReminder, (err, reminderResult) => {
            if (err) return res.status(500).send({ message: '新增 reminder 失敗', error: err });

            const reminderId = reminderResult.insertId;
            const saltRounds = 10;
            bcrypt.hash(password, saltRounds, (err, hashedPassword) => {
                if (err) return res.status(500).send({ message: '密碼加密失敗', error: err });

                const sqlUser = 'INSERT INTO user (user_id, email, password, sensitivity_id, reminder_id) VALUES (?, ?, ?, ?, ?)';
                db.query(sqlUser, [user_id, email, hashedPassword, sensitivityId, reminderId], (err) => {
                    if (err) return res.status(500).send({ message: '新增 user 失敗', error: err });
                    delete verificationCodes[email];
                    res.status(200).send({ message: '註冊成功' });
                });
            });
        });
    });
});

//忘記密碼-寄送驗證碼
app.post('/forget-password/request', (req, res) => {
    const { email } = req.body;
    const checkUserSql = 'SELECT * FROM user WHERE email = ?';

    db.query(checkUserSql, [email], (err, results) => {
        if (err) return res.status(500).send({ message: '查詢失敗', error: err });
        if (results.length === 0) return res.status(404).send({ message: '此信箱尚未註冊' });

        const code = Math.floor(100000 + Math.random() * 900000);
        verificationCodes[email] = {
            code,
            createdAt: Date.now(),
            verified: false
        };

        const transporter = nodemailer.createTransport({
            service: 'gmail',
            auth: { user: 'trafficdetect@gmail.com', pass: 'azfxksjucsladpri' }
        });

        const mailOptions = {
            from: 'trafficdetect@gmail.com',
            to: email,
            subject: '忘記密碼驗證碼',
            text: `您的驗證碼為：${code}`
        };

        transporter.sendMail(mailOptions, error => {
            if (error) return res.status(500).send({ message: '寄信失敗', error });
            res.status(200).send({ message: '驗證碼已寄出' });
        });
    });
});

//忘記密碼-驗證
app.post('/forget-password/verify', (req, res) => {
    const { email, code } = req.body;
    const entry = verificationCodes[email];

    if (!entry) return res.status(400).send({ message: '請先申請驗證碼' });

    const expired = Date.now() - entry.createdAt > 5 * 60 * 1000; // 5 分鐘有效
    if (expired) {
        delete verificationCodes[email];
        return res.status(400).send({ message: '驗證碼已過期' });
    }

    if (entry.code != code) {
        return res.status(400).send({ message: '驗證碼錯誤' });
    }

    verificationCodes[email].verified = true;
    res.status(200).send({ message: '驗證成功' });
});


// 重設密碼
app.post('/reset-password', (req, res) => {
    const { email, new_password } = req.body;
    const entry = verificationCodes[email];

    if (!entry || !entry.verified) {
        return res.status(403).send({ message: '請先完成驗證碼驗證' });
    }

    const saltRounds = 10;
    bcrypt.hash(new_password, saltRounds, (err, hashedPassword) => {
        if (err) return res.status(500).send({ message: '密碼加密失敗', error: err });

        const sql = 'UPDATE user SET password = ? WHERE email = ?';
        db.query(sql, [hashedPassword, email], (err) => {
            if (err) return res.status(500).send({ message: '密碼更新失敗', error: err });

            delete verificationCodes[email];
            res.status(200).send({ message: '密碼已成功更新' });
        });
    });
});


// 登入
app.post('/signin', (req, res) => {
    const { email, password } = req.body;
    const sql = 'SELECT * FROM user WHERE email = ?';

    db.query(sql, [email], (err, results) => {
        if (err) return res.status(500).send(err);
        if (results.length === 0) return res.status(401).json({ message: '帳號錯誤' });

        const storedHash = results[0].PASSWORD;
        bcrypt.compare(password, storedHash, (err, isMatch) => {
            if (err) return res.status(500).send(err);
            if (!isMatch) return res.status(401).json({ message: '密碼錯誤' });

            res.json({ message: '登入成功', user_id: results[0].user_id });
        });
    });
});

// 靈敏度更新
app.patch('/sensitivity', (req, res) => {
    const { user_id, value } = req.body;

    const sql = `
        UPDATE sensitivity
        SET value = ?
        WHERE sensitivity_id = (SELECT sensitivity_id FROM user WHERE user_id = ?)
    `;
    db.query(sql, [value, user_id], (err) => {
        if (err) return res.status(500).send(err);
        res.json({ message: '靈敏度設定更新成功' });
    });
});

// 提醒設定更新
app.patch('/reminder', (req, res) => {
    const { user_id, voice_reminder, shock_reminder } = req.body;

    const sql = `
        UPDATE reminder
        SET voice_reminder = ?, shock_reminder = ?
        WHERE reminder_id = (SELECT reminder_id FROM user WHERE user_id = ?)
    `;
    db.query(sql, [voice_reminder, shock_reminder, user_id], (err) => {
        if (err) return res.status(500).send(err);
        res.json({ message: '提醒設定更新成功' });
    });
});

// 取得靈敏度
app.get('/user/:id/sensitivity', (req, res) => {
    const { id } = req.params;

    const sql = `
        SELECT * FROM sensitivity
        WHERE sensitivity_id = (SELECT sensitivity_id FROM user WHERE user_id = ?)
    `;
    db.query(sql, [id], (err, results) => {
        if (err) return res.status(500).send(err);
        res.json(results);
    });
});

// 取得提醒設定
app.get('/user/:id/reminder', (req, res) => {
    const { id } = req.params;

    const sql = `
        SELECT * FROM reminder
        WHERE reminder_id = (SELECT reminder_id FROM user WHERE user_id = ?)
    `;
    db.query(sql, [id], (err, results) => {
        if (err) return res.status(500).send(err);
        res.json(results);
    });
});

// 啟動伺服器 手機
app.listen(3000, '172.20.10.11', () => {
    console.log('伺服器啟動在 http://172.20.10.11:3000');
});

// Macbook 172.20.10.2 10.22.134.61

/*app.listen(3000, () => {
    console.log('伺服器啟動在 http://localhost:3000');
});*/

