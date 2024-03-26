var bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

// Secret key for JWT
const secretKey = process.env.JWT_SIGN_SECRET;

// Mock database to store users
const users = {};

module.exports = {
    registerView: async(req, res) => {
        const { username, password } = req.body;
        if (!username || !password) return res.status(400).send('Username and password required');

        if (users[username]) return res.status(400).send('User already exists');

        const hashedPassword = await bcrypt.hash(password, 10);
        users[username] = { username, password: hashedPassword };
        res.status(200).send('User created successfuly');
    },

    loginView: async(req, res) => {
        const { username, password } = req.body;
        if (!username || !password) return res.status(400).send('Username and password required');

        const user = users[username];
        if (!user) return res.status(401).send('User not found');

        const validPassword = await bcrypt.compare(password, user.password); // Comparaison des hashs
        if (!validPassword) return res.status(401).send('Wrong password');

        const token = jwt.sign({ username }, secretKey, { expiresIn: '1h' });
        res.status(200).json({ token });
    },

    changePasswordView: async(req, res) => {
        const { username, password, newPassword } = req.body;
        if (!username || !password || !newPassword) return res.status(400).send('Username, old password and new password required');

        const user = users[username];
        if (!user) return res.status(401).send('User not found');

        const validPassword = await bcrypt.compare(password, user.password); // Comparaison des hashs
        if (!validPassword) return res.status(401).send('Wrong password');

        const hashedNewPassword = await bcrypt.hash(newPassword, 10); // Hash du nouveau mot de passe reçu
        user.password = hashedNewPassword;
        res.status(200).send('Password successfuly changed!');
    },

    verifyTokenView: (req, res) => {
        const token = req.headers['Authorization'] || req.headers['authorization'];

        if (!token) return res.status(401).send('Token not found');

        jwt.verify(token, secretKey, (err, decoded) => {
            if (err) return res.status(403).send('Wrong token');
            res.status(200).json({ "information": "Token decoded", "user": decoded });
        });
    }
}