require('dotenv').config();
const express = require('express');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');

const app = express();
app.use(express.json());

// Mock database to store users
const users = {};

// Secret key for JWT
const secretKey = process.env.JWT_SIGN_SECRET;

// Middleware to verify token
function verifyToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    if (!authHeader) return res.status(401).send('Token non fourni.');

    const token = authHeader.split(' ')[1]; // Supprimer le mot-clé "Bearer" s'il est présent
    if (!token) return res.status(401).send('Token non fourni.');

    jwt.verify(token, secretKey, (err, decoded) => {
        if (err) return res.status(403).send('Token invalide.');
        req.user = decoded;
        next();
    });
}

// Register route
app.post('/register', async(req, res) => {
    const { username, password } = req.body;
    if (!username || !password) return res.status(400).send('Nom d\'utilisateur et mot de passe requis.');

    if (users[username]) return res.status(400).send('Utilisateur déjà existant.');

    const hashedPassword = await bcrypt.hash(password, 10);
    console.log(password);
    users[username] = { username, password: hashedPassword };
    res.status(200).send('Utilisateur créé avec succès.');
});

// Login route
app.post('/login', async(req, res) => {
    const { username, password } = req.body;
    if (!username || !password) return res.status(400).send('Nom d\'utilisateur et mot de passe requis.');

    const user = users[username];
    if (!user) return res.status(401).send('Utilisateur non trouvé.');

    const validPassword = await bcrypt.compare(password, user.password); // Comparaison des hashs
    if (!validPassword) return res.status(401).send('Mot de passe incorrect.');

    const token = jwt.sign({ username }, secretKey, { expiresIn: '1h' });
    res.status(200).json({ token });
});

// Change password route
app.post('/change-password', async(req, res) => {
    const { username, password, newPassword } = req.body;
    if (!username || !password || !newPassword) return res.status(400).send('Nom d\'utilisateur, ancien et nouveau mot de passe requis.');

    const user = users[username];
    if (!user) return res.status(401).send('Utilisateur non trouvé.');

    const validPassword = await bcrypt.compare(password, user.password); // Comparaison des hashs
    if (!validPassword) return res.status(401).send('Mot de passe incorrect.');

    const hashedNewPassword = await bcrypt.hash(newPassword, 10); // Hash du nouveau mot de passe reçu
    user.password = hashedNewPassword;
    res.status(200).send('Mot de passe modifié avec succès.');
});

// Test route
app.get('/test', verifyToken, (req, res) => {
    res.status(200).send('Route accessible uniquement par les utilisateurs connectés.');
});

const PORT = process.env.PORT || 5000;
const HOST = process.env.HOST;

app.listen(PORT, HOST, () => {
    console.log('Serveur démarré sur le port ' + PORT);
});