require('dotenv').config();
const express = require('express');
const authRoutes = require('./app/routes/authRoutes');

const app = express();
app.use(express.json());


app.use('/api/auth', authRoutes);

const PORT = process.env.PORT || 5000;
const HOST = process.env.HOST;

app.listen(PORT, HOST, () => {
    console.log('Serveur démarré sur le port ' + PORT);
});