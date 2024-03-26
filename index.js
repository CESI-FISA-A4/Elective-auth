require('dotenv').config();
const express = require('express');
const authRoutes = require('./app/routes/authRoutes');
const { connectToDatabase } = require('./app/utils/initDB');
const roleRouter = require('./app/routes/roleRoutes');

// Connect to DB
connectToDatabase();

const app = express();
app.use(express.json());


app.use('/api/auth', authRoutes);
app.use('/api/auth/roles', roleRouter);

const PORT = process.env.PORT || 5000;
const HOST = process.env.HOST;

app.listen(PORT, HOST, () => {
    console.log('Serveur démarré sur le port ' + PORT);
});