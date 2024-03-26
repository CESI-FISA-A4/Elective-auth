const { Sequelize } = require('sequelize');

const sequelize = new Sequelize(process.env.DB_DATABASE, process.env.DB_USER, process.env.DB_PASSWORD, {
    host: process.env.DB_HOST,
    port: process.env.DB_PORT,
    dialect: 'mysql', // or 'postgres', 'sqlite', 'mssql', etc.
    logging: false,
    timestamps: false,
});

async function syncDatabase() {
    try {
        await sequelize.sync({ alter: true });
        console.log('Model sync successfully');
    } catch (error) {
        console.error('Sync error', error);
    }
}

async function initializeRoles() {
    try {
        const Role = require('../models/Role');
        // Vérifier si les rôles existent déjà
        const existingRoles = await Role.findAll();

        // S'il n'y a aucun rôle, créer les rôles par défaut
        if (!existingRoles.length) {
            await Role.bulkCreate([
                { label: 'admin' },
                { label: 'user' },
                { label: 'restaurant owner' },
                { label: 'deliveryman' }
            ]);
            console.log('Les rôles par défaut ont été créés avec succès.');
        } else {
            console.log('Les rôles existent déjà dans la base de données.');
        }
    } catch (error) {
        console.error('Erreur lors de l\'initialisation des rôles :', error);
    }
}

async function connectToDatabase() {
    try {
        await sequelize.authenticate();
        console.log('Connection has been established successfully.');
        await syncDatabase();
        await initializeRoles();
    } catch (error) {
        console.error('Unable to connect to the database:', error);
    }
}

module.exports = { connectToDatabase: connectToDatabase, sequelize: sequelize, syncDatabase: syncDatabase };