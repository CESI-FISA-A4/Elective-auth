// User.js
const { DataTypes } = require('sequelize');
const { sequelize } = require('../utils/initDB');
const Role = require('./Role');

const User = sequelize.define('User', {
    username: {
        type: DataTypes.STRING,
        allowNull: false
    },
    password: {
        type: DataTypes.STRING,
        allowNull: false
    },
    firstname: {
        type: DataTypes.STRING,
        allowNull: false
    },
    lastname: {
        type: DataTypes.STRING,
        allowNull: false
    },
    refreshToken: {
        type: DataTypes.STRING,
        allowNull: true
    },
    roleId: {
        type: DataTypes.INTEGER,
        allowNull: false
    },
    mentorId: {
        type: DataTypes.INTEGER,
        allowNull: true
    }
});

User.belongsTo(User, { as: 'mentor', foreignKey: 'mentorId' });
User.belongsTo(Role, { as: 'role', foreignKey: 'roleId' });


module.exports = User;