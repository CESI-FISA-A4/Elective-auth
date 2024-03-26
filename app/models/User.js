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
    }
});

User.belongsTo(Role, { as: "role" });


module.exports = User;