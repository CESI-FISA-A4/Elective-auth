// Role.js
const { DataTypes } = require('sequelize');
const { sequelize } = require('../utils/initDB');

const Role = sequelize.define('Role', {
    label: {
        type: DataTypes.STRING,
        allowNull: false,
        unique: true
    }
}, {
    timestamps: false,
});

module.exports = Role;