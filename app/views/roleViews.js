const { Sequelize } = require('sequelize');
const Role = require('../models/Role');

module.exports = {
    getAllRoles: async(req, res) => {
        try {
            const roles = await Role.findAll({
                where: {
                    label: {
                        [Sequelize.Op.not]: 'admin' // Utilisation de Sequelize.Op.not pour la négation
                    }
                }
            });
            return res.status(200).send(roles);
        } catch (error) {
            return res.status(500).json({ "error": "internal error" });
        }
    }
}