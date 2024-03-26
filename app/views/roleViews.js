const Role = require('../models/Role');

module.exports = {
    getAllRoles: async(req, res) => {
        try {
            const roles = await Role.findAll();
            return res.status(200).send(roles);
        } catch (error) {
            return res.status(500).json({ "error": "internal error" });
        }
    }
}