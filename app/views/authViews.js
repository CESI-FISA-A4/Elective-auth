var bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const User = require('../models/User');
const Role = require('../models/Role');

// Secret key for JWT
const secretKey = process.env.JWT_SIGN_SECRET;

module.exports = {
    registerView: async(req, res) => {
        try {
            const { username, password, roleLabel } = req.body;
            if (!username || !password || !roleLabel) return res.status(400).send('Username, password and role required');

            const user = await User.findOne({
                where: {
                    ["username"]: username
                }
            });

            if (user) return res.status(400).send('User already exists');

            const roleFound = await Role.findOne({
                where: {
                    ["label"]: roleLabel
                }
            });

            if (!roleFound) return res.status(400).send('Wrong role');

            const hashedPassword = await bcrypt.hash(password, 10);

            await User.create({
                username,
                password: hashedPassword,
                roleId: roleFound.id
            });

            res.status(200).send('User created successfuly');
        } catch (error) {
            console.log(error);
            return res.status(500).json({ "error": "internal error" });
        }
    },

    loginView: async(req, res) => {
        try {
            const { username, password } = req.body;
            if (!username || !password) return res.status(400).send('Username and password required');

            const user = await User.findOne({
                where: {
                    ["username"]: username
                }
            });
            if (!user) return res.status(401).send('User not found');

            const validPassword = await bcrypt.compare(password, user.password); // Comparaison des hashs
            if (!validPassword) return res.status(401).send('Wrong password');

            const userRole = await user.getRole();

            const token = jwt.sign({ userID: user.id, role: userRole.label }, secretKey, { expiresIn: '1h' });
            res.status(200).json({ token });
        } catch (error) {
            console.log(error);
            return res.status(500).json({ "error": "internal error" });
        }
    },

    changePasswordView: async(req, res) => {
        try {
            const { username, password, newPassword } = req.body;
            if (!username || !password || !newPassword) return res.status(400).send('Username, old password and new password required');

            const user = await User.findOne({
                where: {
                    ["username"]: username
                }
            });
            if (!user) return res.status(401).send('User not found');

            const validPassword = await bcrypt.compare(password, user.password); // Comparaison des hashs
            if (!validPassword) return res.status(401).send('Wrong password');

            const hashedNewPassword = await bcrypt.hash(newPassword, 10); // Hash du nouveau mot de passe reçu

            await user.update({
                ["password"]: hashedNewPassword
            });

            res.status(200).send('Password successfuly changed!');
        } catch (error) {
            console.log(error);
            return res.status(500).json({ "error": "internal error" });
        }
    },

    verifyTokenView: (req, res) => {
        try {
            const token = req.headers['Authorization'] || req.headers['authorization'];

            if (!token) return res.status(401).send('Token not found');

            jwt.verify(token, secretKey, (err, decoded) => {
                if (err) return res.status(403).send('Wrong token');
                return res.status(200).json({ "information": "Token decoded", ...decoded });
            });
        } catch (error) {
            console.log(error);
            return res.status(500).json({ "error": "internal error" });
        }
    }
}