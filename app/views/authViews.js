var bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const User = require('../models/User');
const Role = require('../models/Role');

// Secret key for JWT
const secretKey = process.env.JWT_SIGN_SECRET;

module.exports = {
    registerView: async(req, res) => {
        try {
            const { username, password, firstname, lastname, roleLabel, address } = req.body;
            if (!username || !password || !firstname || !lastname || !roleLabel || !address) return res.status(400).send('Username, password, firstname, lastname, roleLabel and address required');

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

            let isRoleAllowed = ["deliveryman", "developer", "restaurantOwner", "user", "technician", "salesman"].find((roleAllowed) => roleAllowed == roleFound.label);

            if(!isRoleAllowed) return res.status(403).send('Role forbidden');

            const hashedPassword = await bcrypt.hash(password, 10);

            await User.create({
                username,
                firstname,
                lastname,
                password: hashedPassword,
                roleId: roleFound.id,
                address
            });

            res.status(201).send('User created successfully');
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

            const accessToken = jwt.sign({ username: user.username, userId: user.id, roleLabel: userRole.label }, process.env.JWT_SIGN_SECRET, { expiresIn: 3600 });
            const refreshToken = jwt.sign({ username: user.username, userId: user.id, roleLabel: userRole.label }, process.env.REFRESH_TOKEN_KEY, { expiresIn: "7d" });

            user.refreshToken = refreshToken;
            await user.save();

            res.status(200).json({ accessToken, refreshToken, userId: user.id, roleLabel: userRole.label });
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

            res.status(200).send('Password successfully changed!');
        } catch (error) {
            console.log(error);
            return res.status(500).json({ "error": "internal error" });
        }
    },

    refreshToken: (req, res) => {
        const refreshToken = req.body.refreshToken;

        if (!refreshToken) return res.status(401).json({ message: "Invalid refresh token" });

        jwt.verify(refreshToken, process.env.REFRESH_TOKEN_KEY, (err, decoded) => {
            if (err) {
                return res.status(401).json({ message: "Invalid refresh token" });
            } else {
                const accessToken = jwt.sign({ username: decoded.username, userId: decoded.userId, roleLabel: decoded.roleLabel }, process.env.JWT_SIGN_SECRET, { expiresIn: 3600 });
                return res.status(200).json({ accessToken });
            }
        });
    },

    verifyTokenView: (req, res) => {
        try {
            let token = req.headers['Authorization'] || req.headers['authorization'];

            if (!token) return res.status(401).send('Token not found');
            
            if (token.startsWith("Bearer ")) token = token.slice(7);
            
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