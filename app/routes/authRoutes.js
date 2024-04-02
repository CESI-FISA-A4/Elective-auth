// Auth routes
const express = require('express');
const { registerView, loginView, changePasswordView, verifyTokenView, refreshToken } = require('../views/authViews');

const authRoutes = express.Router();

/** -------------------------------------------AUTH Routes--------------------------------------------------- */


authRoutes.post('/register', registerView);
authRoutes.post('/login', loginView);
authRoutes.post('/change-password', changePasswordView);
authRoutes.post('/refresh-token', refreshToken);
authRoutes.post('/verify-token', verifyTokenView);

module.exports = authRoutes;