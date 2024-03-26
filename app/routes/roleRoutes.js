// Auth routes
const express = require('express');
const { getAllRoles } = require('../views/roleViews');

const roleRouter = express.Router();

/** -------------------------------------------Role Routes--------------------------------------------------- */
roleRouter.get('/', getAllRoles);


module.exports = roleRouter;