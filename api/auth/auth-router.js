const router = require("express").Router();
const { checkUsernameExists, validateRoleName } = require('./auth-middleware');
const { JWT_SECRET } = require("../secrets"); // use this secret!
const Users = require('../users/users-model');
const bcrypt = require('bcryptjs');

router.post("/register", validateRoleName, (req, res, next) => {
  const { username, password } = req.body;
  const { role_name } = req; 
  const hash = bcrypt.hashSync(password, 8)

  Users.add({ username, password: hash, role_name })
    .then(newUser => {
        res.status(201).json(newUser);
    })
    .catch(next)
});


router.post("/login", checkUsernameExists, (req, res, next) => {
  res.status(200).json({
    message: `${req.user.username} is back!`,
    token: req.token
  });
});

module.exports = router;
