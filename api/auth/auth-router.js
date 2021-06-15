const router = require("express").Router();
const { checkUsernameExists, validateRoleName } = require('./auth-middleware');
const { JWT_SECRET } = require("../secrets"); // use this secret!
const Users = require('../users/users-model');
const bcrypt = require('bcryptjs');

router.post("/register", validateRoleName, (req, res, next) => {
  const { username, password, role_name } = req.body;
  const hash = bcrypt.hashSync(password, 8)

  Users.add({ username, password: hash, role_name })
    .then(newUser => {
        res.status(201).json(newUser);
    })
    .catch(next)
});


router.post("/login", checkUsernameExists, (req, res, next) => {
  // this code was given... ok to comment out??
  // Users.findBy(req.body)
  //   .then(user => {
  //     console.log(user);
  //   }) 
  //   .catch(next)
  
  res.status(200).json({
    message: `${req.user.username} is back!`,
    token: 'unknown'
  });
  /**
    [POST] /api/auth/login { "username": "sue", "password": "1234" }

    response:
    status 200
    {
      "message": "sue is back!",
      "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.ETC.ETC"
    }

    The token must expire in one day, and must provide the following information
    in its payload:

    {
      "subject"  : 1       // the user_id of the authenticated user
      "username" : "bob"   // the username of the authenticated user
      "role_name": "admin" // the role of the authenticated user
    }
   */
});

module.exports = router;
