 const { JWT_SECRET } = require("../secrets"); // use this secret!
const Users = require('../users/users-model');
const jwt = require('jsonwebtoken');


const restricted = (req, res, next) => {
  const token = req.headers.authorization;
  if (token) {
    jwt.verify(token, JWT_SECRET, (err, decoded) => {
      if (err) {
        res.status(401).json({ message: 'Token invalid' })
      } else {
        req.decodedJwt = decoded;
        next()
      }
    })
  } else {
    res.status(401).json({ message: 'Token required' });
  }
  /*
    If the user does not provide a token in the Authorization header:
    status 401
    {
      "message": "Token required"
    }

    If the provided token does not verify:
    status 401
    {
      "message": "Token invalid"
    }

    Put the decoded token in the req object, to make life easier for middlewares downstream!
  */
}

const only = role_name => (req, res, next) => { // this is a middleware builder
  if (role_name === req.decodedJwt.role_name) {
    next()
  } else {
    next({
      status: 403,
      message: 'This is not for you'
    })
  }

  /*
    If the user does not provide a token in the Authorization header with a role_name
    inside its payload matching the role_name passed to this function as its argument:
    status 403
    {
      "message": "This is not for you"
    }

    Pull the decoded token from the req object, to avoid verifying it again!
  */
}


const checkUsernameExists = async (req, res, next) => {
  try {
    const { username } = req.body;
    const user = await Users.findBy({ username })
    if (!user) {
      next({
        status: 401,
        message: 'Invalid credentials'
      })
    } else {
      req.user = user
      next()
    }
  } catch (err) {
    next(err)
  }
}


const validateRoleName = (req, res, next) => {
  const { role_name } = req.body;
  if (!role_name || role_name.trim() === '') { // solution: !role_name.trim()
    req.role_name = 'student' // solution: req.role_name
    next()
  } else if (role_name.trim() === 'admin') {
    next({
      status: 422,
      message: 'Role name can not be admin'
    })
  } else if (role_name.trim().length > 32) {
    res.status(422).json({ message: 'Role name can not be longer than 32 chars' })
  } else if (role_name.trim()) {
    req.role_name = role_name.trim()
    next()
  }
}

module.exports = {
  restricted,
  checkUsernameExists,
  validateRoleName,
  only,
}
