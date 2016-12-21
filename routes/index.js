var express = require('express');
var router = express.Router();

var passport	= require('passport');
var config    = require('../config/database'); // get db config file
var jwt       = require('jwt-simple');
var User      = require('../app/models/user'); // get the mongoose model

/* GET home page. */
router.get('/', function(req, res, next) {
  res.render('index', { title: 'Express' });
});

router.get('/test', function(req, res) {
    res.send('TEST - *** ROUTE ***');
});

router.post('/signup', function(req, res) {
  if (!req.body.username || !req.body.password) {
    res.json({success: false, msg: 'Please pass name and password.'});
  } else {

    var newUser = new User({
      firstname: req.body.firstName,
      lastname: req.body.lastName,
      username: req.body.username,
      password: req.body.password
    });

    // save the user
    newUser.save(function(err) {
      if (err) {
        return res.json({success: false, msg: 'Username already exists.'});
      }
      res.json({success: true, msg: 'Successful created new user.'});
    });
  }
});

router.post('/authenticate', function(req, res) {
  User.findOne({
    username: req.body.username
  }, function(err, user) {

    if (err) throw err;
 
    if (!user) {
      res.status(401).send({success: false, msg: 'Authentication failed. User not found.'});
    } else {
      // check if password matches
      user.comparePassword(req.body.password, function (err, isMatch) {

        if (isMatch && !err) {
          // if user is found and password is right create a token
          var token = jwt.encode(user, config.secret);
          // return the information including token as JSON
          res.json({success: true, token: 'JWT ' + token});
        } else {
          res.send({success: false, msg: 'Authentication failed. Wrong password.'});
        }
      });
    }
  });
});

getToken = function (headers) {
  if (headers && headers.authorization) {
    var parted = headers.authorization.split(' ');
    if (parted.length === 2) {
      return parted[1];
    } else {
      return null;
    }
  } else {
    return null;
  }
};

// test without jwt
router.get('/userslist', function(req, res) {  
    
    var select = req.query.select;
    User.find({}, function(err, foundData) {
      if(err) {

        res.status(500).send(err);

      } else {
        if(foundData.length == 0) {

           var responseObj = undefined;
           if(select && select == 'count'){
             responseObj = { count: 0 };
           }

           res.status(404).send(responseObj);

        } else {
          var responseObj = foundData;
          if(select && select == 'count') {
            responseObj = { count: foundData.length };
          }

          res.status(200).send(responseObj);
        }
      }

    });

});

router.get('/users', passport.authenticate('jwt', { session: false }), function(req, res) {
  var token = getToken(req.headers);
  if (token) {
    var decoded = jwt.decode(token, config.secret);
    
    var select = req.query.select;
    User.find({}, function(err, foundData) {
      if(err) {
        res.status(500).send(err);
      } else {
        if(foundData.length == 0) {

           var responseObj = undefined;
           if(select && select == 'count'){
             responseObj = { count: 0 };
           }

           res.status(404).send(responseObj);
        } else {

          var responseObj = foundData;
          if(select && select == 'count') {
            responseObj = { count: foundData.length };
          }

          res.status(200).send(responseObj);
        }
      }

    });

  } else {
    return res.status(403).send({success: false, msg: 'No token provided.'});
  }

});

router.get('/memberinfo', passport.authenticate('jwt', { session: false }), function(req, res) {
  var token = getToken(req.headers);
  if (token) {
    var decoded = jwt.decode(token, config.secret);
    User.findOne({
      username: decoded.username
    }, function(err, user) {
        if (err) throw err;
 
        if (!user) {
          return res.status(403).send({success: false, msg: 'Authentication failed. User not found.'});
        } else {
          res.json({success: true, msg: 'Welcome in the member area ' + user.name + '!'});
        }
    });
  } else {
    return res.status(403).send({success: false, msg: 'No token provided.'});
  }
});
 
module.exports = router;
