var express = require('express');
var router = express.Router();

router.get('/', function (req, res, next) {
  res.render('index', { title: 'Express' });
});

router.get('/vuln/:exp', function(req, res){
  res.send("The answer is :" + eval(req.params.exp));
});

module.exports = router;
