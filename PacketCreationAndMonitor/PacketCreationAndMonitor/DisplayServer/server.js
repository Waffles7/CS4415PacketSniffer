var http = require('http');
var myCount = 0;

//create server object
http.createServer(function(req, res) {
  myCount++;
  res.write(JSON.stringify({
    message: "Wassup",
    count: myCount
  }));
  res.end();
}).listen(8080);
