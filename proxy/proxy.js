const fs = require('fs');
const httpProxy = require('http-proxy');

//
// Create the HTTPS proxy server listening on port 8000
//
httpProxy
  .createServer({
    target: {
      host: '127.0.0.1',
      port: 8084,
    },
    ssl: {
      key: fs.readFileSync(process.env['DP_HTTPS_KEY'], 'utf8'),
      cert: fs.readFileSync(process.env['DP_HTTPS_CERT'], 'utf8'),
    },
  })
  .listen(443);
