// =======================
// get the packages we need ============
// =======================
var fs          = require('fs');
var jwt         = require('jsonwebtoken'); // used to create, sign, and verify tokens
var jwkToPem = require('jwk-to-pem'); //generate public keys
var loki        = require('lokijs');
var rand        = require('randomstring');
var https       = require('https');
var axiosx       = require('axios');
var cookieSession = require('cookie-session')

const axios = axiosx.create({});
var morgan      = require('morgan');
var uuidv1      = require('uuid/v1');
var express     = require('express');
var bodyParser  = require('body-parser');
//const util = require('util');
var crypto = require('crypto');
const utf8 = require('utf8');
var nunjucks = require('nunjucks');
var config      = require('./config'); // get our config file
var app         = express();

const iface = '0.0.0.0';
const NDI_URL = config.ndi_hss_endpoint;
const REDIRECT_URL = 'https://localhost:3000/sign/response';

nunjucks.configure('views', {
    autoescape: true,
    express: app
});

app.use(cookieSession({
  name: 'session',
  keys: ['key1', 'key2']
}));
// =======================
// in-memory db =========
// =======================
var db = new loki('db.json');
var userRecords = [
    { name: 'Thor', password: 'password', admin: 'true'}, 
    { name: 'Loki', password: 'password', admin: 'false'}
];
var users = db.addCollection('users');
var results = users.insert(userRecords);

// =======================
// configuration =========
// =======================
var port = process.env.PORT || 3000; // used to create, sign, and verify tokens
var path = __dirname + '/views/';
app.use(express.static('assets'));
app.set('superSecret', config.secret); // secret variable

// use body parser so we can get info from POST and/or URL parameters
app.use(bodyParser.urlencoded({ extended: false }));
app.use(bodyParser.json());

// use morgan to log requests to the console
app.use(morgan('dev'));

// setup axios for cors
const agent = new https.Agent({  
    rejectUnauthorized: false
});
const axiosConfig = {
    httpsAgent: agent,
    headers: {
        'Content-Type': 'application/json;charset=UTF-8',
        "Access-Control-Allow-Origin": "*",
    }    
};

// =======================
// routes ================
// =======================
// basic route
app.get('/', function(req, res) {
    res.writeHead(301, { Location: '/sign-in-ndi' });
    res.end();
    // res.send(`Hello! The API is at http://localhost:${port}/api`);
    //res.sendFile(path + "index.html");
});


app.get('/sign', function(req, res) {
    if (!req.session.ndiId || req.session.ndiId == '') {
    //res.status(400).json({ "message": "invalid parameters given" });
    res.writeHead(301, { Location: '/sign-in-ndi' });
    res.end();
  } else {
    let data = {
        ndiId: req.session.ndiId,
    } ;
    return res.render(path + "signdoc.html", data ) ;
    //res.sendFile(path + "signdoc.html");
  }
});

app.post('/sign', (req, res) => {
//console.log("Session: %j", req.body);
//console.log(req.session.ndiId + req.body.message);
  if (!req.body.csrf || req.session.ndiId == '') {
    //res.status(400).json({ "message": "invalid parameters given" });
    res.writeHead(301, { Location: '/sign-in-ndi' });
    res.end();
  }

    if(!req.body.message || req.body.message == ''){
        let data = {
        result: "The message field was empty.",
        status: "Invalid input",
        reason: ''
    } ;
    return res.render(path + "signerror.html", data ) ;
    }
    //let hash = '';
    //sha256(req.body.message);
    
  const message = req.body.message;
  const hash = crypto.createHash('sha256').update(req.body.message).digest('hex').toUpperCase();
  const ndiId = req.session.ndiId;
  const date = new Date((Date.now() + 300000)).toJSON();
  const nonce = Date.now().toString();
  const vcode = Date.now().toString();
   // console.log(hash);

  // Make request to NDI API

  let body = {
    "client_id": config.ndi_client_id,
    "client_secret": config.ndi_client_secret,
    "nonce": nonce,
    "hash_alg": "sha256",
    "hash": hash,
    "login_hint": ndiId,
    "redirect_uri": REDIRECT_URL, //REDIRECT_URL
    "scope": "signHash",
    "response_type": "json",
    "tx_id": "1",
    "tx_expiry": date,
    "tx_doc_name": message,
    "tx_vcode": vcode
  }

 // console.log(body);

  axios.post(NDI_URL + '/signatures/signHash', body)
    .then((response) => {
      // console.log(response);
      if (response.status === 200 && response.data.usr_action != 'reject') {
          //change this
        //res.send(response.data);
          var data = {
              result: response.data['signedData']['signedHash'],
              status: "Success",
              content: message
          };
          return res.render(path + "signresult.html", data ) ;
      } else {
        return Promise.reject(response)
      }
    })
    .catch((err) => {
      //console.log(err);
      let data = {
        result: JSON.stringify(err.data),
        status: "Failed",
        reason: "The user declined the request"
    } ;
    return res.render(path + "signerror.html", data ) ;
      //res.status(500).send("error");
    });
});


app.get('/sign-in-ndi', function(req, res) {
    res.sendFile(path + "sign-in-ndi.html");
});
function delay(t) {
    return new Promise(function(resolve) {
        setTimeout(resolve, t);
    });
}
function generateCert(kid) {
   // let cert = 0;
    return new Promise((resolve, reject) => {
   // console.log("downloading jwk...");
                https.get(config.ndi_asp_endpoint + '/certs', (resp) => {
                    let data = '';
                    resp.on('data', (chunk) => {
                        data += chunk;
                    });

                    // The whole response has been received. Print out the result.
                    resp.on('end', () => {
                        //console.log(JSON.parse(data)["keys"]["0"]);
                        //let jwk = JSON.parse(data);
                        //let certs = jwkToPem(JSON.parse(data)["keys"]);
                        let certs = JSON.parse(data)["keys"];
                        for(const index in certs){
                            if(certs[index].kid != kid){continue;}
                            cert = certs[index];
                            cert = jwkToPem(cert);
                        }
                      //  console.log(cert);
                        resolve(cert);
                    });
                }).on("error", (err) => {
                    console.log("Cert Error: " + err.message);
                    reject(err);
                });
    });
   // if(cert){return cert;}
}
function poller(url, data, interval, timeout) {
    let start = Date.now();
    function run() {
        return axios.post(url, data, axiosConfig)
        .then(function(response){
                return response.data;
        })
        .catch(function(error){
            // when error is not "authorization_pending", stop polling
            if(error.response && error.response.status === 400 && error.response.data) {
                if (!error.response.data.error.includes("authorization_pending")) {
                    throw error; // stop polling due to unexpected error
                } else {
                   // console.log(error.response.data);
                    if (timeout !== 0 && Date.now() - start > timeout) {
                        throw new Error("polling ended due to timeout");
                    } else {
                        // run again with a short delay
                        return delay(interval).then(run);
                    }
                }
            } else {
               // console.log(error);
                throw error;
            }
        });
    }
    return run();
}
function atob(b64){
    let b = Buffer.from(b64, 'base64');
    return b.toString();
}

app.post('/sign-in-ndi', function(req, res) {
    let baseURL = config.ndi_asp_endpoint;
    let notifToken = rand.generate({ length: 16, charset: 'alphanumeric'});

    let authRequest = {
        client_id : config.ndi_client_id,
        client_secret : config.ndi_client_secret,
        scope: 'openid',
        client_notification_token: notifToken, //unused
        acr_values: 'mod-mf',
        login_hint: req.body.name, //server musrt remember!!
        binding_message: 'Click me to login',
        redirect_uri : '',
        nonce: uuidv1(),
        //nonce: 'mynonce'
    };
    
    var ndiid = req.body.name;
    axios.post(config.ndi_asp_endpoint + '/di-auth', authRequest, axiosConfig)
        .then(function (response) {
         //   console.log(response.data);
            // obtain request attributes for polling
            authRequest.auth_req_id = response.data.auth_req_id;
            authRequest.expires_in = response.data.expires_in;

            let authStatusRequest = { 
                client_id : config.ndi_client_id, 
                client_secret : config.ndi_client_secret,
                code: response.data.auth_req_id.split(':')[1],
                auth_req_id: response.data.auth_req_id,
                grant_type: 'direct_invocation_request'
            };
         //var cert = fs.readFileSync('./ndi-asp-public.pem'); //fallback
                
                
                
            // poller(url, data, interval, timeout, retries)
            poller(config.ndi_asp_endpoint + '/token', authStatusRequest, 1000, 60 * 1000)
                .then(function(status){  
                // console.log("Polling ended");
               //  console.log(status);
                //var cert = fs.readFileSync('./ndi-asp-public.pem');
                //console.log(atob(status.id_token.split('.')[0]));
                let kid = JSON.parse(atob(status.id_token.split('.')[0])).kid;
            //    console.log('kid: ' + kid);
                
                let cert = generateCert(kid); //blocking fn 
                cert.then(result => {
                jwt.verify(status.id_token, result, function(err, decoded) {      
                            if (err) {
                                console.log(err);
                                return res.json({ success: false, message: 'Public key check failed!', response_code: 200 });    
                            } else {
                                // if everything is good, save to request for use in other routes
                                req.decoded = decoded;
                                /*return res.json({ success: true, message: 'Login complete with signature verified.',
                                response: status, id: ndiid, response_code: 200 }); */
                                req.session.ndiId = ndiid;
                                res.writeHead(301, { Location: '/sign' });
                                res.end();
                            }
                })
                });
                
                
                
                
                
                 //res.json({success: true, message: 'Authenticated by NDI', status: status});
             }, function(err){
                //void(0);
                throw err;
            })
            
             .catch(function(err){
                 //console.log(err);
                 //res.json({success: false, message: 'Rejection error', error: err.message, response_code: 400});
                 let data = {
        result: 'User cancelled the operation',
        status: "Failed to Login",
        reason: ''
    } ;
    return res.render(path + "signerror.html", data ) ;
             });
        })
        .catch(function (error) {
            console.log(`Connection error: `);
            console.log(error);
            res.json({success: false, message: 'Unable to connect to NDI', error: error.data, response_code: 500});
        });  
});

app.use("*",function(req,res){
    res.sendFile(path + "404.html");
});

// =======================
// start the server ======
// =======================
app.listen(port, iface);
console.log(`service running at http://${iface}:${port}`);
