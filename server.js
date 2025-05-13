// ✅ Serveur avec login sécurisé obligatoire avant formulaire de contact

const express = require('express');
const helmet = require('helmet');
const session = require('express-session');
const bcrypt = require('bcrypt');
const fs = require('fs');
const https = require('https');
const axios = require('axios');
const path = require('path');
const morgan = require('morgan');
const bodyParser = require('body-parser');

const app = express();

// Middleware de sécurité
app.use(helmet({ contentSecurityPolicy: false }));
app.use(bodyParser.urlencoded({ extended: true }));

// Servez uniquement les fichiers login.html, CSS, JS, etc.
app.use(express.static(path.join(__dirname, '../public'), {
  index: false // Empêche Express de servir automatiquement index.html
}));

// Sessions sécurisées
app.use(session({
  secret: 'monsecret',
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    secure: true
  }
}));

// Journalisation
const accessLogStream = fs.createWriteStream(path.join(__dirname, '../logs/access.log'), { flags: 'a' });
app.use(morgan('combined', { stream: accessLogStream }));

// Création utilisateur fictif unique à l'avance
const USERS = [];
(async () => {
  USERS.push({
    email: 'admin@test.com',
    password: await bcrypt.hash('admin123', 10)
  });
})();

// Middleware pour vérifier authentification
function isAuthenticated(req, res, next) {
  if (req.session.user) return next();
  res.redirect('/login.html');
}

// Redirection initiale vers login
app.get('/', (req, res) => {
  res.redirect('/login.html');
});

// Connexion
app.post('/login', async (req, res) => {
  const { email, password } = req.body;
  const user = USERS.find(u => u.email === email);

  if (user && await bcrypt.compare(password, user.password)) {
    req.session.user = { email };
    return res.redirect('/formulaire');
  }
  res.status(401).send('Email ou mot de passe invalide');
});

// Déconnexion
app.get('/logout', (req, res) => {
  req.session.destroy(() => {
    res.redirect('/login.html');
  });
});

// Route protégée pour formulaire
app.get('/formulaire', isAuthenticated, (req, res) => {
  res.sendFile(path.join(__dirname, '../public/index.html'));
});

// Soumission protégée du formulaire
app.post('/submit', isAuthenticated, async (req, res) => {
  const { name, email, message, 'g-recaptcha-response': captcha } = req.body;

  if (!captcha) {
    return res.status(400).send('Captcha manquant');
  }

  const secretKey = '6LeOmTYrAAAAAKKxSo1ughI6OatfCTrGxvdhaREb';
  const verifyUrl = `https://www.google.com/recaptcha/api/siteverify?secret=${secretKey}&response=${captcha}`;

  try {
    const response = await axios.post(verifyUrl);
    if (!response.data.success) {
      return res.status(403).send('Captcha invalide');
    }

    const hashedEmail = await bcrypt.hash(email, 10);
    const encryptedMsg = Buffer.from(message).toString('base64');

    fs.appendFileSync('./logs/access.log', `Nom: ${name} - Email: ${hashedEmail}\n`);
    res.send('Message reçu et sécurisé.');
  } catch (err) {
    console.error("Erreur lors de la vérification du captcha :", err);
    res.status(500).send('Erreur serveur');
  }
});

// HTTPS Server
const sslOptions = {
  key: fs.readFileSync(path.join(__dirname, '../config/ssl/key.pem')),
  cert: fs.readFileSync(path.join(__dirname, '../config/ssl/cert.pem'))
};

https.createServer(sslOptions, app).listen(3000, '127.0.0.1', () => {
  console.log('✅ Serveur HTTPS démarré sur https://127.0.0.1:3000');
});
