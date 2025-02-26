// Fișier: server.js (Node.js cu Express)
const express = require('express');
const bodyParser = require('body-parser');
const session = require('express-session');
const crypto = require('crypto');
const qrcode = require('qrcode');
const { authenticator } = require('otplib');

const app = express();

// Middleware
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());
app.use(session({
  secret: 'secret-key-change-in-production',
  resave: false,
  saveUninitialized: true,
  cookie: { secure: false } // setează true în producție cu HTTPS
}));

// Bază de date simulată pentru utilizatori
const users = {};

// Endpoint pentru înregistrare
app.post('/register', (req, res) => {
  const { username, password } = req.body;
  
  if (users[username]) {
    return res.status(400).json({ error: 'Utilizator deja existent' });
  }
  
  // Generarea secretului pentru MFA
  const secret = authenticator.generateSecret();
  
  // Stocarea utilizatorului
  users[username] = {
    password: hashPassword(password), // În producție folosește bcrypt
    mfaSecret: secret,
    mfaEnabled: false
  };
  
  // Generarea URL-ului pentru QR code
  const otpauth = authenticator.keyuri(username, 'MeuSait', secret);
  
  // Salvare în sesiune pentru următorul pas
  req.session.registeringUser = username;
  
  // Returnarea secretului și QR code-ului
  qrcode.toDataURL(otpauth, (err, imageUrl) => {
    if (err) {
      return res.status(500).json({ error: 'Eroare la generarea QR code' });
    }
    res.json({ 
      secret: secret,
      qrCode: imageUrl,
      message: 'Scanează codul QR cu aplicația Single ID Authenticator și introdu codul generat pentru verificare'
    });
  });
});

// Endpoint pentru verificarea codului MFA la înregistrare
app.post('/verify-setup', (req, res) => {
  const { token } = req.body;
  const username = req.session.registeringUser;
  
  if (!username || !users[username]) {
    return res.status(400).json({ error: 'Sesiune invalidă' });
  }
  
  const secret = users[username].mfaSecret;
  
  // Verificarea tokenului
  const isValid = authenticator.verify({ token, secret });
  
  if (isValid) {
    // Activarea MFA pentru utilizator
    users[username].mfaEnabled = true;
    req.session.registeringUser = null;
    
    res.json({ success: true, message: 'Autentificarea în doi pași a fost activată cu succes' });
  } else {
    res.status(400).json({ error: 'Cod invalid. Încearcă din nou.' });
  }
});

// Endpoint pentru prima etapă de autentificare
app.post('/login', (req, res) => {
  const { username, password } = req.body;
  
  // Verificare utilizator
  if (!users[username] || users[username].password !== hashPassword(password)) {
    return res.status(401).json({ error: 'Credențiale invalide' });
  }
  
  // Dacă utilizatorul are MFA activat
  if (users[username].mfaEnabled) {
    // Salvăm utilizatorul în sesiune pentru a doua etapă
    req.session.pendingUser = username;
    return res.json({ 
      requireMFA: true, 
      message: 'Te rugăm să introduci codul din aplicația Single ID Authenticator' 
    });
  }
  
  // Dacă MFA nu este activat, utilizatorul este autentificat direct
  req.session.user = username;
  res.json({ success: true, message: 'Autentificare reușită' });
});

// Endpoint pentru a doua etapă de autentificare (MFA)
app.post('/verify-login', (req, res) => {
  const { token } = req.body;
  const username = req.session.pendingUser;
  
  if (!username) {
    return res.status(400).json({ error: 'Sesiune invalidă. Te rugăm să te autentifici din nou.' });
  }
  
  const secret = users[username].mfaSecret;
  
  // Verificarea tokenului
  const isValid = authenticator.verify({ token, secret });
  
  if (isValid) {
    // Autentificare completă
    req.session.user = username;
    req.session.pendingUser = null;
    
    res.json({ success: true, message: 'Autentificare completă reușită' });
  } else {
    res.status(401).json({ error: 'Cod invalid. Încearcă din nou.' });
  }
});

// Funcție simplă pentru hashing parole (pentru demonstrație)
function hashPassword(password) {
  return crypto.createHash('sha256').update(password).digest('hex');
}

// Endpoint protejat care necesită autentificare
app.get('/profile', (req, res) => {
  if (!req.session.user) {
    return res.status(401).json({ error: 'Acces neautorizat' });
  }
  
  res.json({ username: req.session.user, message: 'Date protejate accesate cu succes' });
});

// Endpoint pentru deconectare
app.post('/logout', (req, res) => {
  req.session.destroy();
  res.json({ success: true, message: 'Deconectare reușită' });
});

// Pornirea serverului
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Serverul rulează pe portul ${PORT}`);
});
