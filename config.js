const express = require("express");
const fs = require("fs");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");

const secret = 'my-secret-key';
const tokenExpiration = '15m'; // Tiempo de expiración del token: 15 minutos

const app = express();
app.use(express.json());

const usersFilePath = 'users.json';

const readUsersFromFile = () => {
  try {
    const data = fs.readFileSync(usersFilePath, 'utf8');
    return JSON.parse(data) || [];
  } catch (error) {
    return [];
  }
};

const writeUsersToFile = (users) => {
  fs.writeFileSync(usersFilePath, JSON.stringify(users, null, 2), 'utf8');
};

const generateToken = (user) => {
  return jwt.sign({
    id: user.id,
    name: user.name,
  }, secret, { expiresIn: tokenExpiration });
};

const verifyToken = (token) => {
  try {
    const decoded = jwt.verify(token, secret);
    return decoded;
  } catch (error) {
    return null;
  }
};

app.use(function (req, res, next) {
  res.header('Access-Control-Allow-Origin', '*');
  res.header('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  next();
});

app.post('/api/users/register', async (req, res) => {
  const { name, email, password } = req.body;
  const users = readUsersFromFile();

  const existingUser = users.find((user) => user.email === email);
  if (existingUser) {
    return res.status(400).send({ message: 'El usuario ya existe' });
  }

  const hashedPassword = bcrypt.hashSync(password, 10);
  const newUser = { id: Date.now().toString(), name, email, password: hashedPassword };

  users.push(newUser);
  writeUsersToFile(users);

  res.status(201).send({
    message: 'Usuario creado correctamente',
    user: newUser,
  });
});

app.post('/api/users/login', async (req, res) => {
  const { email, password } = req.body;
  const users = readUsersFromFile();

  const user = users.find((user) => user.email === email);

  if (!user) {
    return res.status(404).send({ message: 'Usuario no encontrado' });
  }

  const isPasswordValid = bcrypt.compareSync(password, user.password);

  if (!isPasswordValid) {
    return res.status(401).send({ message: 'Contraseña incorrecta' });
  }

  const token = generateToken(user);

  res.status(200).send({
    message: 'Inicio de sesión correcto',
    token,
    user
  });
});

app.post('/api/users/logout', (req, res) => {
  const token = req.header('Authorization');

  if (!token) {
    return res.status(401).send({ message: 'Token no proporcionado' });
  }

  const decoded = verifyToken(token.replace('Bearer ', ''));

  if (!decoded) {
    return res.status(401).send({ message: 'Token inválido' });
  }

  // Eliminar el token de la sesión
  // Puedes ajustar la lógica según cómo estás manejando los usuarios y tokens
  res.status(200).send({ message: 'Cierre de sesión exitoso' });
});

app.get('/api/users', async (req, res) => {
  const token = req.header('Authorization');

  if (!token) {
    return res.status(401).send({ message: 'Token no proporcionado' });
  }

  const decoded = verifyToken(token.replace('Bearer ', ''));

  if (!decoded) {
    return res.status(401).send({ message: 'Token inválido' });
  }

  const users = readUsersFromFile();

  res.send(users);
});

// Nueva ruta para buscar usuarios por email
app.get('/api/users/:email', (req, res) => {
  const { email } = req.params;
  const users = readUsersFromFile();

  const user = users.find((user) => user.email === email);

  if (!user) {
    return res.status(404).send({ message: 'Usuario no encontrado' });
  }

  res.send(user);
});

// Nueva ruta para buscar usuarios por ID
app.get('/api/users/id/:id', (req, res) => {
  const { id } = req.params;
  const users = readUsersFromFile();

  const user = users.find((user) => user.id === id);

  if (!user) {
    return res.status(404).send({ message: 'Usuario no encontrado' });
  }

  res.send(user);
});

app.listen(3000, () => console.log('API escuchando en el puerto 3000'));