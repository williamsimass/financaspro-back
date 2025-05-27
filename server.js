require("dotenv").config();
const express = require("express");
const { MongoClient, ServerApiVersion, ObjectId } = require("mongodb");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const cors = require("cors");

const app = express();
const port = process.env.PORT || 3000;
const jwtSecret = process.env.JWT_SECRET;

// Middleware
app.use(cors());
app.use(express.json());

// Conexão com MongoDB
const uri = process.env.MONGODB_URI;
const client = new MongoClient(uri, {
  serverApi: {
    version: ServerApiVersion.v1,
    strict: true,
    deprecationErrors: true,
  }
});

let db;

async function connectDB() {
  try {
    await client.connect();
    db = client.db("financaspro");
    console.log("Conectado ao MongoDB!");
    await db.command({ "ping": 1 });
    console.log("Ping ao banco de dados 'financaspro' bem-sucedido.");

    // Criar índice único para username e email para evitar duplicatas
    const usersCollection = db.collection("users");
    await usersCollection.createIndex({ username: 1 }, { unique: true });
    await usersCollection.createIndex({ email: 1 }, { unique: true });
    console.log("Índices únicos para username e email garantidos.");

  } catch (err) {
    if (err.code === 85 || err.code === 86) { // IndexOptionsConflict or IndexKeySpecsConflict
        console.log("Índices já existem ou conflito na criação, continuando...");
    } else {
        console.error("Falha ao conectar ou criar índices no MongoDB:", err);
        process.exit(1);
    }
  }
}

// Middleware de autenticação
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];

  if (token == null) return res.sendStatus(401);

  jwt.verify(token, jwtSecret, (err, user) => {
    if (err) {
        console.log("Erro na verificação do token:", err.message);
        return res.sendStatus(403);
    }
    req.user = user;
    next();
  });
};


// --- Rotas de Autenticação ---

// Rota de Registro (Atualizada com novos campos)
app.post("/api/auth/register", async (req, res) => {
  const { firstName, lastName, username, email, password } = req.body;

  // Validação básica
  if (!firstName || !lastName || !username || !email || !password) {
    return res.status(400).json({ message: "Todos os campos são obrigatórios: Nome, Sobrenome, Nome de usuário, Email e Senha." });
  }

  // Validação simples de email (pode ser mais robusta)
  if (!/\S+@\S+\.\S+/.test(email)) {
      return res.status(400).json({ message: "Formato de email inválido." });
  }

  try {
    const usersCollection = db.collection("users");

    // Verificar se username ou email já existem (usando $or)
    const existingUser = await usersCollection.findOne({
      $or: [
        { username: username.toLowerCase() },
        { email: email.toLowerCase() }
      ]
    });

    if (existingUser) {
      let message = "Erro no registro.";
      if (existingUser.username === username.toLowerCase()) {
          message = "Nome de usuário já está em uso.";
      } else if (existingUser.email === email.toLowerCase()) {
          message = "Email já está em uso.";
      }
      return res.status(409).json({ message: message });
    }

    // Hash da senha
    const saltRounds = 10;
    const hashedPassword = await bcrypt.hash(password, saltRounds);

    // Inserir novo usuário com todos os campos
    const result = await usersCollection.insertOne({
      firstName: firstName,
      lastName: lastName,
      username: username.toLowerCase(), // Salvar username em minúsculas
      email: email.toLowerCase(), // Salvar email em minúsculas
      password: hashedPassword,
      createdAt: new Date()
    });

    console.log(`Usuário registrado: ${username}, Email: ${email}, ID: ${result.insertedId}`);
    res.status(201).json({ message: "Usuário registrado com sucesso!" });

  } catch (error) {
    console.error("Erro no registro:", error);
    // Verifica erro de chave duplicada (caso o findOne falhe por alguma race condition)
    if (error.code === 11000) {
        let message = "Erro no registro.";
        if (error.keyPattern?.username) {
            message = "Nome de usuário já está em uso.";
        } else if (error.keyPattern?.email) {
            message = "Email já está em uso.";
        }
        return res.status(409).json({ message: message });
    }
    res.status(500).json({ message: "Erro interno do servidor ao registrar usuário." });
  }
});

// Rota de Login (Mantida com username e password)
app.post("/api/auth/login", async (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).json({ message: "Nome de usuário e senha são obrigatórios." });
  }

  try {
    const usersCollection = db.collection("users");
    // Busca pelo username em minúsculas
    const user = await usersCollection.findOne({ username: username.toLowerCase() });

    if (!user) {
      return res.status(401).json({ message: "Credenciais inválidas." });
    }

    // Comparar senha
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(401).json({ message: "Credenciais inválidas." });
    }

    // Gerar token JWT - Incluir ID, username, firstName e lastName no payload
    const payload = {
        userId: user._id,
        username: user.username,
        firstName: user.firstName, // Adicionado para possível uso no frontend
        lastName: user.lastName   // Adicionado para possível uso no frontend
    };
    const token = jwt.sign(payload, jwtSecret, { expiresIn: "1h" }); // Token expira em 1 hora

    console.log(`Usuário logado: ${user.username}`);
    // Retorna o token e dados básicos do usuário
    res.json({ token: token, user: { username: user.username, firstName: user.firstName, lastName: user.lastName } });

  } catch (error) {
    console.error("Erro no login:", error);
    res.status(500).json({ message: "Erro interno do servidor ao fazer login." });
  }
});

// Rota de verificação de token
app.get("/api/auth/verify", authenticateToken, (req, res) => {
  // Retorna os dados do usuário que estão no token
  res.json({ valid: true, user: req.user });
});


// --- Rotas de Transações (Implementação Pendente) ---

// GET /api/transactions - Listar transações do usuário logado
app.get("/api/transactions", authenticateToken, async (req, res) => {
  try {
    const transactionsCollection = db.collection("transactions");
    // Busca transações que pertencem ao userId do token
    const transactions = await transactionsCollection.find({ userId: new ObjectId(req.user.userId) }).sort({ date: -1 }).toArray(); // Ordena por data descendente
    res.json(transactions);
  } catch (error) {
    console.error("Erro ao buscar transações:", error);
    res.status(500).json({ message: "Erro interno ao buscar transações." });
  }
});

// POST /api/transactions - Adicionar nova transação para o usuário logado
app.post("/api/transactions", authenticateToken, async (req, res) => {
  const { description, amount, category, date, type } = req.body;

  // Validação básica dos dados da transação
  if (!description || !amount || !category || !date || !type) {
    return res.status(400).json({ message: "Todos os campos da transação são obrigatórios." });
  }
  if (typeof amount !== 'number' || amount <= 0) {
      return res.status(400).json({ message: "O valor da transação deve ser um número positivo." });
  }
  if (type !== 'income' && type !== 'expense') {
      return res.status(400).json({ message: "O tipo da transação deve ser 'income' ou 'expense'." });
  }

  try {
    const transactionsCollection = db.collection("transactions");
    const newTransaction = {
      userId: new ObjectId(req.user.userId), // Associa ao usuário logado
      description,
      amount,
      category,
      date, // Espera-se formato YYYY-MM-DD
      type,
      createdAt: new Date()
    };

    const result = await transactionsCollection.insertOne(newTransaction);
    // Retorna a transação criada com o ID gerado pelo MongoDB
    const createdTransaction = await transactionsCollection.findOne({ _id: result.insertedId });

    console.log(`Transação adicionada para ${req.user.username}, ID: ${result.insertedId}`);
    res.status(201).json(createdTransaction);

  } catch (error) {
    console.error("Erro ao adicionar transação:", error);
    res.status(500).json({ message: "Erro interno ao adicionar transação." });
  }
});

// DELETE /api/transactions/:id - Excluir transação do usuário logado
app.delete("/api/transactions/:id", authenticateToken, async (req, res) => {
  const transactionId = req.params.id;

  // Validar se o ID é um ObjectId válido
  if (!ObjectId.isValid(transactionId)) {
    return res.status(400).json({ message: "ID de transação inválido." });
  }

  try {
    const transactionsCollection = db.collection("transactions");

    // Tenta deletar a transação verificando se pertence ao usuário logado
    const result = await transactionsCollection.deleteOne({
      _id: new ObjectId(transactionId),
      userId: new ObjectId(req.user.userId) // Garante que só pode deletar suas próprias transações
    });

    if (result.deletedCount === 0) {
      // Se não deletou, ou a transação não existe ou não pertence ao usuário
      return res.status(404).json({ message: "Transação não encontrada ou não pertence a este usuário." });
    }

    console.log(`Transação removida para ${req.user.username}, ID: ${transactionId}`);
    res.status(200).json({ message: "Transação removida com sucesso." }); // Ou status 204 (No Content)

  } catch (error) {
    console.error("Erro ao remover transação:", error);
    res.status(500).json({ message: "Erro interno ao remover transação." });
  }
});


// Iniciar o servidor após conectar ao DB
connectDB().then(() => {
  app.listen(port, '0.0.0.0', () => { // Escuta em 0.0.0.0 para ser acessível externamente
    console.log(`Servidor backend rodando em http://0.0.0.0:${port}`);
  });
}).catch(err => {
    console.error("Erro fatal ao iniciar o servidor:", err);
});

