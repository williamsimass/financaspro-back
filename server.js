require("dotenv").config();
const express = require("express");
const { MongoClient, ServerApiVersion, ObjectId } = require("mongodb");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const cors = require("cors");

const app = express();
const port = process.env.PORT || 3000;
const jwtSecret = process.env.JWT_SECRET;

// Middleware att
// Ordem Padrão Recomendada:
app.use(cors({ 
  origin: ["https://williamsimass.github.io/financaspro", "https://williamsimass.github.io/financaspro/register.html", "https://williamsimass.github.io/financaspro", "http://localhost:5000"],
  methods: ["GET", "POST", "DELETE", "PUT", "OPTIONS"],
  allowedHeaders: ["Content-Type", "Authorization"]
} ));
app.use(express.json()); // DEPOIS do cors

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
  console.log("--- Iniciando conexão com MongoDB ---");
  try {
    await client.connect();
    db = client.db("financaspro");
    console.log("Conectado ao MongoDB!");
    await db.command({ "ping": 1 });
    console.log("Ping ao banco de dados 'financaspro' bem-sucedido.");

    // Criar índice único para username e email para evitar duplicatas
    console.log("Tentando criar índices únicos...");
    const usersCollection = db.collection("users");
    await usersCollection.createIndex({ username: 1 }, { unique: true });
    await usersCollection.createIndex({ email: 1 }, { unique: true });
    console.log("Índices únicos para username e email garantidos (ou já existentes).");

  } catch (err) {
    if (err.code === 85 || err.code === 86) { // IndexOptionsConflict or IndexKeySpecsConflict
        console.log("Índices já existem ou conflito na criação, continuando...");
    } else {
        console.error("!!! FALHA CRÍTICA ao conectar ou criar índices no MongoDB !!!");
        console.error("Mensagem do Erro:", err.message);
        console.error("Stack do Erro:", err.stack);
        process.exit(1); // Encerrar o processo se não conseguir conectar ao DB
    }
  }
  console.log("--- Conexão com MongoDB finalizada ---");
}

// Middleware de autenticação
const authenticateToken = (req, res, next) => {
  console.log("--- Middleware authenticateToken INICIADO ---");
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];
  console.log("Token recebido (primeiros/últimos chars):", token ? `${token.substring(0, 5)}...${token.substring(token.length - 5)}` : "Nenhum");

  if (token == null) {
    console.log("authenticateToken: Token nulo, retornando 401.");
    return res.sendStatus(401);
  }

  jwt.verify(token, jwtSecret, (err, user) => {
    if (err) {
        console.error("!!! ERRO na verificação do token JWT !!!");
        console.error("Mensagem do Erro:", err.message);
        // Não logar o stack completo aqui por segurança, mas a mensagem é útil
        return res.sendStatus(403);
    }
    console.log("authenticateToken: Token verificado com sucesso para usuário:", user.username);
    req.user = user;
    next();
    console.log("--- Middleware authenticateToken FINALIZADO (next chamado) ---");
  });
};


// --- Rotas de Autenticação ---

// Rota de Registro (Atualizada com logs detalhados)
app.post("/api/auth/register", async (req, res) => {
  console.log("--- Rota /api/auth/register INICIADA ---");
  const { firstName, lastName, username, email, password } = req.body;
  console.log(`Tentativa de registro para: ${username}, Email: ${email}`);

  // Validação básica
  if (!firstName || !lastName || !username || !email || !password) {
    console.log("Registro - Erro: Campos obrigatórios ausentes.");
    return res.status(400).json({ message: "Todos os campos são obrigatórios: Nome, Sobrenome, Nome de usuário, Email e Senha." });
  }

  // Validação simples de email
  if (!/\S+@\S+\.\S+/.test(email)) {
      console.log("Registro - Erro: Formato de email inválido.");
      return res.status(400).json({ message: "Formato de email inválido." });
  }

  try {
    console.log("Registro - Dentro do TRY - Antes de acessar DB");
    const usersCollection = db.collection("users");

    console.log("Registro - Verificando se usuário/email já existe...");
    const existingUser = await usersCollection.findOne({
      $or: [
        { username: username.toLowerCase() },
        { email: email.toLowerCase() }
      ]
    });
    console.log("Registro - Verificação de existência concluída. Usuário existente:", !!existingUser);

    if (existingUser) {
      let message = "Erro no registro.";
      if (existingUser.username === username.toLowerCase()) {
          message = "Nome de usuário já está em uso.";
      } else if (existingUser.email === email.toLowerCase()) {
          message = "Email já está em uso.";
      }
      console.log(`Registro - Erro: ${message}`);
      return res.status(409).json({ message: message });
    }

    console.log("Registro - Antes de gerar hash da senha com bcrypt");
    const saltRounds = 10;
    const hashedPassword = await bcrypt.hash(password, saltRounds);
    console.log("Registro - Hash da senha gerado.");

    console.log("Registro - Antes de inserir novo usuário no DB");
    const result = await usersCollection.insertOne({
      firstName: firstName,
      lastName: lastName,
      username: username.toLowerCase(),
      email: email.toLowerCase(),
      password: hashedPassword,
      createdAt: new Date()
    });
    console.log(`Registro - Usuário inserido com sucesso: ${username}, ID: ${result.insertedId}`);
    
    res.status(201).json({ message: "Usuário registrado com sucesso!" });
    console.log("--- Rota /api/auth/register FINALIZADA com sucesso ---");

  } catch (error) {
    console.error("!!! ERRO NO CATCH da rota /api/auth/register !!!");
    console.error("Mensagem do Erro:", error.message);
    console.error("Stack do Erro:", error.stack);
    // Verifica erro de chave duplicada (caso o findOne falhe por alguma race condition)
    if (error.code === 11000) {
        let message = "Erro no registro.";
        if (error.keyPattern?.username) {
            message = "Nome de usuário já está em uso.";
        } else if (error.keyPattern?.email) {
            message = "Email já está em uso.";
        }
        console.log(`Registro - Erro de chave duplicada: ${message}`);
        return res.status(409).json({ message: message });
    }
    res.status(500).json({ message: "Erro interno do servidor ao registrar usuário." });
    console.log("--- Rota /api/auth/register FINALIZADA com erro no catch ---");
  }
});

// Rota de Login (Atualizada com logs detalhados)
app.post("/api/auth/login", async (req, res) => {
  console.log("--- Rota /api/auth/login INICIADA ---");
  const { username, password } = req.body;
  console.log(`Tentativa de login para usuário: ${username}`);

  if (!username || !password) {
    console.log("Login - Erro: Username ou senha ausentes.");
    return res.status(400).json({ message: "Nome de usuário e senha são obrigatórios." });
  }

  try {
    console.log("Login - Dentro do TRY - Antes de buscar usuário no DB");
    const usersCollection = db.collection("users");
    const user = await usersCollection.findOne({ username: username.toLowerCase() });
    console.log("Login - Depois de buscar usuário no DB. Usuário encontrado:", !!user);

    if (!user) {
      console.log("Login - Erro: Usuário não encontrado no DB.");
      return res.status(401).json({ message: "Credenciais inválidas." });
    }

    console.log("Login - Antes de comparar senha com bcrypt");
    const isMatch = await bcrypt.compare(password, user.password);
    console.log("Login - Depois de comparar senha. Senha corresponde:", isMatch);

    if (!isMatch) {
      console.log("Login - Erro: Senha não corresponde.");
      return res.status(401).json({ message: "Credenciais inválidas." });
    }

    console.log("Login - Antes de gerar token JWT");
    const payload = {
        userId: user._id,
        username: user.username,
        firstName: user.firstName,
        lastName: user.lastName
    };
    const token = jwt.sign(payload, jwtSecret, { expiresIn: "1h" });
    console.log("Login - Token JWT gerado com sucesso.");

    console.log(`Login - Usuário logado com sucesso: ${user.username}`);
    // Retorna o token e dados básicos do usuário
    res.json({ token: token, user: { username: user.username, firstName: user.firstName, lastName: user.lastName } });
    console.log("--- Rota /api/auth/login FINALIZADA com sucesso ---");

  } catch (error) {
    console.error("!!! ERRO NO CATCH da rota /api/auth/login !!!"); 
    console.error("Mensagem do Erro:", error.message);
    console.error("Stack do Erro:", error.stack);
    res.status(500).json({ message: "Erro interno do servidor ao fazer login." });
    console.log("--- Rota /api/auth/login FINALIZADA com erro no catch ---");
  }
});

// Rota de verificação de token
app.get("/api/auth/verify", authenticateToken, (req, res) => {
  console.log("--- Rota /api/auth/verify INICIADA ---");
  // Retorna os dados do usuário que estão no token (já validados pelo middleware)
  res.json({ valid: true, user: req.user });
  console.log("--- Rota /api/auth/verify FINALIZADA com sucesso ---");
});


// --- Rotas de Transações (Adicionar logs se necessário) ---

// GET /api/transactions - Listar transações do usuário logado
app.get("/api/transactions", authenticateToken, async (req, res) => {
  console.log(`--- Rota GET /api/transactions INICIADA para usuário: ${req.user.username} ---`);
  try {
    console.log("Transações - Dentro do TRY - Buscando transações...");
    const transactionsCollection = db.collection("transactions");
    const transactions = await transactionsCollection.find({ userId: new ObjectId(req.user.userId) }).sort({ date: -1 }).toArray();
    console.log(`Transações - Busca concluída. ${transactions.length} transações encontradas.`);
    res.json(transactions);
    console.log("--- Rota GET /api/transactions FINALIZADA com sucesso ---");
  } catch (error) {
    console.error("!!! ERRO NO CATCH da rota GET /api/transactions !!!");
    console.error("Mensagem do Erro:", error.message);
    console.error("Stack do Erro:", error.stack);
    res.status(500).json({ message: "Erro interno ao buscar transações." });
    console.log("--- Rota GET /api/transactions FINALIZADA com erro no catch ---");
  }
});

// POST /api/transactions - Adicionar nova transação para o usuário logado
app.post("/api/transactions", authenticateToken, async (req, res) => {
  console.log(`--- Rota POST /api/transactions INICIADA para usuário: ${req.user.username} ---`);
  const { description, amount, category, date, type } = req.body;
  console.log(`Tentativa de adicionar transação: ${description}, Valor: ${amount}`);

  // Validação básica
  if (!description || !amount || !category || !date || !type) {
    console.log("Transações POST - Erro: Campos obrigatórios ausentes.");
    return res.status(400).json({ message: "Todos os campos da transação são obrigatórios." });
  }
  if (typeof amount !== 'number' || amount <= 0) {
      console.log("Transações POST - Erro: Valor inválido.");
      return res.status(400).json({ message: "O valor da transação deve ser um número positivo." });
  }
  if (type !== 'income' && type !== 'expense') {
      console.log("Transações POST - Erro: Tipo inválido.");
      return res.status(400).json({ message: "O tipo da transação deve ser 'income' ou 'expense'." });
  }

  try {
    console.log("Transações POST - Dentro do TRY - Antes de inserir no DB");
    const transactionsCollection = db.collection("transactions");
    const newTransaction = {
      userId: new ObjectId(req.user.userId),
      description,
      amount,
      category,
      date,
      type,
      createdAt: new Date()
    };

    const result = await transactionsCollection.insertOne(newTransaction);
    console.log(`Transações POST - Inserção no DB concluída. ID: ${result.insertedId}`);
    const createdTransaction = await transactionsCollection.findOne({ _id: result.insertedId });
    console.log("Transações POST - Transação criada recuperada do DB.");

    res.status(201).json(createdTransaction);
    console.log("--- Rota POST /api/transactions FINALIZADA com sucesso ---");

  } catch (error) {
    console.error("!!! ERRO NO CATCH da rota POST /api/transactions !!!");
    console.error("Mensagem do Erro:", error.message);
    console.error("Stack do Erro:", error.stack);
    res.status(500).json({ message: "Erro interno ao adicionar transação." });
    console.log("--- Rota POST /api/transactions FINALIZADA com erro no catch ---");
  }
});

// DELETE /api/transactions/:id - Excluir transação do usuário logado
app.delete("/api/transactions/:id", authenticateToken, async (req, res) => {
  const transactionId = req.params.id;
  console.log(`--- Rota DELETE /api/transactions/:id INICIADA para usuário: ${req.user.username}, ID: ${transactionId} ---`);

  if (!ObjectId.isValid(transactionId)) {
    console.log("Transações DELETE - Erro: ID inválido.");
    return res.status(400).json({ message: "ID de transação inválido." });
  }

  try {
    console.log("Transações DELETE - Dentro do TRY - Antes de deletar no DB");
    const transactionsCollection = db.collection("transactions");
    const result = await transactionsCollection.deleteOne({
      _id: new ObjectId(transactionId),
      userId: new ObjectId(req.user.userId)
    });
    console.log(`Transações DELETE - Deleção no DB concluída. Count: ${result.deletedCount}`);

    if (result.deletedCount === 0) {
      console.log("Transações DELETE - Erro: Transação não encontrada ou não pertence ao usuário.");
      return res.status(404).json({ message: "Transação não encontrada ou não pertence a este usuário." });
    }

    res.status(200).json({ message: "Transação removida com sucesso." });
    console.log("--- Rota DELETE /api/transactions/:id FINALIZADA com sucesso ---");

  } catch (error) {
    console.error("!!! ERRO NO CATCH da rota DELETE /api/transactions/:id !!!");
    console.error("Mensagem do Erro:", error.message);
    console.error("Stack do Erro:", error.stack);
    res.status(500).json({ message: "Erro interno ao remover transação." });
    console.log("--- Rota DELETE /api/transactions/:id FINALIZADA com erro no catch ---");
  }
});


// Iniciar o servidor após conectar ao DB
connectDB().then(() => {
  app.listen(port, '0.0.0.0', () => {
    console.log(`Servidor backend rodando em http://0.0.0.0:${port}`);
  });
}).catch(err => {
    // O erro fatal já é logado dentro de connectDB
    console.error("Erro fatal detectado ao tentar iniciar o servidor após falha na conexão com DB.");
    // process.exit(1) já é chamado dentro de connectDB em caso de falha crítica
});

