require("dotenv").config();
const sql = require("mssql");

const config = {
  server: process.env.DB_SERVER,
  database: process.env.DB_DATABASE,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  options: {
    encrypt: process.env.DB_ENCRYPT === "true",
    trustServerCertificate: process.env.DB_TRUST_SERVER_CERT === "true",
  },
};

const poolPromise = sql
  .connect(config)
  .then((pool) => {
    console.log("Conexão com Azure SQL estabelecida!");
    return pool;
  })
  .catch((err) => {
    console.error("Erro ao conectar ao Azure SQL:", err);
    process.exit(1);
  });

module.exports = {
  sql,
  poolPromise,
};
