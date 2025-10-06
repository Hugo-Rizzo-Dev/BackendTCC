require("dotenv").config();

const express = require("express");
const crypto = require("crypto");
const cors = require("cors");
const bcrypt = require("bcrypt");
const axios = require("axios");
const multer = require("multer");
const exifr = require("exifr");
const nodemailer = require("nodemailer");
const { v4: uuidv4 } = require("uuid");
const { poolPromise, sql } = require("./db");
const { gerarDescricaoIA } = require("./gemini");

const jwt = require("jsonwebtoken");
const JWT_SECRET = process.env.JWT_SECRET || "dev-secret";

const app = express();
app.use(cors());
app.use(express.json());
const upload = multer({ storage: multer.memoryStorage() });

app.get("/", (_, res) => res.send("API TCC - ok"));

/* Filter Posts */
async function moderateImageWithVision(buffer) {
  const apiKey = process.env.VISION_API_KEY;
  if (!apiKey) {
    console.error("[Vision] Missing VISION_API_KEY env var");
    throw new Error("Vision API key not configured");
  }

  const payload = {
    requests: [
      {
        image: { content: buffer.toString("base64") },
        features: [
          { type: "SAFE_SEARCH_DETECTION", maxResults: 1 },
          { type: "LABEL_DETECTION", maxResults: 50 },
        ],
      },
    ],
  };

  const url = `https://vision.googleapis.com/v1/images:annotate?key=${apiKey}`;

  const { data } = await axios.post(url, payload, {
    headers: { "Content-Type": "application/json" },
  });

  const resp = data?.responses?.[0] || {};
  const safe = resp.safeSearchAnnotation || {};

  const badLikelihood = new Set(["LIKELY", "VERY_LIKELY"]);
  const reasons = [];

  if (badLikelihood.has(safe.adult)) reasons.push("adult");
  if (badLikelihood.has(safe.violence)) reasons.push("violence");
  if (badLikelihood.has(safe.racy)) reasons.push("racy");
  if (badLikelihood.has(safe.medical)) reasons.push("medical");
  if (badLikelihood.has(safe.spoof)) reasons.push("spoof");

  const labels = (resp.labelAnnotations || []).map((l) =>
    (l.description || "").toLowerCase()
  );

  const weaponTerms = new Set([
    "weapon",
    "gun",
    "handgun",
    "pistol",
    "rifle",
    "shotgun",
    "machine gun",
    "knife",
    "dagger",
  ]);
  const drugTerms = new Set([
    "drug",
    "illicit drug",
    "narcotic",
    "cannabis",
    "marijuana",
    "weed",
    "cocaine",
    "heroin",
    "methamphetamine",
    "meth",
    "opioid",
    "pills",
  ]);

  if (labels.some((d) => weaponTerms.has(d))) reasons.push("weapon");
  if (labels.some((d) => drugTerms.has(d))) reasons.push("drugs");

  const ok = reasons.length === 0;
  if (!ok) {
    console.warn("[Vision] Image blocked. Reasons:", reasons.join(", "));
  }
  return { ok, reasons, safe, labels };
}

// Middleware para verificar autenticação
function checkAuth(req, _res, next) {
  const hdr = req.headers.authorization;
  if (hdr?.startsWith("Bearer ")) {
    try {
      const { userId } = jwt.verify(hdr.slice(7), JWT_SECRET);
      req.userId = userId;
    } catch (err) {
      console.warn("JWT verification failed:", err.message);
    }
  }

  if (!req.userId && req.headers["x-user-id"]) {
    console.warn(
      `[AUTH_WARN] Usando cabeçalho X-User-Id inseguro para o usuário: ${req.headers["x-user-id"]}`
    );
    req.userId = req.headers["x-user-id"];
  }

  next();
}

// Middleware para rotas de administrador
async function adminOnly(req, res, next) {
  try {
    if (!req.userId) {
      return res.status(401).json({ message: "Autenticação necessária." });
    }

    const pool = await poolPromise;
    const { recordset } = await pool
      .request()
      .input("id", sql.UniqueIdentifier, req.userId)
      .query("SELECT isAdmin FROM dbo.Usuarios WHERE id = @id");

    if (!recordset[0]?.isAdmin) {
      return res
        .status(403)
        .json({ message: "Acesso negado. Apenas administradores." });
    }

    next();
  } catch (err) {
    console.error("adminOnly middleware error:", err);
    res.status(500).json({ message: "Erro interno no servidor." });
  }
}

/* =================================================================
 * HELPERS
 * =================================================================*/
function buildAvatarUrl(req, id, temAvatar) {
  if (!temAvatar) {
    return null;
  }

  const protocol =
    process.env.NODE_ENV === "production" ? "https" : req.protocol;
  const host = req.get("host");

  return `${protocol}://${host}/users/${id}/avatar`;
}

/* =================================================================
 * ROTAS
 * =================================================================*/

app.use(checkAuth);

/* ---------- USUÁRIOS ------------------------------------------------ */
app.post("/users", async (req, res) => {
  const { nome, sobrenome, dataNascimento, genero, email, senha } = req.body;

  if (!nome || !sobrenome || !dataNascimento || !genero || !email || !senha)
    return res.status(400).json({ message: "Campos obrigatórios faltando." });

  if (!["M", "F"].includes(genero))
    return res.status(400).json({ message: 'Gênero deve ser "M" ou "F"' });

  try {
    const pool = await poolPromise;
    await pool
      .request()
      .input("id", sql.UniqueIdentifier, uuidv4())
      .input("nome", sql.NVarChar, nome)
      .input("sobrenome", sql.NVarChar, sobrenome)
      .input("dataNascimento", sql.Date, dataNascimento)
      .input("genero", sql.Char(1), genero)
      .input("email", sql.NVarChar, email)
      .input("senhaHash", sql.NVarChar, await bcrypt.hash(senha, 10)).query(`
                INSERT INTO dbo.Usuarios
                    (id, nome, sobrenome, dataNascimento, genero, email, senhaHash)
                VALUES
                    (@id, @nome, @sobrenome, @dataNascimento, @genero, @email, @senhaHash)
            `);

    res.status(201).json({ message: "Usuário criado" });
  } catch (err) {
    console.error(err);
    if (err.number === 2627)
      return res.status(409).json({ message: "E-mail já cadastrado" });
    res.status(500).json({ message: "Erro interno" });
  }
});

app.get("/users", async (req, res) => {
  try {
    const pool = await poolPromise;
    const r = await pool.request().query(`
            SELECT id, nome, sobrenome, dataNascimento, genero, email, tipo, descricao,
                    CASE WHEN fotoPerfilData IS NOT NULL THEN 1 ELSE 0 END AS temAvatar
            FROM    dbo.Usuarios
        `);

    const users = r.recordset.map((u) => ({
      ...u,
      fotoPerfil: buildAvatarUrl(req, u.id, u.temAvatar),
    }));

    res.json(users);
  } catch (err) {
    console.error("GET /users:", err);
    res.status(500).json({ message: "Erro interno" });
  }
});

app.get("/users/:id", async (req, res) => {
  const { id } = req.params;
  const pool = await poolPromise;

  const r = await pool.request().input("id", sql.UniqueIdentifier, id).query(`
        SELECT id, nome, sobrenome, dataNascimento, genero, email, tipo, descricao,
                CASE WHEN fotoPerfilData IS NOT NULL THEN 1 ELSE 0 END AS temAvatar
        FROM dbo.Usuarios
        WHERE id = @id
    `);

  if (!r.recordset.length)
    return res.status(404).json({ message: "Usuário não encontrado" });

  const u = r.recordset[0];
  res.json({
    ...u,
    fotoPerfil: buildAvatarUrl(req, u.id, u.temAvatar),
  });
});

app.put("/users/:id", upload.single("avatar"), async (req, res) => {
  const { nome, sobrenome, dataNascimento, genero, tipo, descricao } = req.body;
  if (!nome || !sobrenome || !dataNascimento || !["M", "F"].includes(genero))
    return res.status(400).json({ message: "Dados inválidos" });

  try {
    const pool = await poolPromise;
    const q = pool
      .request()
      .input("id", sql.UniqueIdentifier, req.params.id)
      .input("nome", sql.NVarChar, nome)
      .input("sobrenome", sql.NVarChar, sobrenome)
      .input("dataNascimento", sql.Date, dataNascimento)
      .input("genero", sql.Char(1), genero)
      .input("tipo", sql.Int, tipo || null)
      .input("descricao", sql.NVarChar, (descricao ?? "").slice(0, 200));

    let sets = `
                nome           = @nome,
                sobrenome      = @sobrenome,
                dataNascimento = @dataNascimento,
                genero         = @genero,
                tipo           = @tipo,
                descricao      = @descricao
            `;

    if (req.file) {
      q.input("foto", sql.VarBinary(sql.MAX), req.file.buffer);
      sets += `, fotoPerfilData = @foto`;
    }

    await q.query(`UPDATE dbo.Usuarios SET ${sets} WHERE id = @id`);
    res.json({ message: "Perfil atualizado" });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Erro interno" });
  }
});

app.get("/users/:id/following", async (req, res) => {
  try {
    const pool = await poolPromise;
    const r = await pool
      .request()
      .input("id", sql.UniqueIdentifier, req.params.id).query(`
        SELECT seguidoId AS id,
               nome, 
               sobrenome,
               temAvatar -- Apenas o campo booleano
        FROM   dbo.vw_Following
        WHERE  userId = @id
        ORDER  BY nome, sobrenome
      `);

    const followingList = r.recordset.map((user) => ({
      ...user,
      fotoPerfil: buildAvatarUrl(req, user.id, user.temAvatar),
    }));

    res.json(followingList);
  } catch (err) {
    console.error("following list:", err);
    res.status(500).json({ message: "Erro interno" });
  }
});

app.get("/users/:id/avatar", async (req, res) => {
  const pool = await poolPromise;
  const r = await pool
    .request()
    .input("id", sql.UniqueIdentifier, req.params.id)
    .query(`SELECT fotoPerfilData FROM dbo.Usuarios WHERE id = @id`);

  const bin = r.recordset[0]?.fotoPerfilData;
  if (!bin) return res.status(404).send("Sem avatar");
  res.set("Content-Type", "image/jpeg").send(bin);
});

app.post("/login", async (req, res) => {
  const { email, senha } = req.body;
  if (!email || !senha)
    return res.status(400).json({ message: "Informe email e senha" });

  try {
    const pool = await poolPromise;
    const r = await pool
      .request()
      .input("email", sql.NVarChar, email)
      .query(
        `SELECT id, nome, sobrenome, senhaHash, isAdmin,
                        CASE WHEN fotoPerfilData IS NOT NULL THEN 1 ELSE 0 END AS temAvatar
                FROM dbo.Usuarios WHERE email=@email`
      );

    if (
      !r.recordset.length ||
      !(await bcrypt.compare(senha, r.recordset[0].senhaHash))
    )
      return res.status(401).json({ message: "Credenciais inválidas" });

    const u = r.recordset[0];
    res.json({
      user: {
        id: u.id,
        nome: u.nome,
        sobrenome: u.sobrenome,
        isAdmin: !!u.isAdmin,
        fotoPerfil: buildAvatarUrl(req, u.id, u.temAvatar),
      },
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Erro interno" });
  }
});

/* Reset Password */
app.post("/forgot-password", async (req, res) => {
  const { email } = req.body;
  if (!email) {
    return res.status(400).json({ message: "O e-mail é obrigatório." });
  }

  try {
    const pool = await poolPromise;
    const { recordset } = await pool
      .request()
      .input("email", sql.NVarChar, email)
      .query("SELECT id FROM dbo.Usuarios WHERE email = @email");

    const user = recordset[0];

    if (!user) {
      return res.json({
        message:
          "Se um usuário com este e-mail existir, um código de recuperação foi enviado.",
      });
    }

    const resetCode = crypto.randomInt(100000, 999999).toString();

    const expires = new Date();
    expires.setMinutes(expires.getMinutes() + 10);

    await pool
      .request()
      .input("id", sql.UniqueIdentifier, user.id)
      .input("token", sql.NVarChar, resetCode)
      .input("expires", sql.DateTime, expires).query(`
        UPDATE dbo.Usuarios 
        SET resetPasswordToken = @token, resetPasswordExpires = @expires
        WHERE id = @id
      `);

    await transporter.sendMail({
      from: `"App Turismo" <${process.env.REPORT_SMTP_USER}>`,
      to: email,
      subject: "Seu Código de Recuperação de Senha - App Turismo",
      html: `
        <p>Olá,</p>
        <p>Use o código abaixo para redefinir sua senha no App Turismo.</p>
        <h2 style="text-align:center; letter-spacing: 5px;">${resetCode}</h2>
        <p>Este código é válido por 10 minutos.</p>
        <p>Se você não solicitou isso, ignore este e-mail.</p>
      `,
    });

    res.json({
      message: "Um código de recuperação foi enviado para seu email.",
    });
  } catch (err) {
    console.error("Erro em /forgot-password:", err);
    res.status(500).json({ message: "Erro interno no servidor." });
  }
});

app.post("/verify-code", async (req, res) => {
  const { email, code } = req.body;
  if (!email || !code) {
    return res
      .status(400)
      .json({ message: "E-mail e código são obrigatórios." });
  }

  try {
    const pool = await poolPromise;
    const { recordset } = await pool
      .request()
      .input("email", sql.NVarChar, email)
      .input("code", sql.NVarChar, code)
      .input("now", sql.DateTime, new Date()).query(`
        SELECT id FROM dbo.Usuarios 
        WHERE email = @email AND resetPasswordToken = @code AND resetPasswordExpires > @now
      `);

    const user = recordset[0];

    if (!user) {
      return res.status(400).json({ message: "Código inválido ou expirado." });
    }

    await pool
      .request()
      .input("id", sql.UniqueIdentifier, user.id)
      .query(
        `UPDATE dbo.Usuarios SET resetPasswordToken = NULL WHERE id = @id`
      );

    const resetAuthToken = jwt.sign({ userId: user.id }, JWT_SECRET, {
      expiresIn: "5m",
    });

    res.json({
      message: "Código verificado com sucesso.",
      resetAuthToken: resetAuthToken,
    });
  } catch (err) {
    console.error("Erro em /verify-code:", err);
    res.status(500).json({ message: "Erro interno no servidor." });
  }
});

app.post("/reset-password", async (req, res) => {
  const { resetAuthToken, senha } = req.body;

  if (!resetAuthToken || !senha) {
    return res
      .status(400)
      .json({ message: "Token de autorização e nova senha são obrigatórios." });
  }

  try {
    const decoded = jwt.verify(resetAuthToken, JWT_SECRET);
    const userId = decoded.userId;

    const novaSenhaHash = await bcrypt.hash(senha, 10);

    const pool = await poolPromise;
    await pool
      .request()
      .input("id", sql.UniqueIdentifier, userId)
      .input("senhaHash", sql.NVarChar, novaSenhaHash).query(`
        UPDATE dbo.Usuarios 
        SET senhaHash = @senhaHash,
            resetPasswordExpires = NULL
        WHERE id = @id
      `);

    res.json({ message: "Senha redefinida com sucesso!" });
  } catch (err) {
    if (err instanceof jwt.JsonWebTokenError) {
      return res
        .status(401)
        .json({ message: "Token de autorização inválido ou expirado." });
    }
    console.error("Erro em /reset-password:", err);
    res.status(500).json({ message: "Erro interno no servidor." });
  }
});

// Verificar imagem
app.post("/moderate-image", upload.single("foto"), async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ ok: false, message: "Image is required." });
    }
    const moderation = await moderateImageWithVision(req.file.buffer);
    if (!moderation.ok) {
      return res.status(400).json({
        ok: false,
        message:
          "Imagem reprovada automaticamente por conter conteúdo impróprio.",
        reasons: moderation.reasons,
      });
    }
    return res.json({ ok: true });
  } catch (err) {
    console.error("[Vision] Pre-check failed:", err.message);
    return res.status(502).json({
      ok: false,
      message: "Falha ao verificar a imagem na Vision API.",
    });
  }
});

/* ---------- POSTS -------------------------------------------------- */
app.post("/posts", upload.single("foto"), async (req, res) => {
  const {
    usuarioId,
    legenda,
    latitude,
    longitude,
    localNome,
    descricaoIA,
    tags,
  } = req.body;
  if (!req.file) return res.status(400).json({ message: "Foto obrigatória" });

  try {
    const moderation = await moderateImageWithVision(req.file.buffer);
    if (!moderation.ok) {
      return res.status(400).json({
        message:
          "Imagem reprovada automaticamente por conter conteúdo impróprio.",
        reasons: moderation.reasons,
      });
    }
  } catch (err) {
    console.error("[Vision] Moderation failed:", err.message);
    return res.status(502).json({
      message: "Falha ao verificar a imagem na Vision API.",
    });
  }

  let lat = latitude ? +latitude : null;
  let lng = longitude ? +longitude : null;
  let nomeDoLocal = localNome;

  const postId = uuidv4();

  try {
    const pool = await poolPromise;
    const transaction = new sql.Transaction(pool);
    await transaction.begin();

    try {
      await new sql.Request(transaction)
        .input("id", sql.UniqueIdentifier, postId)
        .input("usuarioId", sql.UniqueIdentifier, usuarioId)
        .input("legenda", sql.NVarChar, legenda)
        .input("latitude", sql.Float, lat)
        .input("longitude", sql.Float, lng)
        .input("localNome", sql.NVarChar, nomeDoLocal)
        .input("descricaoIA", sql.NVarChar(sql.MAX), descricaoIA)
        .input("img", sql.VarBinary(sql.MAX), req.file.buffer).query(`
                    INSERT INTO dbo.Posts (id, usuarioId, legenda, latitude, longitude, localNome, descricaoIA, imagemData, createdAt)
                    VALUES (@id, @usuarioId, @legenda, @latitude, @longitude, @localNome, @descricaoIA, @img, GETUTCDATE())
                `);

      if (tags && tags.trim() !== "") {
        const tagNames = tags
          .split(",")
          .map((tag) => tag.trim().toLowerCase())
          .filter((t) => t);

        for (const tagName of tagNames) {
          let tagResult = await new sql.Request(transaction)
            .input("nome", sql.NVarChar, tagName)
            .query("SELECT id FROM dbo.Tags WHERE nome = @nome");

          let tagId;
          if (tagResult.recordset.length > 0) {
            tagId = tagResult.recordset[0].id;
          } else {
            tagResult = await new sql.Request(transaction)
              .input("nome", sql.NVarChar, tagName)
              .query(
                "INSERT INTO dbo.Tags (nome) OUTPUT INSERTED.id VALUES (@nome)"
              );
            tagId = tagResult.recordset[0].id;
          }

          await new sql.Request(transaction)
            .input("postId", sql.UniqueIdentifier, postId)
            .input("tagId", sql.Int, tagId)
            .query(
              "INSERT INTO dbo.PostTags (postId, tagId) VALUES (@postId, @tagId)"
            );
        }
      }

      await transaction.commit();
      res.status(201).json({ message: "Post e tags criados com sucesso" });
    } catch (err) {
      await transaction.rollback();
      throw err;
    }
  } catch (err) {
    console.error("Erro ao criar post com tags:", err);
    res.status(500).json({ message: "Erro interno" });
  }
});

app.get("/posts/:postId/image", async (req, res) => {
  const pool = await poolPromise;
  const r = await pool
    .request()
    .input("id", sql.UniqueIdentifier, req.params.postId)
    .query("SELECT imagemData FROM dbo.Posts WHERE id=@id");

  const bin = r.recordset[0]?.imagemData;
  if (!bin) return res.status(404).send("Sem imagem");
  res.set("Content-Type", "image/jpeg").send(bin);
});

app.get("/posts", async (req, res) => {
  const viewer = req.userId ?? "00000000-0000-0000-0000-000000000000";
  const { lat, lng } = req.query;

  try {
    const pool = await poolPromise;
    const request = pool.request().input("uid", sql.UniqueIdentifier, viewer);

    let query = `
          WITH PostsData AS (
              SELECT
                  p.id, p.legenda, p.createdAt, p.latitude, p.longitude,
                  p.localNome, p.descricaoIA,
                  p.isPontoTuristico, p.tentativasVotacao,
                  u.id AS autorId, u.nome, u.sobrenome,
                  CASE WHEN u.fotoPerfilData IS NULL THEN 0 ELSE 1 END AS hasAvatar,
                  (SELECT COUNT(*) FROM dbo.PostLikes pl WHERE pl.postId = p.id) AS likes,
                  (SELECT COUNT(*) FROM dbo.Comentarios c WHERE c.postId = p.id) AS comments,
                  CASE WHEN EXISTS (SELECT 1 FROM dbo.PostLikes pl WHERE pl.postId = p.id AND pl.usuarioId = @uid)
                        THEN 1 ELSE 0 END AS curtiu,
                  v.id as votacaoId,
                  v.terminaEm as votacaoTerminaEm,
                  (SELECT COUNT(vu.voto) FROM dbo.VotosUsuarios vu WHERE vu.votacaoId = v.id AND vu.voto = 1) AS votosSim,
                  (SELECT COUNT(vu.voto) FROM dbo.VotosUsuarios vu WHERE vu.votacaoId = v.id AND vu.voto = 0) AS votosNao,
                  CASE WHEN EXISTS (SELECT 1 FROM dbo.VotosUsuarios vu WHERE vu.votacaoId = v.id AND vu.usuarioId = @uid)
                        THEN 1 ELSE 0 END AS jaVotou,
                  CASE 
                      WHEN EXISTS (SELECT 1 FROM dbo.Seguidores s WHERE s.seguidorId = @uid AND s.seguidoId = u.id) 
                      THEN 1 
                      ELSE 0 
                  END AS isFollowing
                  ${
                    lat && lng
                      ? `,
                  (6371 * acos(
                      cos(radians(@userLat)) * cos(radians(p.latitude)) *
                      cos(radians(p.longitude) - radians(@userLng)) +
                      sin(radians(@userLat)) * sin(radians(p.latitude))
                  )) AS distancia_km`
                      : ""
                  }
              FROM dbo.Posts p
              JOIN dbo.Usuarios u ON u.id = p.usuarioId
              LEFT JOIN dbo.Votacoes v ON v.postId = p.id AND v.status = 'ativa' AND v.terminaEm > GETUTCDATE()
          )
          SELECT *
          FROM PostsData
          ${lat && lng ? "WHERE distancia_km <= 300" : ""}
          ORDER BY isFollowing DESC, createdAt DESC
      `;

    if (lat && lng) {
      request.input("userLat", sql.Float, parseFloat(lat));
      request.input("userLng", sql.Float, parseFloat(lng));
    }

    const r = await request.query(query);

    const posts = r.recordset.map((p) => ({
      ...p,
      fotoPerfil: buildAvatarUrl(req, p.autorId, p.hasAvatar),
    }));
    res.json(posts);
  } catch (err) {
    console.error("Erro ao buscar posts:", err);
    res.status(500).json({ message: "Erro interno" });
  }
});

// Rota para o autor do post iniciar uma votação
app.post("/posts/:postId/iniciar-votacao", async (req, res) => {
  const { postId } = req.params;
  const { userId } = req;

  if (!userId) {
    return res.status(401).json({ message: "Autenticação necessária." });
  }

  try {
    const pool = await poolPromise;

    const postResult = await pool
      .request()
      .input("postId", sql.UniqueIdentifier, postId)
      .query(
        "SELECT usuarioId, tentativasVotacao, isPontoTuristico FROM dbo.Posts WHERE id = @postId"
      );

    const post = postResult.recordset[0];

    if (!post) {
      return res.status(404).json({ message: "Post não encontrado." });
    }
    if (post.usuarioId.toUpperCase() !== userId.toUpperCase()) {
      // Comparação case-insensitive para segurança
      return res
        .status(403)
        .json({ message: "Apenas o autor pode iniciar uma votação." });
    }
    if (post.isPontoTuristico) {
      return res
        .status(400)
        .json({ message: "Este local já é um ponto turístico." });
    }
    if (post.tentativasVotacao >= 3) {
      return res
        .status(400)
        .json({ message: "Limite de 3 tentativas de votação atingido." });
    }

    const votacaoId = uuidv4();
    const agora = new Date();
    const terminaEm = new Date(agora.getTime() + 24 * 60 * 60 * 1000); // 24 horas

    const transaction = new sql.Transaction(pool);
    await transaction.begin();
    try {
      // Atualiza o post
      await new sql.Request(transaction)
        .input("postId", sql.UniqueIdentifier, postId)
        .query(
          "UPDATE dbo.Posts SET tentativasVotacao = tentativasVotacao + 1 WHERE id = @postId"
        );

      // Insere a votação
      await new sql.Request(transaction)
        .input("votacaoId", sql.UniqueIdentifier, votacaoId)
        .input("postId", sql.UniqueIdentifier, postId)
        .input("iniciadaEm", sql.DateTime2, agora)
        .input("terminaEm", sql.DateTime2, terminaEm)
        .input("status", sql.NVarChar, "ativa").query(`
                    INSERT INTO dbo.Votacoes (id, postId, iniciadaEm, terminaEm, status)
                    VALUES (@votacaoId, @postId, @iniciadaEm, @terminaEm, @status);
                `);

      await transaction.commit();
      res.status(201).json({ message: "Votação iniciada com sucesso!" });
    } catch (err) {
      await transaction.rollback();
      throw err;
    }
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Erro interno ao iniciar votação" });
  }
});

// Rota para um usuário votar
app.post("/votacoes/:votacaoId/votar", async (req, res) => {
  const { votacaoId } = req.params;
  const { voto } = req.body; // true para 'Sim', false para 'Não'
  const { userId } = req;

  if (voto === undefined) {
    return res
      .status(400)
      .json({ message: "O voto (true/false) é obrigatório." });
  }
  if (!userId) {
    return res.status(401).json({ message: "Autenticação necessária." });
  }

  try {
    const pool = await poolPromise;

    await fecharVotacoesExpiradas(pool);

    const votacaoResult = await pool
      .request()
      .input("votacaoId", sql.UniqueIdentifier, votacaoId)
      .query(
        "SELECT status, terminaEm FROM dbo.Votacoes WHERE id = @votacaoId"
      );

    const votacao = votacaoResult.recordset[0];
    if (
      !votacao ||
      votacao.status !== "ativa" ||
      new Date() > votacao.terminaEm
    ) {
      return res
        .status(400)
        .json({ message: "Esta votação não está mais ativa." });
    }

    await pool
      .request()
      .input("votacaoId", sql.UniqueIdentifier, votacaoId)
      .input("usuarioId", sql.UniqueIdentifier, userId)
      .input("voto", sql.Bit, voto)
      .input("votadoEm", sql.DateTime2, new Date()).query(`
                    INSERT INTO dbo.VotosUsuarios (votacaoId, usuarioId, voto, votadoEm)
                    VALUES (@votacaoId, @usuarioId, @voto, @votadoEm)
                `);

    res.status(201).json({ message: "Voto registrado com sucesso!" });
  } catch (err) {
    if (err.number === 2627) {
      // Chave primária duplicada
      return res.status(409).json({ message: "Você já votou nesta sessão." });
    }
    console.error(err);
    res.status(500).json({ message: "Erro interno ao registrar voto" });
  }
});

async function fecharVotacoesExpiradas(pool) {
  console.log("Verificando votações expiradas...");
  const votacoesExpiradas = await pool
    .request()
    .query(
      "SELECT id, postId FROM dbo.Votacoes WHERE terminaEm < GETUTCDATE() AND status = 'ativa'"
    );

  for (const votacao of votacoesExpiradas.recordset) {
    const votosResult = await pool
      .request()
      .input("votacaoId", sql.UniqueIdentifier, votacao.id)
      .query(
        "SELECT SUM(CAST(voto AS INT)) as votosSim, COUNT(*) as totalVotos FROM dbo.VotosUsuarios WHERE votacaoId = @votacaoId"
      );

    const { votosSim, totalVotos } = votosResult.recordset[0];
    const resultado =
      (votosSim || 0) > (totalVotos || 0) / 2 ? "aprovada" : "reprovada";

    await pool
      .request()
      .input("votacaoId", sql.UniqueIdentifier, votacao.id)
      .input("resultado", sql.NVarChar, resultado)
      .query(
        "UPDATE dbo.Votacoes SET status = 'concluida', resultado = @resultado WHERE id = @votacaoId"
      );

    if (resultado === "aprovada") {
      await pool
        .request()
        .input("postId", sql.UniqueIdentifier, votacao.postId)
        .query("UPDATE dbo.Posts SET isPontoTuristico = 1 WHERE id = @postId");
    }
  }
}

app.get("/users/:id/posts", async (req, res) => {
  const viewer = req.userId ?? req.params.id;
  const pool = await poolPromise;
  const r = await pool
    .request()
    .input("uid", sql.UniqueIdentifier, viewer)
    .input("userId", sql.UniqueIdentifier, req.params.id).query(`
            SELECT  p.id, p.legenda, p.createdAt, p.latitude, p.longitude,
                    u.id AS autorId, u.nome, u.sobrenome,
                    CASE WHEN u.fotoPerfilData IS NULL THEN 0 ELSE 1 END AS hasAvatar,
                    (SELECT COUNT(*) FROM dbo.PostLikes pl WHERE pl.postId = p.id) AS likes,
                    (SELECT COUNT(*) FROM dbo.Comentarios c WHERE c.postId = p.id)  AS comments,
                    CASE WHEN EXISTS (SELECT 1 FROM dbo.PostLikes pl
                                        WHERE pl.postId = p.id AND pl.usuarioId = @uid)
                        THEN 1 ELSE 0 END AS curtiu
            FROM dbo.Posts p
            JOIN dbo.Usuarios u ON u.id = p.usuarioId
            WHERE p.usuarioId = @userId
            ORDER BY p.createdAt DESC
        `);

  res.json(
    r.recordset.map((p) => ({
      ...p,
      fotoPerfil: buildAvatarUrl(req, p.autorId, p.hasAvatar),
    }))
  );
});

app.delete("/posts/:id", async (req, res) => {
  const { usuarioId } = req.body;
  if (!usuarioId)
    return res.status(400).json({ message: "usuarioId necessário" });

  const pool = await poolPromise;
  const ok = await pool
    .request()
    .input("id", sql.UniqueIdentifier, req.params.id)
    .input("uid", sql.UniqueIdentifier, usuarioId).query(`
            SELECT 1 FROM dbo.Posts WHERE id=@id AND usuarioId=@uid
        `);

  if (!ok.recordset.length)
    return res.status(403).json({ message: "Sem permissão" });

  await pool.request().input("id", sql.UniqueIdentifier, req.params.id).query(`
            DELETE dbo.PostLikes    WHERE postId=@id;
            DELETE dbo.Comentarios  WHERE postId=@id;
            DELETE dbo.Posts        WHERE id=@id;
        `);

  res.json({ message: "Post excluído" });
});

app.post("/posts/:id/like", async (req, res) => {
  const { usuarioId } = req.body;
  const pool = await poolPromise;
  await pool
    .request()
    .input("id", sql.UniqueIdentifier, req.params.id)
    .input("uid", sql.UniqueIdentifier, usuarioId).query(`
            IF NOT EXISTS (SELECT 1 FROM dbo.PostLikes WHERE postId=@id AND usuarioId=@uid)
                INSERT dbo.PostLikes(postId,usuarioId) VALUES (@id,@uid)
        `);
  res.json({ ok: true });
});

app.delete("/posts/:id/like", async (req, res) => {
  const { usuarioId } = req.body;
  const pool = await poolPromise;
  await pool
    .request()
    .input("id", sql.UniqueIdentifier, req.params.id)
    .input("uid", sql.UniqueIdentifier, usuarioId)
    .query("DELETE dbo.PostLikes WHERE postId=@id AND usuarioId=@uid");
  res.json({ ok: true });
});

/* ---------- COMENTÁRIOS ------------------------------------------- */
app.get("/posts/:id/comments", async (req, res) => {
  const pool = await poolPromise;
  const r = await pool
    .request()
    .input("id", sql.UniqueIdentifier, req.params.id).query(`
            SELECT c.id, c.texto, c.createdAt, c.updatedAt,
                    u.id AS autorId, u.nome, u.sobrenome,
                    CASE WHEN u.fotoPerfilData IS NULL THEN 0 ELSE 1 END AS hasAvatar
            FROM    dbo.Comentarios c
            JOIN    dbo.Usuarios    u ON u.id = c.usuarioId
            WHERE   c.postId = @id
            ORDER  BY c.createdAt
        `);

  res.json(
    r.recordset.map((c) => ({
      ...c,
      editado: !!c.updatedAt,
      fotoPerfil: buildAvatarUrl(req, c.autorId, c.hasAvatar),
    }))
  );
});

app.post("/posts/:id/comments", async (req, res) => {
  const { usuarioId, texto } = req.body;
  if (!texto?.trim()) return res.status(400).json({ message: "Texto vazio" });

  const pool = await poolPromise;
  await pool
    .request()
    .input("cid", sql.UniqueIdentifier, uuidv4())
    .input("id", sql.UniqueIdentifier, req.params.id)
    .input("uid", sql.UniqueIdentifier, usuarioId)
    .input("txt", sql.NVarChar, texto.trim()).query(`
            INSERT dbo.Comentarios(id,postId,usuarioId,texto,createdAt)
            VALUES (@cid,@id,@uid,@txt,GETUTCDATE())
        `);

  res.status(201).json({ ok: true });
});

app.put("/comments/:cid", async (req, res) => {
  const { usuarioId, texto } = req.body;
  if (!texto?.trim()) return res.status(400).json({ message: "Texto vazio" });

  const pool = await poolPromise;
  const r = await pool
    .request()
    .input("cid", sql.UniqueIdentifier, req.params.cid)
    .input("uid", sql.UniqueIdentifier, usuarioId)
    .input("txt", sql.NVarChar, texto.trim()).query(`
            UPDATE dbo.Comentarios
                SET texto = @txt,
                    updatedAt = GETUTCDATE()
                WHERE id = @cid AND usuarioId = @uid
        `);

  if (r.rowsAffected[0] === 0)
    return res.status(403).json({ message: "Sem permissão para editar" });

  res.json({ ok: true });
});

app.delete("/comments/:cid", async (req, res) => {
  const { usuarioId } = req.query;
  const pool = await poolPromise;
  const r = await pool
    .request()
    .input("cid", sql.UniqueIdentifier, req.params.cid)
    .input("uid", sql.UniqueIdentifier, usuarioId).query(`
            DELETE dbo.Comentarios
            WHERE id = @cid AND usuarioId = @uid
        `);

  if (r.rowsAffected[0] === 0)
    return res.status(403).json({ message: "Sem permissão para excluir" });

  res.json({ ok: true });
});

/* ---------- RELACIONAMENTO (followers / following) -------------------*/
app.post("/follow", async (req, res) => {
  const { seguidorId, seguidoId } = req.body || {};
  if (!seguidorId || !seguidoId)
    return res
      .status(400)
      .json({ message: "seguidorId e seguidoId obrigatórios" });

  const pool = await poolPromise;
  await pool
    .request()
    .input("a", sql.UniqueIdentifier, seguidorId)
    .input("b", sql.UniqueIdentifier, seguidoId).query(`
            IF NOT EXISTS (SELECT 1 FROM dbo.Seguidores WHERE seguidorId=@a AND seguidoId=@b)
                INSERT dbo.Seguidores(seguidorId,seguidoId) VALUES (@a,@b)
        `);

  res.json({ following: true });
});

app.delete("/follow", async (req, res) => {
  const { seguidorId, seguidoId } = req.query || {};
  if (!seguidorId || !seguidoId)
    return res
      .status(400)
      .json({ message: "seguidorId e seguidoId obrigatórios" });

  const pool = await poolPromise;
  await pool
    .request()
    .input("a", sql.UniqueIdentifier, seguidorId)
    .input("b", sql.UniqueIdentifier, seguidoId)
    .query("DELETE dbo.Seguidores WHERE seguidorId=@a AND seguidoId=@b");

  res.json({ following: false });
});

app.get("/follow/status", async (req, res) => {
  const { seguidorId, seguidoId } = req.query;
  const pool = await poolPromise;
  const r = await pool
    .request()
    .input("a", sql.UniqueIdentifier, seguidorId)
    .input("b", sql.UniqueIdentifier, seguidoId)
    .query("SELECT 1 FROM dbo.Seguidores WHERE seguidorId=@a AND seguidoId=@b");
  res.json({ following: !!r.recordset.length });
});

app.get("/users/:id/followers/count", async (req, res) => {
  try {
    const pool = await poolPromise;
    const r = await pool
      .request()
      .input("id", sql.UniqueIdentifier, req.params.id).query(`
                SELECT COUNT(*) AS total
                FROM   dbo.Seguidores
                WHERE  seguidoId = @id
            `);

    res.json({ total: r.recordset[0].total });
  } catch (err) {
    console.error("followers/count:", err);
    res.status(500).json({ message: "Erro interno" });
  }
});

app.get("/users/:id/following/count", async (req, res) => {
  try {
    const pool = await poolPromise;
    const r = await pool
      .request()
      .input("id", sql.UniqueIdentifier, req.params.id).query(`
                SELECT COUNT(*) AS total
                FROM   dbo.Seguidores
                WHERE  seguidorId = @id
            `);

    res.json({ total: r.recordset[0].total });
  } catch (err) {
    console.error("following/count:", err);
    res.status(500).json({ message: "Erro interno" });
  }
});

/* ---------- DENUNCIAS ----------------------------------------------- */
const transporter = nodemailer.createTransport({
  host: process.env.REPORT_SMTP_HOST,
  port: Number(process.env.REPORT_SMTP_PORT),
  secure: process.env.REPORT_SMTP_SECURE === "true",
  auth: {
    user: process.env.REPORT_SMTP_USER,
    pass: process.env.REPORT_SMTP_PASS,
  },
});

app.post("/validate-report", async (req, res) => {
  const { postId, reason } = req.body;
  if (!postId || !reason) {
    return res
      .status(400)
      .json({ message: "ID do Post e o motivo são obrigatórios." });
  }

  try {
    const pool = await poolPromise;
    const postResult = await pool
      .request()
      .input("id", sql.UniqueIdentifier, postId)
      .query("SELECT imagemData FROM dbo.Posts WHERE id = @id");

    const imageBuffer = postResult.recordset[0]?.imagemData;
    if (!imageBuffer) {
      return res
        .status(404)
        .json({ message: "Imagem do post não encontrada." });
    }
    const imageBase64 = imageBuffer.toString("base64");

    const prompt = `
            Você é um moderador de conteúdo especialista para o aplicativo "SpotClick".
            O SpotClick é uma rede social de crowdsourcing focada em descobrir e partilhar pontos turísticos interessantes através da comunidade. O objetivo é que os próprios utilizadores definam o que é um ponto turístico.
            A sua tarefa é analisar uma denúncia feita por um utilizador e determinar se ela é válida.
            Uma denúncia é VÁLIDA se o texto da denúncia descrever um problema real e relevante que viole as regras da comunidade, tais como:
            - A imagem contém conteúdo explícito (nudez, violência, discurso de ódio).
            - A imagem e o texto são claramente publicidade, promoção de uma loja ou spam comercial.
            - O conteúdo não tem qualquer relação com turismo, viagens ou descoberta de locais (ex: uma selfie em casa, uma foto de um prato de comida sem contexto de restaurante, etc.).
            Uma denúncia é INVÁLIDA se:
            - O texto da denúncia for spam (caracteres aleatórios, nonsense).
            - O texto for um ataque pessoal ou não tiver relação com o conteúdo da imagem.
            - For uma tentativa clara de abusar do sistema de denúncias.
            Analise a IMAGEM e o TEXTO DA DENÚNCIA abaixo.
            Texto da denúncia: "${reason}"
            
            Responda APENAS com um objeto JSON com a seguinte estrutura:
            {
              "isValid": boolean,
              "reasoning": "explique em português e numa frase curta e direta o porquê da sua decisão."
            }
        `;

    const apiKey = process.env.GEMINI_API_KEY;
    const url = `https://generativelanguage.googleapis.com/v1/models/gemini-2.0-flash:generateContent?key=${apiKey}`;

    const payload = {
      contents: [
        {
          parts: [
            { text: prompt },
            {
              inline_data: {
                mime_type: "image/jpeg",
                data: imageBase64,
              },
            },
          ],
        },
      ],
    };

    const { data } = await axios.post(url, payload, {
      headers: { "Content-Type": "application/json" },
    });

    const responseText = data?.candidates?.[0]?.content?.parts?.[0]?.text;
    if (!responseText) {
      throw new Error("A IA não devolveu uma resposta válida.");
    }

    const jsonResponse = JSON.parse(
      responseText
        .replace(/```json/g, "")
        .replace(/```/g, "")
        .trim()
    );

    res.json(jsonResponse);
  } catch (e) {
    console.error(
      "Erro na validação da denúncia com IA:",
      e.response ? e.response.data : e.message
    );
    res
      .status(500)
      .json({ message: "Não foi possível validar a denúncia com a IA." });
  }
});

app.post("/reports", async (req, res) => {
  const { postId, reporterId, reason } = req.body;
  if (!reason?.trim()) {
    return res.status(400).json({ message: "Motivo obrigatório" });
  }

  try {
    const pool = await poolPromise;

    const { recordset: post } = await pool
      .request()
      .input("id", sql.UniqueIdentifier, postId).query(`
                SELECT usuarioId, imagemData
                FROM   dbo.Posts
                WHERE  id = @id
            `);

    if (!post.length) {
      return res.status(404).json({ message: "Post não encontrado" });
    }

    await pool
      .request()
      .input("rid", sql.UniqueIdentifier, uuidv4())
      .input("pid", sql.UniqueIdentifier, postId)
      .input("uid", sql.UniqueIdentifier, reporterId)
      .input("reason", sql.NVarChar, reason.slice(0, 500)).query(`
                INSERT dbo.Reports(id,postId,reporterId,reason)
                VALUES (@rid,@pid,@uid,@reason)
            `);

    await transporter.sendMail({
      from: `"Denúncias AppTurismo" <${process.env.REPORT_SMTP_USER}>`,
      to: process.env.REPORT_MAIL,
      subject: "Nova denúncia de post",
      text: `Post ID: ${postId}\nAutor do post: ${post[0].usuarioId}\nDenunciante : ${reporterId}\n\nMotivo informado:\n${reason}`,
      attachments: [
        {
          filename: `${postId}.jpg`,
          content: post[0].imagemData,
        },
      ],
    });

    res.json({ ok: true });
  } catch (e) {
    console.error("send report:", e);
    res.status(500).json({ message: "Erro ao enviar denúncia" });
  }
});

// Lista de denúncias pendentes para admin
app.get("/admin/reports", adminOnly, async (req, res) => {
  try {
    const r = await poolPromise.then((p) =>
      p.request().query(`
                -- CORREÇÃO DE ROBUSTEZ: Trocado JOIN por LEFT JOIN
                -- Isso garante que a denúncia apareça mesmo que o usuário denunciante tenha sido deletado.
                SELECT r.id, r.postId, r.reason, r.createdAt,
                        u.nome + ' ' + ISNULL(u.sobrenome,'') AS reporterName
                FROM dbo.Reports r
                LEFT JOIN dbo.Usuarios u ON u.id = r.reporterId
                WHERE r.resolvedAt IS NULL
                ORDER BY r.createdAt
            `)
    );
    res.json(r.recordset);
  } catch (err) {
    console.error("GET /admin/reports error:", err);
    res.status(500).json({ message: "Erro ao buscar denúncias." });
  }
});

// Apagar o post e marcar denúncia como resolvida
app.post("/admin/reports/:id/delete", adminOnly, async (req, res) => {
  const { id } = req.params;
  const pool = await poolPromise;

  const { recordset } = await pool
    .request()
    .input("id", sql.UniqueIdentifier, id)
    .query("SELECT postId FROM dbo.Reports WHERE id=@id");

  if (!recordset.length) return res.status(404).send("Denúncia não encontrada");
  const { postId } = recordset[0];

  await pool.request().input("pid", sql.UniqueIdentifier, postId).query(`
            DELETE dbo.PostLikes WHERE postId=@pid;
            DELETE dbo.Comentarios WHERE postId=@pid;
            DELETE dbo.Posts       WHERE id=@pid;
        `);

  await pool.request().input("id", sql.UniqueIdentifier, id).query(`
            UPDATE dbo.Reports
                SET resolvedAt=SYSUTCDATETIME(),
                    resolution='deleted'
                WHERE id=@id
        `);
  res.json({ ok: true });
});

// Ignorar denúncia
app.post("/admin/reports/:id/ignore", adminOnly, async (req, res) => {
  await poolPromise.then((p) =>
    p.request().input("id", sql.UniqueIdentifier, req.params.id).query(`
            UPDATE dbo.Reports
                SET resolvedAt=SYSUTCDATETIME(),
                    resolution='ignored'
            WHERE id=@id
        `)
  );
  res.json({ ok: true });
});

/* ---------- OUTRAS ROTAS --------------------------------------------- */
app.get("/tourist-spots", async (req, res) => {
  const { lat, lng, radius } = req.query;

  if (!lat || !lng || !radius) {
    return res
      .status(400)
      .json({ message: "Latitude, longitude e raio são obrigatórios." });
  }

  try {
    const pool = await poolPromise;
    const result = await pool
      .request()
      .input("userLat", sql.Float, parseFloat(lat))
      .input("userLng", sql.Float, parseFloat(lng))
      .input("radiusKm", sql.Float, parseFloat(radius)).query(`
                WITH SpotsWithDistance AS (
                    SELECT
                        id, legenda, latitude, longitude,
                        (
                            6371 * acos(
                                cos(radians(@userLat)) * cos(radians(latitude)) *
                                cos(radians(longitude) - radians(@userLng)) +
                                sin(radians(@userLat)) * sin(radians(latitude))
                            )
                        ) AS distancia_km
                    FROM
                        dbo.Posts
                    WHERE
                        isPontoTuristico = 1 AND latitude IS NOT NULL AND longitude IS NOT NULL
                )
                SELECT
                    id, legenda, latitude, longitude, distancia_km
                FROM
                    SpotsWithDistance
                WHERE
                    distancia_km <= @radiusKm
                ORDER BY
                    distancia_km;
            `);

    res.json(result.recordset);
  } catch (err) {
    console.error("Erro ao buscar pontos turísticos:", err);
    res.status(500).json({ message: "Erro interno no servidor" });
  }
});

app.post("/generate-description", async (req, res) => {
  try {
    const { prompt } = req.body;
    if (!prompt) {
      return res.status(400).json({ message: "O prompt é obrigatório." });
    }
    const descricao = await gerarDescricaoIA(prompt);
    if (descricao) {
      res.status(200).json({ description: descricao });
    } else {
      res
        .status(500)
        .json({ message: "A IA não conseguiu gerar uma descrição." });
    }
  } catch (error) {
    console.error("Erro na rota /generate-description:", error);
    res.status(500).json({ message: "Erro interno no servidor." });
  }
});

app.get("/search", async (req, res) => {
  const { q: searchTerm } = req.query;

  if (!searchTerm || searchTerm.trim().length < 2) {
    return res.json({ users: [], posts: [] });
  }

  try {
    const pool = await poolPromise;
    const usersResult = await pool
      .request()
      .input("term", sql.NVarChar, `%${searchTerm}%`).query(`
                SELECT TOP 5 id, nome, sobrenome,
                        CASE WHEN fotoPerfilData IS NOT NULL THEN 1 ELSE 0 END AS hasAvatar
                FROM dbo.Usuarios
                WHERE (nome + ' ' + sobrenome) LIKE @term;
            `);

    const users = usersResult.recordset.map((u) => ({
      ...u,
      fotoPerfil: buildAvatarUrl(req, u.id, u.hasAvatar),
    }));

    const postsResult = await pool
      .request()
      .input("term", sql.NVarChar, `%${searchTerm}%`).query(`
                SELECT DISTINCT TOP 10 p.id, p.legenda, p.localNome
                FROM dbo.Posts AS p
                LEFT JOIN dbo.PostTags AS pt ON p.id = pt.postId
                LEFT JOIN dbo.Tags AS t ON pt.tagId = t.id
                WHERE p.localNome LIKE @term 
                    OR p.legenda LIKE @term 
                    OR t.nome LIKE @term;
            `);

    res.json({ users: users, posts: postsResult.recordset });
  } catch (err) {
    console.error("Erro na busca:", err);
    res.status(500).json({ message: "Erro interno ao realizar a busca." });
  }
});

/* =================================================================
 * START
 * =================================================================*/
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`API rodando em http://localhost:${PORT}`));
