require("dotenv").config();
const axios = require("axios");

async function gerarDescricaoIA(prompt) {
  const GEMINI_API_KEY = process.env.GEMINI_API_KEY;
  if (!GEMINI_API_KEY) {
    console.error("Chave da API Gemini não configurada no .env do servidor");
    throw new Error("Chave da API Gemini não configurada");
  }

  const url = `https://generativelanguage.googleapis.com/v1/models/gemini-1.5-flash:generateContent?key=${GEMINI_API_KEY}`;

  const requestBody = {
    contents: [{ parts: [{ text: prompt }] }],
  };

  try {
    const { data } = await axios.post(url, requestBody, {
      headers: {
        "Content-Type": "application/json",
      },
    });

    const textoGerado = data?.candidates?.[0]?.content?.parts?.[0]?.text;

    if (textoGerado) {
      console.log("Descrição gerada pela IA:", textoGerado);
      return textoGerado;
    } else {
      console.warn("A API Gemini retornou uma resposta vazia.");
      return null;
    }
  } catch (error) {
    if (error.response) {
      console.error(
        "Erro na API Gemini:",
        error.response.status,
        error.response.data
      );
    } else {
      console.error("Erro na API Gemini:", error.message);
    }
    return null;
  }
}

module.exports = { gerarDescricaoIA };
