require("dotenv").config();
const axios = require("axios");

// A função agora recebe o prompt completo como argumento.
async function gerarDescricaoIA(prompt) {
  const GEMINI_API_KEY = process.env.GEMINI_API_KEY;
  if (!GEMINI_API_KEY) {
    console.error("Chave da API Gemini não configurada no .env do servidor");
    throw new Error("Chave da API Gemini não configurada");
  }

  // A URL da API com a chave e o nome do modelo.
  const url = `https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash-latest:generateContent?key=${GEMINI_API_KEY}`;

  // O corpo da requisição agora usa o prompt recebido diretamente.
  const requestBody = {
    contents: [{ parts: [{ text: prompt }] }],
  };

  try {
    // Faz a chamada POST para a URL.
    const { data } = await axios.post(url, requestBody, {
      headers: {
        "Content-Type": "application/json",
      },
    });

    // Extrai o texto da resposta da API.
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
