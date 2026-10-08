import OpenAI from "openai";

export const BASE_URL = process.env.TAVIAN_BASE_URL;
export const KEY = process.env.TAVIAN_KEY;
export const NARROW_KEY = process.env.TAVIAN_NARROW_KEY;

// No retries: error tests must see the first answer, not the third.
export const client = (apiKey = KEY) => new OpenAI({ baseURL: BASE_URL, apiKey, maxRetries: 0 });

export const user = (text) => [{ role: "user", content: text }];

export const WEATHER_TOOL = {
  type: "function",
  function: {
    name: "get_weather",
    description: "Get the weather for a city.",
    parameters: {
      type: "object",
      properties: { city: { type: "string" } },
      required: ["city"],
    },
  },
};

export async function collect(stream) {
  const chunks = [];
  for await (const chunk of stream) chunks.push(chunk);
  const text = chunks.map((c) => c.choices[0]?.delta?.content ?? "").join("");
  return { chunks, text };
}
