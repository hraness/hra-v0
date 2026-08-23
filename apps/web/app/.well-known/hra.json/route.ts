import {
  HRA_DEPLOYMENT_IDENTITY,
} from "../../deployment-identity";

const body = `${JSON.stringify(HRA_DEPLOYMENT_IDENTITY, undefined, 2)}\n`;
const headers = {
  "Cache-Control": "public, max-age=0, must-revalidate",
  "Content-Type": "application/json; charset=utf-8",
} as const;

export function GET(): Response {
  return new Response(body, { headers, status: 200 });
}

export function HEAD(): Response {
  return new Response(null, { headers, status: 200 });
}
