import {
  createHraSecurityTxt,
} from "../../site";

export const HRA_SECURITY_TXT = createHraSecurityTxt();

const headers = {
  "Cache-Control": "public, max-age=0, must-revalidate",
  "Content-Type": "text/plain; charset=utf-8",
} as const;

export function GET(): Response {
  return new Response(HRA_SECURITY_TXT, { headers, status: 200 });
}

export function HEAD(): Response {
  return new Response(null, { headers, status: 200 });
}
