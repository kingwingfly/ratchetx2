// Deterministic TypeScript fixture exercising preview_code_web.
export interface Greeting {
  target: string;
  marker: string;
}

export function formatGreeting(input: Greeting): string {
  return `Hello ${input.target} [${input.marker}]`;
}
