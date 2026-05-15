import { createApiClient } from "@nopass/ui";

const API_BASE = process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:3001";

export const api = createApiClient(API_BASE);
