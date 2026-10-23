import { useState } from "react";
import { Button, Field } from "@nopass/ui";

interface UnlockFormProps {
  error: string | null;
  unlocking: boolean;
  initialEmail: string;
  onUnlock: (email: string, password: string) => void;
}

export function UnlockForm({ error, unlocking, initialEmail, onUnlock }: UnlockFormProps) {
  const [email, setEmail] = useState(initialEmail);
  const [password, setPassword] = useState("");

  return (
    <main className="min-h-[360px] p-5 pt-6">
      <p className="text-h3 font-semibold text-fg">nopwd</p>
      <h1 className="mt-6 text-h2 font-semibold text-fg">Unlock your vault</h1>
      <p className="mt-1 text-ui text-muted">Your master password never leaves this device.</p>
      <form
        onSubmit={(e) => {
          e.preventDefault();
          onUnlock(email, password);
        }}
        className="mt-5 flex flex-col gap-4"
      >
        <Field
          label="Email"
          type="email"
          placeholder="you@example.com"
          value={email}
          onChange={(e) => setEmail(e.target.value)}
          required
          autoComplete="email"
          autoFocus={!initialEmail}
        />
        <Field
          label="Master password"
          type="password"
          revealable
          value={password}
          onChange={(e) => setPassword(e.target.value)}
          required
          autoComplete="current-password"
          autoFocus={!!initialEmail}
        />
        {error && (
          <p role="alert" className="text-meta text-danger">
            {error}
          </p>
        )}
        <Button type="submit" variant="primary" size="lg" pending={unlocking} pendingLabel="Unlocking…" className="w-full">
          Unlock
        </Button>
      </form>
    </main>
  );
}
