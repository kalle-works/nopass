import { Section } from "./container";

const ROWS: Array<[string, string, string, string]> = [
  ["Client-side encryption of the vault", "Yes", "Yes", "Yes"],
  ["Client source code available", "Yes, MIT", "No", "Yes, GPL and AGPL"],
  ["Independent security audit published", "Not yet", "Yes", "Yes"],
  ["Master password key derivation", "Argon2id, 64 MiB, 3 passes", "PBKDF2-HMAC-SHA256, plus a Secret Key", "PBKDF2-SHA256 by default, Argon2id optional"],
  ["Login protocol", "SRP-6a, password hash not sent", "SRP", "Derived hash of the password sent to the server"],
  ["Command-line tool", "Yes", "Yes", "Yes"],
  ["Run a command with secrets in its environment", "Yes, nopwd run", "Yes, op run", "Separate product (Secrets Manager)"],
  ["Browser extension and passkeys", "Yes", "Yes", "Yes"],
  ["Mobile apps", "No", "Yes", "Yes"],
  ["SSO, SCIM and enterprise admin", "No", "Yes", "Yes"],
];

export function Comparison() {
  return (
    <Section
      id="compare"
      title="How it compares"
      intro="1Password and Bitwarden are mature, audited products with mobile apps and larger teams behind them. This is where nopwd is the same, different or behind, as of this writing."
    >
      <div className="-mx-4 overflow-x-auto px-4 sm:mx-0 sm:px-0">
        <table className="w-full min-w-[720px] border-collapse text-left text-ui">
          <caption className="sr-only">Feature comparison of nopwd, 1Password and Bitwarden</caption>
          <thead>
            <tr className="border-b border-divider">
              <th scope="col" className="py-3 pr-4 text-meta font-medium text-muted">
                Feature
              </th>
              <th scope="col" className="px-4 py-3 text-meta font-medium text-fg">
                nopwd
              </th>
              <th scope="col" className="px-4 py-3 text-meta font-medium text-muted">
                1Password
              </th>
              <th scope="col" className="px-4 py-3 text-meta font-medium text-muted">
                Bitwarden
              </th>
            </tr>
          </thead>
          <tbody>
            {ROWS.map(([feature, nopwd, onePassword, bitwarden]) => (
              <tr key={feature} className="border-b border-divider align-top">
                <th scope="row" className="py-3 pr-4 font-normal text-fg">
                  {feature}
                </th>
                <td className="px-4 py-3 text-fg">{nopwd}</td>
                <td className="px-4 py-3 text-muted">{onePassword}</td>
                <td className="px-4 py-3 text-muted">{bitwarden}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </Section>
  );
}
