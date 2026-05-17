"use client";

import { useEffect, useState, useCallback, useRef } from "react";
import { useRouter, useSearchParams } from "next/navigation";
import { useNopassStore, ItemEditor, OrgPanel } from "@nopass/ui";
import { decryptItem, encryptItem } from "@nopass/crypto";
import { computeTotp } from "@nopass/ui";
import type {
  EncryptedVaultItem,
  VaultItemPlaintext,
  VaultItemType,
  LoginItem,
  NoteItem,
  CardItem,
  IdentityItem,
  SshKeyItem,
} from "@nopass/types";
import { api } from "@/lib/api";

type Filter = "all" | VaultItemType;
type SidebarTab = "vault" | "teams";

const TYPE_LABELS: Record<VaultItemType, string> = {
  login: "Logins",
  note: "Notes",
  card: "Cards",
  identity: "Identities",
  ssh_key: "SSH Keys",
};

const TYPE_COLORS: Record<VaultItemType, string> = {
  login: "bg-blue-100 text-blue-700 dark:bg-blue-900/40 dark:text-blue-300",
  note: "bg-amber-100 text-amber-700 dark:bg-amber-900/40 dark:text-amber-300",
  card: "bg-green-100 text-green-700 dark:bg-green-900/40 dark:text-green-300",
  identity: "bg-purple-100 text-purple-700 dark:bg-purple-900/40 dark:text-purple-300",
  ssh_key: "bg-teal-100 text-teal-700 dark:bg-teal-900/40 dark:text-teal-300",
};

const AVATAR_COLORS = [
  "bg-blue-500",
  "bg-violet-500",
  "bg-emerald-500",
  "bg-amber-500",
  "bg-rose-500",
  "bg-cyan-500",
  "bg-pink-500",
  "bg-indigo-500",
];

function getAvatarColor(name: string): string {
  let hash = 0;
  for (let i = 0; i < name.length; i++) hash = name.charCodeAt(i) + ((hash << 5) - hash);
  return AVATAR_COLORS[Math.abs(hash) % AVATAR_COLORS.length]!;
}

interface DecryptedEntry {
  item: EncryptedVaultItem;
  plaintext: VaultItemPlaintext;
}

function ItemAvatar({ name, type }: { name: string; type: VaultItemType }) {
  const initial = name.trim().charAt(0).toUpperCase() || "?";
  const color = getAvatarColor(name);
  const icons: Record<VaultItemType, React.ReactNode> = {
    login: (
      <svg className="w-4 h-4 text-white" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth="1.75">
        <rect x="3" y="11" width="18" height="11" rx="2" />
        <path d="M7 11V7a5 5 0 0 1 10 0v4" />
      </svg>
    ),
    note: (
      <svg className="w-4 h-4 text-white" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth="1.75">
        <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z" />
        <polyline points="14 2 14 8 20 8" />
        <line x1="16" y1="13" x2="8" y2="13" />
        <line x1="16" y1="17" x2="8" y2="17" />
        <polyline points="10 9 9 9 8 9" />
      </svg>
    ),
    card: (
      <svg className="w-4 h-4 text-white" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth="1.75">
        <rect x="1" y="4" width="22" height="16" rx="2" ry="2" />
        <line x1="1" y1="10" x2="23" y2="10" />
      </svg>
    ),
    identity: (
      <svg className="w-4 h-4 text-white" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth="1.75">
        <path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2" />
        <circle cx="12" cy="7" r="4" />
      </svg>
    ),
    ssh_key: (
      <svg className="w-4 h-4 text-white" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth="1.75">
        <path d="M21 2l-2 2m-7.61 7.61a5.5 5.5 0 1 1-7.778 7.778 5.5 5.5 0 0 1 7.777-7.777zm0 0L15.5 7.5m0 0l3 3L22 7l-3-3m-3.5 3.5L19 4" />
      </svg>
    ),
  };

  return (
    <div className={`w-9 h-9 rounded-xl ${color} flex items-center justify-center shrink-0 shadow-sm`}>
      {icons[type] ?? <span className="text-sm font-bold text-white">{initial}</span>}
    </div>
  );
}

function CopyButton({ text, label = "Copy" }: { text: string; label?: string }) {
  const [copied, setCopied] = useState(false);

  async function handleCopy() {
    try {
      await navigator.clipboard.writeText(text);
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    } catch {
      // clipboard unavailable
    }
  }

  return (
    <button
      onClick={handleCopy}
      title={copied ? "Copied!" : label}
      className={`p-1.5 rounded-md transition-all ${
        copied
          ? "text-green-600 bg-green-50 dark:text-green-400 dark:bg-green-900/30"
          : "text-gray-400 hover:text-gray-600 hover:bg-gray-100 dark:hover:text-gray-300 dark:hover:bg-gray-700"
      }`}
    >
      {copied ? (
        <svg className="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth="2.5">
          <polyline points="20 6 9 17 4 12" />
        </svg>
      ) : (
        <svg className="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth="1.75">
          <rect x="9" y="9" width="13" height="13" rx="2" ry="2" />
          <path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1" />
        </svg>
      )}
    </button>
  );
}

function SecretField({ value }: { value: string }) {
  const [visible, setVisible] = useState(false);
  return (
    <div className="flex items-center gap-1">
      <span className="flex-1 font-mono text-sm text-gray-800 dark:text-gray-200 break-all">
        {visible ? value : "•".repeat(Math.min(value.length, 20))}
      </span>
      <button
        onClick={() => setVisible((v) => !v)}
        className="p-1 text-gray-400 hover:text-gray-600 dark:hover:text-gray-300 rounded transition-colors"
        title={visible ? "Hide" : "Reveal"}
      >
        {visible ? (
          <svg className="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth="1.75">
            <path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94" />
            <path d="M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19" />
            <line x1="1" y1="1" x2="23" y2="23" />
          </svg>
        ) : (
          <svg className="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth="1.75">
            <path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z" />
            <circle cx="12" cy="12" r="3" />
          </svg>
        )}
      </button>
      <CopyButton text={value} label={`Copy ${visible ? "visible" : "hidden"} value`} />
    </div>
  );
}

function DetailField({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div>
      <p className="text-[11px] font-semibold text-gray-400 dark:text-gray-500 uppercase tracking-wider mb-1">{label}</p>
      {children}
    </div>
  );
}

function TotpCode({ uri }: { uri: string }) {
  const [result, setResult] = useState<{ code: string; remainingSeconds: number; period: number } | null>(null);

  useEffect(() => {
    let cancelled = false;
    let intervalId: ReturnType<typeof setInterval> | null = null;

    async function tick() {
      const r = await computeTotp(uri);
      if (!cancelled) setResult(r);
    }

    tick();
    // Align subsequent ticks to wall-clock second boundaries to avoid drift
    const delay = 1000 - (Date.now() % 1000);
    const timeoutId = setTimeout(() => {
      tick();
      intervalId = setInterval(tick, 1000);
    }, delay);

    return () => {
      cancelled = true;
      clearTimeout(timeoutId);
      if (intervalId !== null) clearInterval(intervalId);
    };
  }, [uri]);

  if (!result) return null;

  const { code, remainingSeconds, period } = result;
  const fraction = remainingSeconds / period;
  const urgent = remainingSeconds <= 5;
  const radius = 9;
  const circumference = 2 * Math.PI * radius;
  const dashOffset = circumference * (1 - fraction);

  return (
    <div className="flex items-center gap-2">
      <span className={`font-mono text-xl font-bold tracking-widest ${urgent ? "text-red-500 dark:text-red-400" : "text-gray-900 dark:text-white"}`}>
        {code.slice(0, 3)} {code.slice(3)}
      </span>
      <svg width="24" height="24" viewBox="0 0 24 24" className="shrink-0">
        <circle cx="12" cy="12" r={radius} fill="none" stroke="currentColor" strokeWidth="2" className="text-gray-200 dark:text-gray-700" />
        <circle
          cx="12"
          cy="12"
          r={radius}
          fill="none"
          stroke="currentColor"
          strokeWidth="2"
          strokeDasharray={circumference}
          strokeDashoffset={dashOffset}
          strokeLinecap="round"
          transform="rotate(-90 12 12)"
          className={`transition-[stroke-dashoffset] ${urgent ? "text-red-500 dark:text-red-400" : "text-blue-500 dark:text-blue-400"}`}
        />
        <text x="12" y="16" textAnchor="middle" className="fill-current text-gray-500 dark:text-gray-400" style={{ fontSize: "7px" }}>
          {remainingSeconds}s
        </text>
      </svg>
      <CopyButton text={code} label="Copy code" />
    </div>
  );
}

function LoginDetail({ login }: { login: LoginItem }) {
  return (
    <>
      {login.username && (
        <DetailField label="Username / Email">
          <div className="flex items-center gap-1">
            <span className="text-sm text-gray-800 dark:text-gray-200 break-all flex-1">{login.username}</span>
            <CopyButton text={login.username} label="Copy username" />
          </div>
        </DetailField>
      )}
      {login.password && (
        <DetailField label="Password">
          <SecretField value={login.password} />
        </DetailField>
      )}
      {login.totp && (
        <DetailField label="One-Time Password">
          <TotpCode uri={login.totp} />
        </DetailField>
      )}
      {login.urls && login.urls.length > 0 && (
        <DetailField label="Website">
          {login.urls.map((url) => (
            <a
              key={url}
              href={url}
              target="_blank"
              rel="noopener noreferrer"
              className="text-sm text-blue-600 dark:text-blue-400 hover:underline break-all block"
            >
              {url}
            </a>
          ))}
        </DetailField>
      )}
      {login.notes && (
        <DetailField label="Notes">
          <p className="text-sm text-gray-700 dark:text-gray-300 whitespace-pre-wrap break-words">{login.notes}</p>
        </DetailField>
      )}
    </>
  );
}

function NoteDetail({ note }: { note: NoteItem }) {
  return (
    <DetailField label="Content">
      <p className="text-sm text-gray-700 dark:text-gray-300 whitespace-pre-wrap break-words leading-relaxed">
        {note.content}
      </p>
    </DetailField>
  );
}

function CardDetail({ card }: { card: CardItem }) {
  return (
    <>
      {card.cardholderName && (
        <DetailField label="Cardholder">
          <span className="text-sm text-gray-800 dark:text-gray-200">{card.cardholderName}</span>
        </DetailField>
      )}
      {card.number && (
        <DetailField label="Card number">
          <SecretField value={card.number} />
        </DetailField>
      )}
      {(card.expMonth || card.expYear) && (
        <DetailField label="Expiry">
          <span className="text-sm text-gray-800 dark:text-gray-200">
            {card.expMonth}/{card.expYear}
          </span>
        </DetailField>
      )}
      {card.cvv && (
        <DetailField label="CVV">
          <SecretField value={card.cvv} />
        </DetailField>
      )}
    </>
  );
}

function IdentityDetail({ identity }: { identity: IdentityItem }) {
  const fields: Array<[string, string | undefined]> = [
    ["First name", identity.firstName],
    ["Last name", identity.lastName],
    ["Email", identity.email],
    ["Phone", identity.phone],
    ["Address", identity.address],
    ["City", identity.city],
    ["Country", identity.country],
  ];
  return (
    <>
      {fields
        .filter(([, v]) => v)
        .map(([label, value]) => (
          <DetailField key={label} label={label}>
            <div className="flex items-center gap-1">
              <span className="text-sm text-gray-800 dark:text-gray-200 flex-1">{value}</span>
              <CopyButton text={value!} label={`Copy ${label.toLowerCase()}`} />
            </div>
          </DetailField>
        ))}
    </>
  );
}

function SshKeyDetail({ sshKey }: { sshKey: SshKeyItem }) {
  return (
    <>
      {sshKey.publicKey && (
        <DetailField label="Public key">
          <div className="flex items-start gap-1">
            <span className="flex-1 font-mono text-xs text-gray-800 dark:text-gray-200 break-all leading-relaxed">
              {sshKey.publicKey}
            </span>
            <CopyButton text={sshKey.publicKey} label="Copy public key" />
          </div>
        </DetailField>
      )}
      <DetailField label="Private key">
        <SecretField value={sshKey.privateKey} />
      </DetailField>
      {sshKey.passphrase && (
        <DetailField label="Passphrase">
          <SecretField value={sshKey.passphrase} />
        </DetailField>
      )}
      {sshKey.comment && (
        <DetailField label="Comment">
          <div className="flex items-center gap-1">
            <span className="text-sm text-gray-800 dark:text-gray-200 flex-1 font-mono">{sshKey.comment}</span>
            <CopyButton text={sshKey.comment} label="Copy comment" />
          </div>
        </DetailField>
      )}
      {sshKey.notes && (
        <DetailField label="Notes">
          <p className="text-sm text-gray-700 dark:text-gray-300 whitespace-pre-wrap break-words">{sshKey.notes}</p>
        </DetailField>
      )}
    </>
  );
}

function DetailPane({
  entry,
  onEdit,
  onDelete,
  onClose,
}: {
  entry: DecryptedEntry;
  onEdit: () => void;
  onDelete: () => void;
  onClose: () => void;
}) {
  const [confirmDelete, setConfirmDelete] = useState(false);
  const { plaintext, item } = entry;

  return (
    <aside className="w-96 flex flex-col border-l border-gray-200 dark:border-gray-700 bg-white dark:bg-gray-800 shrink-0 animate-slide-in-right">
      {/* Header */}
      <div className="flex items-start gap-3 px-5 py-4 border-b border-gray-200 dark:border-gray-700">
        <ItemAvatar name={plaintext.name} type={item.itemType} />
        <div className="flex-1 min-w-0 pt-0.5">
          <h2 className="text-sm font-semibold text-gray-900 dark:text-white truncate">{plaintext.name}</h2>
          <p className="text-xs text-gray-400 dark:text-gray-500 mt-0.5">{TYPE_LABELS[item.itemType].slice(0, -1)}</p>
        </div>
        <div className="flex items-center gap-1 shrink-0">
          <button
            onClick={onEdit}
            className="px-3 py-1.5 text-xs font-medium text-gray-600 dark:text-gray-400 hover:text-gray-900 dark:hover:text-white hover:bg-gray-100 dark:hover:bg-gray-700 rounded-lg transition-colors border border-gray-200 dark:border-gray-700"
          >
            Edit
          </button>
          <button
            onClick={onClose}
            className="p-1.5 text-gray-400 hover:text-gray-600 dark:hover:text-gray-300 hover:bg-gray-100 dark:hover:bg-gray-700 rounded-lg transition-colors"
            title="Close"
          >
            <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth="2">
              <line x1="18" y1="6" x2="6" y2="18" />
              <line x1="6" y1="6" x2="18" y2="18" />
            </svg>
          </button>
        </div>
      </div>

      {/* Fields */}
      <div className="flex-1 overflow-y-auto p-5 space-y-5">
        {plaintext.type === "login" && <LoginDetail login={plaintext as LoginItem} />}
        {plaintext.type === "note" && <NoteDetail note={plaintext as NoteItem} />}
        {plaintext.type === "card" && <CardDetail card={plaintext as CardItem} />}
        {plaintext.type === "identity" && <IdentityDetail identity={plaintext as IdentityItem} />}
        {plaintext.type === "ssh_key" && <SshKeyDetail sshKey={plaintext as SshKeyItem} />}

        <div className="text-[11px] text-gray-300 dark:text-gray-600 pt-2 border-t border-gray-100 dark:border-gray-700">
          <p>ID {item.id.slice(0, 8)}… · v{item.version}</p>
        </div>
      </div>

      {/* Delete */}
      <div className="p-4 border-t border-gray-100 dark:border-gray-700">
        {confirmDelete ? (
          <div className="bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 rounded-lg p-3">
            <p className="text-xs text-red-700 dark:text-red-400 mb-3 font-medium">
              Delete this item permanently?
            </p>
            <div className="flex gap-2">
              <button
                onClick={() => setConfirmDelete(false)}
                className="flex-1 py-1.5 text-xs text-gray-600 dark:text-gray-400 hover:bg-gray-100 dark:hover:bg-gray-700 rounded-md transition-colors"
              >
                Cancel
              </button>
              <button
                onClick={onDelete}
                className="flex-1 py-1.5 text-xs font-medium text-white bg-red-600 hover:bg-red-700 rounded-md transition-colors"
              >
                Delete
              </button>
            </div>
          </div>
        ) : (
          <button
            onClick={() => setConfirmDelete(true)}
            className="w-full py-1.5 text-xs text-red-500 hover:text-red-700 dark:hover:text-red-400 hover:bg-red-50 dark:hover:bg-red-900/20 rounded-lg transition-colors"
          >
            Delete item
          </button>
        )}
      </div>
    </aside>
  );
}

function Toast({ message }: { message: string }) {
  return (
    <div className="fixed bottom-6 left-1/2 z-50 px-4 py-2 bg-gray-900 dark:bg-gray-100 text-white dark:text-gray-900 text-sm rounded-full shadow-lg animate-toast pointer-events-none">
      {message}
    </div>
  );
}

export default function VaultPage() {
  const router = useRouter();
  const searchParams = useSearchParams();
  const {
    isUnlocked,
    sessionToken,
    defaultVaultId,
    vaultEncKey,
    vaultMacKey,
    items,
    isLoading,
    email: userEmail,
    setItems,
    upsertItem,
    markDeleted,
    setLoading,
    lock,
  } = useNopassStore();

  const [decrypted, setDecrypted] = useState<Map<string, VaultItemPlaintext>>(new Map());
  const [filter, setFilter] = useState<Filter>("all");
  const [search, setSearch] = useState("");
  const [sidebarTab, setSidebarTab] = useState<SidebarTab>("vault");
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [modal, setModal] = useState<
    | { mode: "create"; itemType: VaultItemType }
    | { mode: "edit"; entry: DecryptedEntry }
    | null
  >(null);
  const [typePicker, setTypePicker] = useState(false);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [toast, setToast] = useState<{ message: string; id: number } | null>(null);
  const typePickerRef = useRef<HTMLDivElement>(null);
  const searchRef = useRef<HTMLInputElement>(null);

  const selectedEntry = selectedId
    ? (() => {
        const item = items.find((i) => i.id === selectedId);
        const plaintext = item ? decrypted.get(item.id) : undefined;
        return item && plaintext ? { item, plaintext } : null;
      })()
    : null;

  function showToast(message: string) {
    const id = Date.now();
    setToast({ message, id });
    setTimeout(() => setToast((t) => (t?.id === id ? null : t)), 2000);
  }

  async function copyToClipboard(text: string, successMessage: string) {
    try {
      await navigator.clipboard.writeText(text);
      showToast(successMessage);
    } catch {
      // clipboard unavailable
    }
  }

  // Deep-link: /vault?item=ID (e.g. from health page)
  useEffect(() => {
    const itemId = searchParams.get("item");
    if (itemId) {
      setSelectedId(itemId);
      router.replace("/vault");
    }
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // Autofocus search on mount
  useEffect(() => {
    const timer = setTimeout(() => searchRef.current?.focus(), 50);
    return () => clearTimeout(timer);
  }, []);

  // Close type picker on outside click
  useEffect(() => {
    if (!typePicker) return;
    function handleClick(e: MouseEvent) {
      if (typePickerRef.current && !typePickerRef.current.contains(e.target as Node)) {
        setTypePicker(false);
      }
    }
    document.addEventListener("mousedown", handleClick);
    return () => document.removeEventListener("mousedown", handleClick);
  }, [typePicker]);

  // Keyboard shortcuts
  useEffect(() => {
    function handleKey(e: KeyboardEvent) {
      const tag = (e.target as HTMLElement).tagName;
      const inInput = tag === "INPUT" || tag === "TEXTAREA" || tag === "SELECT";

      if (e.key === "Escape") {
        if (modal) { setModal(null); return; }
        if (selectedId) { setSelectedId(null); return; }
      }

      if (!inInput && !modal) {
        if ((e.metaKey || e.ctrlKey) && e.key === "k") {
          e.preventDefault();
          searchRef.current?.focus();
          return;
        }
        if (e.key === "/" && !selectedId) {
          e.preventDefault();
          searchRef.current?.focus();
          return;
        }
        if (e.key === "n" && !typePicker) {
          setTypePicker(true);
          return;
        }
        // Quick-copy shortcuts when a login item is selected
        if (selectedEntry?.plaintext.type === "login") {
          const login = selectedEntry.plaintext as LoginItem;
          if (e.key === "c" && login.password) {
            e.preventDefault();
            copyToClipboard(login.password, "Password copied");
            return;
          }
          if (e.key === "u" && login.username) {
            e.preventDefault();
            copyToClipboard(login.username, "Username copied");
            return;
          }
        }
      }
    }
    document.addEventListener("keydown", handleKey);
    return () => document.removeEventListener("keydown", handleKey);
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [modal, selectedId, typePicker, selectedEntry]);

  useEffect(() => {
    if (!isUnlocked()) router.replace("/login");
  }, [isUnlocked, router]);

  useEffect(() => {
    if (!isUnlocked() || !sessionToken || !defaultVaultId) return;
    setLoading(true);
    api.vault
      .items(defaultVaultId, sessionToken)
      .then((apiItems) => setItems(apiItems))
      .catch((err) => setError(err instanceof Error ? err.message : "Failed to load vault"))
      .finally(() => setLoading(false));
  }, [isUnlocked, sessionToken, defaultVaultId, setItems, setLoading]);

  useEffect(() => {
    if (!vaultEncKey || !vaultMacKey) return;
    const enc = vaultEncKey;
    const mac = vaultMacKey;
    const active = items.filter((i) => i.deletedAt === null);

    Promise.all(
      active.map(async (item) => {
        try {
          const plain = await decryptItem(item, enc, mac);
          return [item.id, plain] as const;
        } catch {
          return null;
        }
      }),
    ).then((results) => {
      const map = new Map<string, VaultItemPlaintext>();
      for (const r of results) {
        if (r) map.set(r[0], r[1]);
      }
      setDecrypted(map);
    });
  }, [items, vaultEncKey, vaultMacKey]);

  const handleSave = useCallback(
    async (plaintext: VaultItemPlaintext) => {
      if (!sessionToken || !defaultVaultId || !vaultEncKey || !vaultMacKey) return;
      setSaving(true);
      setError(null);
      try {
        const encrypted = await encryptItem(plaintext, vaultEncKey, vaultMacKey);
        if (modal?.mode === "create") {
          const created = await api.vault.create(
            defaultVaultId,
            { itemType: plaintext.type, blob: encrypted.blob, blobIv: encrypted.blobIv, blobMac: encrypted.blobMac },
            sessionToken,
          );
          upsertItem(created);
          setSelectedId(created.id);
          showToast("Item saved");
        } else if (modal?.mode === "edit") {
          await api.vault.update(
            defaultVaultId,
            modal.entry.item.id,
            { blob: encrypted.blob, blobIv: encrypted.blobIv, blobMac: encrypted.blobMac, version: modal.entry.item.version },
            sessionToken,
          );
          upsertItem({
            ...modal.entry.item,
            blob: encrypted.blob,
            blobIv: encrypted.blobIv,
            blobMac: encrypted.blobMac,
            version: modal.entry.item.version + 1,
          });
          setSelectedId(modal.entry.item.id);
          showToast("Changes saved");
        }
        setModal(null);
      } catch (err) {
        setError(err instanceof Error ? err.message : "Save failed");
      } finally {
        setSaving(false);
      }
    },
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [modal, sessionToken, defaultVaultId, vaultEncKey, vaultMacKey, upsertItem],
  );

  const handleDelete = useCallback(
    async (itemId: string) => {
      if (!sessionToken || !defaultVaultId) return;
      try {
        await api.vault.delete(defaultVaultId, itemId, sessionToken);
        markDeleted(itemId);
        setSelectedId(null);
        showToast("Item deleted");
      } catch (err) {
        setError(err instanceof Error ? err.message : "Delete failed");
      }
    },
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [sessionToken, defaultVaultId, markDeleted],
  );

  const handleLock = useCallback(() => {
    lock();
    router.replace("/login");
  }, [lock, router]);

  const activeItems = items.filter((i) => i.deletedAt === null);
  const filteredItems = activeItems.filter((item) => {
    if (filter !== "all" && item.itemType !== filter) return false;
    if (search) {
      const plain = decrypted.get(item.id);
      if (!plain) return false;
      return plain.name.toLowerCase().includes(search.toLowerCase());
    }
    return true;
  });

  useEffect(() => {
    document.title = "Vault — nopwd";
  }, []);

  if (!isUnlocked()) return null;

  const userInitial = userEmail ? userEmail.charAt(0).toUpperCase() : "?";

  return (
    <div className="flex h-screen bg-gray-50 dark:bg-gray-900">
      {/* Sidebar */}
      <aside className="w-56 flex flex-col border-r border-gray-200 dark:border-gray-700 bg-white dark:bg-gray-800 shrink-0">
        {/* Logo */}
        <div className="px-4 py-4 border-b border-gray-200 dark:border-gray-700">
          <div className="flex items-center gap-2">
            <div className="w-7 h-7 rounded-lg bg-blue-600 flex items-center justify-center shrink-0">
              <svg className="w-[14px] h-[14px] text-white" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth="2">
                <rect x="3" y="11" width="18" height="11" rx="2" />
                <path d="M7 11V7a5 5 0 0 1 10 0v4" />
              </svg>
            </div>
            <span className="font-semibold text-sm text-gray-900 dark:text-white tracking-tight">nopwd</span>
          </div>
        </div>

        {/* Tab switcher */}
        <div className="flex border-b border-gray-200 dark:border-gray-700 shrink-0">
          {(["vault", "teams"] as SidebarTab[]).map((tab) => (
            <button
              key={tab}
              onClick={() => setSidebarTab(tab)}
              className={`flex-1 py-2 text-xs font-medium transition-colors ${
                sidebarTab === tab
                  ? "text-blue-600 dark:text-blue-400 border-b-2 border-blue-600 dark:border-blue-400"
                  : "text-gray-400 dark:text-gray-500 hover:text-gray-600 dark:hover:text-gray-300"
              }`}
            >
              {tab === "vault" ? "Vault" : "Teams"}
            </button>
          ))}
        </div>

        {sidebarTab === "vault" ? (
          <nav className="flex-1 overflow-y-auto p-2">
            {(["all", "login", "note", "card", "identity", "ssh_key"] as Filter[]).map((f) => {
              const count = f === "all" ? activeItems.length : activeItems.filter((i) => i.itemType === f).length;
              const isActive = filter === f;
              return (
                <button
                  key={f}
                  onClick={() => setFilter(f)}
                  className={`w-full text-left px-3 py-2 rounded-lg text-sm transition-colors flex items-center justify-between mb-0.5 ${
                    isActive
                      ? "bg-blue-50 dark:bg-blue-900/30 text-blue-700 dark:text-blue-300 font-medium"
                      : "text-gray-600 dark:text-gray-400 hover:bg-gray-100 dark:hover:bg-gray-700 hover:text-gray-900 dark:hover:text-white"
                  }`}
                >
                  <span>{f === "all" ? "All items" : TYPE_LABELS[f]}</span>
                  <span className={`text-xs tabular-nums ${isActive ? "text-blue-500 dark:text-blue-400" : "text-gray-400 dark:text-gray-500"}`}>
                    {count}
                  </span>
                </button>
              );
            })}
          </nav>
        ) : (
          <div className="flex-1 overflow-y-auto">
            {sessionToken && (
              <OrgPanel apiClient={api} sessionToken={sessionToken} />
            )}
          </div>
        )}

        {/* User info + lock */}
        <div className="p-3 border-t border-gray-200 dark:border-gray-700">
          <div className="flex items-center gap-2.5 mb-2">
            <div className="w-7 h-7 rounded-full bg-blue-100 dark:bg-blue-900/40 flex items-center justify-center shrink-0">
              <span className="text-xs font-semibold text-blue-700 dark:text-blue-300">{userInitial}</span>
            </div>
            <p className="text-xs text-gray-500 dark:text-gray-400 truncate flex-1" title={userEmail ?? ""}>
              {userEmail}
            </p>
          </div>
          <button
            onClick={handleLock}
            className="w-full flex items-center gap-2 px-2.5 py-1.5 text-xs text-gray-500 dark:text-gray-400 hover:bg-gray-100 dark:hover:bg-gray-700 hover:text-gray-700 dark:hover:text-gray-200 rounded-lg transition-colors"
          >
            <svg className="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth="1.75">
              <rect x="3" y="11" width="18" height="11" rx="2" />
              <path d="M7 11V7a5 5 0 0 1 10 0v4" />
            </svg>
            Lock vault
          </button>
        </div>
      </aside>

      {/* Main content */}
      <div className="flex-1 flex flex-col min-w-0">
        {/* Toolbar */}
        <header className="flex items-center gap-3 px-5 py-3 border-b border-gray-200 dark:border-gray-700 bg-white dark:bg-gray-800">
          <div className="relative flex-1 max-w-sm">
            <svg className="absolute left-3 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-gray-400" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth="2">
              <circle cx="11" cy="11" r="8" />
              <path d="M21 21l-4.35-4.35" />
            </svg>
            <input
              ref={searchRef}
              type="search"
              placeholder="Search…"
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              className="w-full pl-9 pr-3 py-2 text-sm border border-gray-200 dark:border-gray-600 rounded-lg bg-gray-50 dark:bg-gray-700 text-gray-900 dark:text-white placeholder:text-gray-400 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent transition"
            />
          </div>
          <div className="ml-auto flex items-center gap-2">
            <span className="text-xs text-gray-400 dark:text-gray-500 hidden sm:block">
              <kbd className="px-1.5 py-0.5 bg-gray-100 dark:bg-gray-700 rounded text-gray-400 dark:text-gray-500 font-mono">⌘K</kbd>
            </span>
            <button
              onClick={() => router.push("/vault/health")}
              className="flex items-center gap-1.5 px-3 py-2 text-sm text-gray-600 dark:text-gray-400 hover:bg-gray-100 dark:hover:bg-gray-700 hover:text-gray-800 dark:hover:text-gray-200 rounded-lg font-medium transition-colors"
            >
              <svg className="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth="1.75">
                <path strokeLinecap="round" strokeLinejoin="round" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
              </svg>
              Security
            </button>
            <button
              onClick={() => router.push("/vault/import")}
              className="flex items-center gap-1.5 px-3 py-2 text-sm text-gray-600 dark:text-gray-400 hover:bg-gray-100 dark:hover:bg-gray-700 hover:text-gray-800 dark:hover:text-gray-200 rounded-lg font-medium transition-colors"
            >
              <svg className="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth="1.75">
                <path strokeLinecap="round" strokeLinejoin="round" d="M3 16.5v2.25A2.25 2.25 0 005.25 21h13.5A2.25 2.25 0 0021 18.75V16.5M16.5 12L12 16.5m0 0L7.5 12m4.5 4.5V3" />
              </svg>
              Import
            </button>
            <div className="relative" ref={typePickerRef}>
              <button
                data-testid="new-item-btn"
                onClick={() => setTypePicker((v) => !v)}
                className="flex items-center gap-1.5 px-3.5 py-2 text-sm bg-blue-600 hover:bg-blue-700 text-white rounded-lg font-medium transition-colors"
              >
                <svg className="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth="2.5">
                  <line x1="12" y1="5" x2="12" y2="19" />
                  <line x1="5" y1="12" x2="19" y2="12" />
                </svg>
                New item
              </button>
              {typePicker && (
                <div
                  data-testid="type-picker"
                  className="absolute right-0 top-full mt-1.5 z-40 bg-white dark:bg-gray-800 border border-gray-200 dark:border-gray-700 rounded-xl shadow-lg py-1.5 min-w-[140px]"
                >
                  {(["Login", "Note", "Card", "Identity", "SSH Key"] as const).map((label) => (
                    <button
                      key={label}
                      data-testid={`type-${label.toLowerCase()}`}
                      onClick={() => {
                        const typeMap: Record<string, VaultItemType> = {
                          login: "login", note: "note", card: "card", identity: "identity", "ssh key": "ssh_key",
                        };
                        setModal({ mode: "create", itemType: typeMap[label.toLowerCase()] ?? "login" as VaultItemType });
                        setTypePicker(false);
                        setSelectedId(null);
                      }}
                      className="w-full text-left px-3.5 py-2 text-sm text-gray-700 dark:text-gray-300 hover:bg-gray-100 dark:hover:bg-gray-700 transition-colors"
                    >
                      {label}
                    </button>
                  ))}
                </div>
              )}
            </div>
          </div>
        </header>

        {/* Item list */}
        <main className="flex-1 overflow-y-auto p-5">
          {error && (
            <div className="mb-4 flex items-center gap-2.5 p-3 bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 rounded-lg text-sm text-red-700 dark:text-red-400">
              <svg className="w-4 h-4 shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth="2">
                <circle cx="12" cy="12" r="10" />
                <line x1="12" y1="8" x2="12" y2="12" />
                <line x1="12" y1="16" x2="12.01" y2="16" />
              </svg>
              {error}
              <button onClick={() => setError(null)} className="ml-auto text-gray-400 hover:text-gray-600">
                <svg className="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth="2">
                  <line x1="18" y1="6" x2="6" y2="18" /><line x1="6" y1="6" x2="18" y2="18" />
                </svg>
              </button>
            </div>
          )}

          {isLoading ? (
            <div className="space-y-1.5 max-w-2xl">
              {[...Array(5)].map((_, i) => (
                <div key={i} className="flex items-center gap-3 p-3 rounded-xl bg-white dark:bg-gray-800 border border-gray-100 dark:border-gray-700 animate-pulse">
                  <div className="w-9 h-9 rounded-xl bg-gray-200 dark:bg-gray-700 shrink-0" />
                  <div className="flex-1 space-y-2">
                    <div className="h-3 bg-gray-200 dark:bg-gray-700 rounded w-28" />
                    <div className="h-2.5 bg-gray-100 dark:bg-gray-700/50 rounded w-44" />
                  </div>
                </div>
              ))}
            </div>
          ) : filteredItems.length === 0 ? (
            <div className="flex flex-col items-center justify-center h-64 text-center">
              <div className="w-14 h-14 rounded-2xl bg-gray-100 dark:bg-gray-800 flex items-center justify-center mb-4">
                <svg className="w-7 h-7 text-gray-300 dark:text-gray-600" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth="1.5">
                  <rect x="3" y="11" width="18" height="11" rx="2" />
                  <path d="M7 11V7a5 5 0 0 1 10 0v4" />
                </svg>
              </div>
              <p className="text-sm font-medium text-gray-500 dark:text-gray-400">
                {search ? "No matching items" : "Your vault is empty"}
              </p>
              {!search && (
                <p className="text-xs text-gray-400 dark:text-gray-500 mt-1">
                  Press <kbd className="px-1 py-0.5 bg-gray-100 dark:bg-gray-700 rounded text-[11px] font-mono">N</kbd> or click New item to get started
                </p>
              )}
            </div>
          ) : (
            <div className="max-w-2xl space-y-0.5">
              {filteredItems.map((item) => {
                const plain = decrypted.get(item.id);
                const name = plain?.name ?? "…";
                const subtitle =
                  plain?.type === "login"
                    ? ((plain as LoginItem).username || (plain as LoginItem).urls?.[0] || "")
                    : plain?.type === "card"
                      ? `•••• ${((plain as { lastFour?: string }).lastFour ?? "").padStart(4, "·")}`
                      : plain?.type === "note"
                        ? ((plain as NoteItem).content?.slice(0, 60) ?? "")
                        : "";
                const isSelected = selectedId === item.id;
                const loginPlain = item.itemType === "login" && plain ? (plain as LoginItem) : null;

                return (
                  <div key={item.id} className="group relative flex items-center">
                    <button
                      onClick={() => setSelectedId(isSelected ? null : item.id)}
                      className={`flex-1 flex items-center gap-3 px-3 py-2.5 rounded-xl text-left transition-all ${
                        isSelected
                          ? "bg-blue-50 dark:bg-blue-900/20 border border-blue-200 dark:border-blue-800"
                          : "hover:bg-white dark:hover:bg-gray-800 hover:shadow-sm border border-transparent hover:border-gray-200 dark:hover:border-gray-700"
                      }`}
                    >
                      <ItemAvatar name={name} type={item.itemType} />
                      <div className="flex-1 min-w-0">
                        <p className={`text-sm font-medium truncate ${isSelected ? "text-blue-700 dark:text-blue-300" : "text-gray-900 dark:text-white"}`}>
                          {name}
                        </p>
                        {subtitle && (
                          <p className="text-xs text-gray-400 dark:text-gray-500 truncate mt-0.5">{subtitle}</p>
                        )}
                      </div>
                      <span className={`text-[10px] font-medium px-2 py-0.5 rounded-full shrink-0 transition-opacity ${TYPE_COLORS[item.itemType]} ${loginPlain ? "group-hover:opacity-0" : ""}`}>
                        {TYPE_LABELS[item.itemType].slice(0, -1)}
                      </span>
                    </button>

                    {/* Quick-copy actions for login items — visible on hover */}
                    {loginPlain && (
                      <div className="absolute right-3 flex items-center gap-0.5 opacity-0 group-hover:opacity-100 transition-opacity">
                        {loginPlain.username && (
                          <button
                            onClick={() => copyToClipboard(loginPlain.username!, "Username copied")}
                            title="Copy username (U)"
                            className="p-1.5 text-gray-400 hover:text-gray-700 dark:hover:text-gray-200 hover:bg-gray-200 dark:hover:bg-gray-600 rounded-md transition-colors"
                          >
                            <svg className="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth="1.75">
                              <path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2" />
                              <circle cx="12" cy="7" r="4" />
                            </svg>
                          </button>
                        )}
                        {loginPlain.password && (
                          <button
                            onClick={() => copyToClipboard(loginPlain.password!, "Password copied")}
                            title="Copy password (C)"
                            className="p-1.5 text-gray-400 hover:text-gray-700 dark:hover:text-gray-200 hover:bg-gray-200 dark:hover:bg-gray-600 rounded-md transition-colors"
                          >
                            <svg className="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth="1.75">
                              <rect x="9" y="9" width="13" height="13" rx="2" ry="2" />
                              <path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1" />
                            </svg>
                          </button>
                        )}
                      </div>
                    )}
                  </div>
                );
              })}
            </div>
          )}

          {/* Keyboard shortcut hint — shown only when a login is selected */}
          {selectedEntry?.plaintext.type === "login" && (
            <div className="mt-4 max-w-2xl flex items-center gap-3 text-[11px] text-gray-300 dark:text-gray-600">
              <kbd className="px-1.5 py-0.5 bg-gray-100 dark:bg-gray-700 rounded font-mono text-gray-400">C</kbd>
              <span>copy password</span>
              <kbd className="px-1.5 py-0.5 bg-gray-100 dark:bg-gray-700 rounded font-mono text-gray-400">U</kbd>
              <span>copy username</span>
            </div>
          )}
        </main>
      </div>

      {/* Detail pane */}
      {selectedEntry && (
        <DetailPane
          entry={selectedEntry}
          onEdit={() =>
            setModal({ mode: "edit", entry: selectedEntry })
          }
          onDelete={() => handleDelete(selectedEntry.item.id)}
          onClose={() => setSelectedId(null)}
        />
      )}

      {/* Item editor modal */}
      {modal && (
        <div
          className="fixed inset-0 bg-black/40 backdrop-blur-sm flex items-center justify-center z-50 p-4"
          onClick={(e) => { if (e.target === e.currentTarget) setModal(null); }}
        >
          <div className="bg-white dark:bg-gray-800 rounded-2xl shadow-2xl w-full max-w-lg max-h-[90vh] overflow-hidden flex flex-col">
            <div className="flex items-center justify-between px-6 py-4 border-b border-gray-200 dark:border-gray-700">
              <h2 className="text-base font-semibold text-gray-900 dark:text-white">
                {modal.mode === "create"
                  ? `New ${TYPE_LABELS[modal.itemType].slice(0, -1)}`
                  : `Edit ${TYPE_LABELS[modal.entry.plaintext.type as VaultItemType].slice(0, -1)}`}
              </h2>
              <button
                onClick={() => setModal(null)}
                className="p-1.5 rounded-lg text-gray-400 hover:text-gray-600 hover:bg-gray-100 dark:hover:text-gray-300 dark:hover:bg-gray-700 transition-colors"
              >
                <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth="2">
                  <line x1="18" y1="6" x2="6" y2="18" />
                  <line x1="6" y1="6" x2="18" y2="18" />
                </svg>
              </button>
            </div>
            <div className="overflow-y-auto p-6">
              <ItemEditor
                itemType={modal.mode === "create" ? modal.itemType : modal.entry.plaintext.type}
                initial={modal.mode === "edit" ? modal.entry.plaintext : undefined}
                onSave={handleSave}
                onCancel={() => setModal(null)}
                saving={saving}
              />
            </div>
          </div>
        </div>
      )}

      {/* Toast notification */}
      {toast && <Toast message={toast.message} />}
    </div>
  );
}
