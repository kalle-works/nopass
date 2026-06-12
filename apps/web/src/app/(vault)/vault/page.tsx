"use client";

import { useEffect, useState, useCallback, useRef, Suspense } from "react";
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

type Filter = "all" | "favorites" | VaultItemType;
type SidebarTab = "vault" | "teams";

const TYPE_LABELS: Record<VaultItemType, string> = {
  login: "Logins",
  note: "Notes",
  card: "Cards",
  identity: "Identities",
  ssh_key: "SSH Keys",
};

interface DecryptedEntry {
  item: EncryptedVaultItem;
  plaintext: VaultItemPlaintext;
}

function ItemAvatar({ type }: { type: VaultItemType }) {
  const icons: Record<VaultItemType, React.ReactNode> = {
    login: (
      <svg className="w-4 h-4 text-[#9C988D]" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth="1.5">
        <rect x="3" y="11" width="18" height="11" />
        <path d="M7 11V7a5 5 0 0 1 10 0v4" />
      </svg>
    ),
    note: (
      <svg className="w-4 h-4 text-[#9C988D]" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth="1.5">
        <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z" />
        <polyline points="14 2 14 8 20 8" />
        <line x1="16" y1="13" x2="8" y2="13" />
        <line x1="16" y1="17" x2="8" y2="17" />
      </svg>
    ),
    card: (
      <svg className="w-4 h-4 text-[#9C988D]" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth="1.5">
        <rect x="1" y="4" width="22" height="16" />
        <line x1="1" y1="10" x2="23" y2="10" />
      </svg>
    ),
    identity: (
      <svg className="w-4 h-4 text-[#9C988D]" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth="1.5">
        <path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2" />
        <circle cx="12" cy="7" r="4" />
      </svg>
    ),
    ssh_key: (
      <svg className="w-4 h-4 text-[#9C988D]" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth="1.5">
        <path d="M21 2l-2 2m-7.61 7.61a5.5 5.5 0 1 1-7.778 7.778 5.5 5.5 0 0 1 7.777-7.777zm0 0L15.5 7.5m0 0l3 3L22 7l-3-3m-3.5 3.5L19 4" />
      </svg>
    ),
  };

  return (
    <div className="w-9 h-9 bg-[#181713] border border-[#2B2923] flex items-center justify-center shrink-0">
      {icons[type]}
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
      className={`p-1.5 transition-all ${
        copied
          ? "text-[#7CFF6B] bg-[#7CFF6B]/10"
          : "text-[#9C988D] hover:text-[#F4F1E8] hover:bg-[#2B2923]"
      }`}
    >
      {copied ? (
        <svg className="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth="2.5">
          <polyline points="20 6 9 17 4 12" />
        </svg>
      ) : (
        <svg className="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth="1.5">
          <rect x="9" y="9" width="13" height="13" />
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
      <span className="flex-1 font-mono text-sm text-[#F4F1E8] break-all">
        {visible ? value : "•".repeat(Math.min(value.length, 20))}
      </span>
      <button
        onClick={() => setVisible((v) => !v)}
        className="p-1 text-[#9C988D] hover:text-[#F4F1E8] transition-colors"
        title={visible ? "Hide" : "Reveal"}
      >
        {visible ? (
          <svg className="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth="1.5">
            <path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94" />
            <path d="M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19" />
            <line x1="1" y1="1" x2="23" y2="23" />
          </svg>
        ) : (
          <svg className="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth="1.5">
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
      <p className="font-mono text-[10px] text-[#9C988D] uppercase tracking-widest mb-1.5">{label}</p>
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
      <span className={`font-mono text-xl font-bold tracking-widest ${urgent ? "text-[#E8321A]" : "text-[#F4F1E8]"}`}>
        {code.slice(0, 3)} {code.slice(3)}
      </span>
      <svg width="24" height="24" viewBox="0 0 24 24" className="shrink-0">
        <circle cx="12" cy="12" r={radius} fill="none" stroke="currentColor" strokeWidth="2" className="text-[#2B2923]" />
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
          className={`transition-[stroke-dashoffset] ${urgent ? "text-[#E8321A]" : "text-[#D6FF3F]"}`}
        />
        <text x="12" y="16" textAnchor="middle" fill="#9C988D" style={{ fontSize: "7px" }}>
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
            <span className="text-sm text-[#F4F1E8] break-all flex-1">{login.username}</span>
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
              className="text-sm text-[#D6FF3F] hover:underline break-all block"
            >
              {url}
            </a>
          ))}
        </DetailField>
      )}
      {login.customFields && login.customFields.length > 0 && (
        <>
          {login.customFields.map((field, i) => (
            <DetailField key={i} label={field.name || `Field ${i + 1}`}>
              {field.fieldType === "hidden" ? (
                <SecretField value={field.value} />
              ) : (
                <div className="flex items-center gap-1">
                  <span className="text-sm text-[#F4F1E8] flex-1 break-all">{field.value}</span>
                  <CopyButton text={field.value} label={`Copy ${field.name}`} />
                </div>
              )}
            </DetailField>
          ))}
        </>
      )}
      {login.notes && (
        <DetailField label="Notes">
          <p className="text-sm text-[#9C988D] whitespace-pre-wrap break-words">{login.notes}</p>
        </DetailField>
      )}
    </>
  );
}

function NoteDetail({ note }: { note: NoteItem }) {
  return (
    <DetailField label="Content">
      <p className="text-sm text-[#F4F1E8] whitespace-pre-wrap break-words leading-relaxed">
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
          <span className="text-sm text-[#F4F1E8]">{card.cardholderName}</span>
        </DetailField>
      )}
      {card.number && (
        <DetailField label="Card number">
          <SecretField value={card.number} />
        </DetailField>
      )}
      {(card.expMonth || card.expYear) && (
        <DetailField label="Expiry">
          <span className="text-sm text-[#F4F1E8]">
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
              <span className="text-sm text-[#F4F1E8] flex-1">{value}</span>
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
            <span className="flex-1 font-mono text-xs text-[#F4F1E8] break-all leading-relaxed">
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
            <span className="text-sm text-[#F4F1E8] flex-1 font-mono">{sshKey.comment}</span>
            <CopyButton text={sshKey.comment} label="Copy comment" />
          </div>
        </DetailField>
      )}
      {sshKey.notes && (
        <DetailField label="Notes">
          <p className="text-sm text-[#9C988D] whitespace-pre-wrap break-words">{sshKey.notes}</p>
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
  isFavorite,
  onToggleFavorite,
}: {
  entry: DecryptedEntry;
  onEdit: () => void;
  onDelete: () => void;
  onClose: () => void;
  isFavorite: boolean;
  onToggleFavorite: () => void;
}) {
  const [confirmDelete, setConfirmDelete] = useState(false);
  const { plaintext, item } = entry;

  return (
    <aside className="w-96 flex flex-col border-l border-[#2B2923] bg-[#11110F] shrink-0 animate-slide-in-right">
      {/* Header */}
      <div className="flex items-start gap-3 px-5 py-4 border-b border-[#2B2923]">
        <ItemAvatar type={item.itemType} />
        <div className="flex-1 min-w-0 pt-0.5">
          <h2 className="text-sm font-semibold text-[#F4F1E8] truncate">{plaintext.name}</h2>
          <p className="font-mono text-[10px] text-[#9C988D] uppercase tracking-widest mt-0.5">
            {TYPE_LABELS[item.itemType].slice(0, -1)}
          </p>
        </div>
        <div className="flex items-center gap-1 shrink-0">
          <button
            onClick={onToggleFavorite}
            title={isFavorite ? "Remove from favorites" : "Add to favorites"}
            className={`p-1.5 transition-colors ${isFavorite ? "text-[#D6FF3F] hover:text-[#C4EE30]" : "text-[#2B2923] hover:text-[#D6FF3F]"}`}
          >
            <svg className="w-4 h-4" fill={isFavorite ? "currentColor" : "none"} viewBox="0 0 24 24" stroke="currentColor" strokeWidth="1.5">
              <path d="M12 2l3.09 6.26L22 9.27l-5 4.87 1.18 6.88L12 17.77l-6.18 3.25L7 14.14 2 9.27l6.91-1.01L12 2z" />
            </svg>
          </button>
          <button
            onClick={onEdit}
            className="px-3 py-1.5 font-mono text-xs text-[#9C988D] hover:text-[#F4F1E8] hover:bg-[#181713] border border-[#2B2923] hover:border-[#9C988D] transition-colors"
          >
            Edit
          </button>
          <button
            onClick={onClose}
            className="p-1.5 text-[#9C988D] hover:text-[#F4F1E8] hover:bg-[#181713] transition-colors"
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

        <div className="font-mono text-[10px] text-[#9C988D]/40 pt-2 border-t border-[#2B2923]">
          <p>ID {item.id.slice(0, 8)}… · v{item.version}</p>
        </div>
      </div>

      {/* Delete */}
      <div className="p-4 border-t border-[#2B2923]">
        {confirmDelete ? (
          <div className="bg-[#E8321A]/10 border border-[#E8321A]/30 p-3">
            <p className="font-mono text-xs text-[#E8321A] mb-3">
              Delete this item permanently?
            </p>
            <div className="flex gap-2">
              <button
                onClick={() => setConfirmDelete(false)}
                className="flex-1 py-1.5 font-mono text-xs text-[#9C988D] hover:bg-[#2B2923] hover:text-[#F4F1E8] transition-colors"
              >
                Cancel
              </button>
              <button
                onClick={onDelete}
                className="flex-1 py-1.5 font-mono text-xs font-medium text-white bg-[#E8321A] hover:bg-[#D42D18] transition-colors"
              >
                Delete
              </button>
            </div>
          </div>
        ) : (
          <button
            onClick={() => setConfirmDelete(true)}
            className="w-full py-1.5 font-mono text-xs text-[#E8321A]/60 hover:text-[#E8321A] hover:bg-[#E8321A]/10 transition-colors"
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
    <div className="fixed bottom-6 left-1/2 z-50 px-4 py-2 bg-[#F4F1E8] text-[#070706] font-mono text-xs animate-toast pointer-events-none">
      {message}
    </div>
  );
}

export default function VaultPage() {
  return (
    <Suspense>
      <VaultPageInner />
    </Suspense>
  );
}

function VaultPageInner() {
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
    toggleFavorite,
    favorites,
    copyWithAutoClear,
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
    const ok = await copyWithAutoClear(text);
    if (ok) showToast(successMessage);
  }

  useEffect(() => {
    const itemId = searchParams.get("item");
    if (itemId) {
      setSelectedId(itemId);
      router.replace("/vault");
    }
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  useEffect(() => {
    const timer = setTimeout(() => searchRef.current?.focus(), 50);
    return () => clearTimeout(timer);
  }, []);

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
    if (!isUnlocked()) return;
    const IDLE_MS = 15 * 60 * 1000;
    let timer: ReturnType<typeof setTimeout>;

    function resetTimer() {
      clearTimeout(timer);
      timer = setTimeout(() => {
        lock();
        router.replace("/login");
      }, IDLE_MS);
    }

    const events = ["mousedown", "mousemove", "keydown", "touchstart", "scroll", "click"] as const;
    for (const ev of events) window.addEventListener(ev, resetTimer, { passive: true });
    resetTimer();

    return () => {
      clearTimeout(timer);
      for (const ev of events) window.removeEventListener(ev, resetTimer);
    };
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [isUnlocked]);

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
    if (filter === "favorites" && !favorites.has(item.id)) return false;
    if (filter !== "all" && filter !== "favorites" && item.itemType !== filter) return false;
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
    <div className="flex h-screen bg-[#070706]">
      {/* Sidebar */}
      <aside className="w-56 flex flex-col border-r border-[#2B2923] bg-[#11110F] shrink-0">
        {/* Logo */}
        <div className="px-4 py-4 border-b border-[#2B2923]">
          <span className="font-mono text-sm font-semibold text-[#F4F1E8] tracking-tight">nopwd</span>
        </div>

        {/* Tab switcher */}
        <div className="flex border-b border-[#2B2923] shrink-0">
          {(["vault", "teams"] as SidebarTab[]).map((tab) => (
            <button
              key={tab}
              onClick={() => setSidebarTab(tab)}
              className={`flex-1 py-2 font-mono text-xs transition-colors ${
                sidebarTab === tab
                  ? "text-[#D6FF3F] border-b border-[#D6FF3F]"
                  : "text-[#9C988D] hover:text-[#F4F1E8]"
              }`}
            >
              {tab === "vault" ? "Vault" : "Teams"}
            </button>
          ))}
        </div>

        {sidebarTab === "vault" ? (
          <nav className="flex-1 overflow-y-auto p-2">
            {(["all", "favorites", "login", "note", "card", "identity", "ssh_key"] as Filter[]).map((f) => {
              const count =
                f === "all"
                  ? activeItems.length
                  : f === "favorites"
                    ? activeItems.filter((i) => favorites.has(i.id)).length
                    : activeItems.filter((i) => i.itemType === f).length;
              const isActive = filter === f;
              const label =
                f === "all" ? "All items" :
                f === "favorites" ? "Favorites" :
                TYPE_LABELS[f as VaultItemType];
              return (
                <button
                  key={f}
                  onClick={() => setFilter(f)}
                  className={`w-full text-left px-3 py-2 font-mono text-xs transition-colors flex items-center justify-between mb-0.5 ${
                    isActive
                      ? "text-[#D6FF3F] bg-[#D6FF3F]/10"
                      : "text-[#9C988D] hover:text-[#F4F1E8] hover:bg-[#181713]"
                  }`}
                >
                  <span className="flex items-center gap-2">
                    {f === "favorites" && (
                      <svg className="w-3 h-3" fill="currentColor" viewBox="0 0 24 24">
                        <path d="M12 2l3.09 6.26L22 9.27l-5 4.87 1.18 6.88L12 17.77l-6.18 3.25L7 14.14 2 9.27l6.91-1.01L12 2z" />
                      </svg>
                    )}
                    {label}
                  </span>
                  <span className={`tabular-nums ${isActive ? "text-[#D6FF3F]" : "text-[#9C988D]/60"}`}>
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
        <div className="p-3 border-t border-[#2B2923]">
          <div className="flex items-center gap-2.5 mb-2">
            <div className="w-7 h-7 bg-[#2B2923] flex items-center justify-center shrink-0">
              <span className="font-mono text-xs font-semibold text-[#9C988D]">{userInitial}</span>
            </div>
            <p className="text-xs text-[#9C988D] truncate flex-1" title={userEmail ?? ""}>
              {userEmail}
            </p>
          </div>
          <button
            onClick={handleLock}
            className="w-full flex items-center gap-2 px-2.5 py-1.5 font-mono text-xs text-[#9C988D] hover:bg-[#181713] hover:text-[#F4F1E8] transition-colors"
          >
            <svg className="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth="1.5">
              <rect x="3" y="11" width="18" height="11" />
              <path d="M7 11V7a5 5 0 0 1 10 0v4" />
            </svg>
            Lock vault
          </button>
        </div>
      </aside>

      {/* Main content */}
      <div className="flex-1 flex flex-col min-w-0">
        {/* Toolbar */}
        <header className="flex items-center gap-3 px-5 py-3 border-b border-[#2B2923] bg-[#11110F]">
          <div className="relative flex-1 max-w-sm">
            <svg className="absolute left-3 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-[#9C988D]" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth="2">
              <circle cx="11" cy="11" r="8" />
              <path d="M21 21l-4.35-4.35" />
            </svg>
            <input
              ref={searchRef}
              type="search"
              placeholder="Search…"
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              className="w-full pl-9 pr-3 py-2 text-sm border border-[#2B2923] bg-[#070706] text-[#F4F1E8] placeholder:text-[#9C988D]/60 focus:outline-none focus:border-[#D6FF3F] transition-colors"
            />
          </div>
          <div className="ml-auto flex items-center gap-2">
            <span className="font-mono text-xs text-[#9C988D]/60 hidden sm:block">
              <kbd className="px-1.5 py-0.5 bg-[#2B2923] text-[#9C988D] font-mono">⌘K</kbd>
            </span>
            <button
              onClick={() => router.push("/vault/health")}
              className="flex items-center gap-1.5 px-3 py-2 font-mono text-xs text-[#9C988D] hover:bg-[#181713] hover:text-[#F4F1E8] transition-colors"
            >
              <svg className="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth="1.5">
                <path strokeLinecap="round" strokeLinejoin="round" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
              </svg>
              Security
            </button>
            <button
              onClick={() => router.push("/vault/devices")}
              className="flex items-center gap-1.5 px-3 py-2 font-mono text-xs text-[#9C988D] hover:bg-[#181713] hover:text-[#F4F1E8] transition-colors"
            >
              <svg className="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth="1.5">
                <rect x="2" y="3" width="20" height="14" />
                <path d="M8 21h8M12 17v4" />
              </svg>
              Devices
            </button>
            <button
              onClick={() => router.push("/vault/import")}
              className="flex items-center gap-1.5 px-3 py-2 font-mono text-xs text-[#9C988D] hover:bg-[#181713] hover:text-[#F4F1E8] transition-colors"
            >
              <svg className="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth="1.5">
                <path strokeLinecap="round" strokeLinejoin="round" d="M3 16.5v2.25A2.25 2.25 0 005.25 21h13.5A2.25 2.25 0 0021 18.75V16.5M16.5 12L12 16.5m0 0L7.5 12m4.5 4.5V3" />
              </svg>
              Import
            </button>
            <div className="relative" ref={typePickerRef}>
              <button
                data-testid="new-item-btn"
                onClick={() => setTypePicker((v) => !v)}
                className="flex items-center gap-1.5 px-3.5 py-2 font-mono text-xs font-semibold bg-[#D6FF3F] hover:bg-[#C4EE30] text-[#070706] transition-colors"
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
                  className="absolute right-0 top-full mt-1 z-40 bg-[#11110F] border border-[#2B2923] py-1 min-w-[140px]"
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
                      className="w-full text-left px-3.5 py-2 font-mono text-xs text-[#9C988D] hover:text-[#F4F1E8] hover:bg-[#181713] transition-colors"
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
            <div className="mb-4 flex items-center gap-2.5 p-3 bg-[#E8321A]/10 border border-[#E8321A]/30 text-sm text-[#E8321A]">
              <svg className="w-4 h-4 shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth="2">
                <circle cx="12" cy="12" r="10" />
                <line x1="12" y1="8" x2="12" y2="12" />
                <line x1="12" y1="16" x2="12.01" y2="16" />
              </svg>
              {error}
              <button onClick={() => setError(null)} className="ml-auto text-[#9C988D] hover:text-[#F4F1E8]">
                <svg className="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth="2">
                  <line x1="18" y1="6" x2="6" y2="18" /><line x1="6" y1="6" x2="18" y2="18" />
                </svg>
              </button>
            </div>
          )}

          {isLoading ? (
            <div className="space-y-px max-w-2xl">
              {[...Array(5)].map((_, i) => (
                <div key={i} className="flex items-center gap-3 p-3 bg-[#11110F] border border-[#2B2923] animate-pulse">
                  <div className="w-9 h-9 bg-[#2B2923] shrink-0" />
                  <div className="flex-1 space-y-2">
                    <div className="h-3 bg-[#2B2923] w-28" />
                    <div className="h-2.5 bg-[#181713] w-44" />
                  </div>
                </div>
              ))}
            </div>
          ) : filteredItems.length === 0 ? (
            <div className="flex flex-col items-center justify-center h-64 text-center">
              <div className="w-14 h-14 bg-[#11110F] border border-[#2B2923] flex items-center justify-center mb-4">
                <svg className="w-7 h-7 text-[#2B2923]" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth="1.5">
                  <rect x="3" y="11" width="18" height="11" />
                  <path d="M7 11V7a5 5 0 0 1 10 0v4" />
                </svg>
              </div>
              <p className="font-mono text-xs text-[#9C988D] uppercase tracking-widest">
                {search ? "No matching items" : "Your vault is empty"}
              </p>
              {!search && (
                <p className="text-xs text-[#9C988D]/60 mt-2">
                  Press <kbd className="px-1 py-0.5 bg-[#2B2923] font-mono text-[#9C988D]">N</kbd> or click New item to get started
                </p>
              )}
            </div>
          ) : (
            <div className="max-w-2xl space-y-px">
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
                      className={`flex-1 flex items-center gap-3 px-3 py-2.5 text-left transition-all ${
                        isSelected
                          ? "bg-[#181713] border-l-2 border-l-[#D6FF3F] border-y border-r border-[#2B2923]"
                          : "hover:bg-[#11110F] border-l-2 border-l-transparent border-y border-r border-transparent hover:border-[#2B2923]"
                      }`}
                    >
                      <ItemAvatar type={item.itemType} />
                      <div className="flex-1 min-w-0">
                        <p className={`text-sm font-medium truncate ${isSelected ? "text-[#D6FF3F]" : "text-[#F4F1E8]"}`}>
                          {name}
                        </p>
                        {subtitle && (
                          <p className="text-xs text-[#9C988D] truncate mt-0.5">{subtitle}</p>
                        )}
                      </div>
                      <span className={`font-mono text-[10px] text-[#9C988D] uppercase tracking-widest shrink-0 transition-opacity ${loginPlain ? "group-hover:opacity-0" : ""}`}>
                        {TYPE_LABELS[item.itemType].slice(0, -1)}
                      </span>
                    </button>

                    {/* Quick-copy actions for login items */}
                    {loginPlain && (
                      <div className="absolute right-3 flex items-center gap-0.5 opacity-0 group-hover:opacity-100 transition-opacity">
                        {loginPlain.username && (
                          <button
                            onClick={() => copyToClipboard(loginPlain.username!, "Username copied")}
                            title="Copy username (U)"
                            className="p-1.5 text-[#9C988D] hover:text-[#F4F1E8] hover:bg-[#2B2923] transition-colors"
                          >
                            <svg className="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth="1.5">
                              <path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2" />
                              <circle cx="12" cy="7" r="4" />
                            </svg>
                          </button>
                        )}
                        {loginPlain.password && (
                          <button
                            onClick={() => copyToClipboard(loginPlain.password!, "Password copied")}
                            title="Copy password (C)"
                            className="p-1.5 text-[#9C988D] hover:text-[#F4F1E8] hover:bg-[#2B2923] transition-colors"
                          >
                            <svg className="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth="1.5">
                              <rect x="9" y="9" width="13" height="13" />
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

          {/* Keyboard shortcut hint */}
          {selectedEntry?.plaintext.type === "login" && (
            <div className="mt-4 max-w-2xl flex items-center gap-3 font-mono text-[10px] text-[#9C988D]/40">
              <kbd className="px-1.5 py-0.5 bg-[#2B2923] text-[#9C988D]">C</kbd>
              <span>copy password</span>
              <kbd className="px-1.5 py-0.5 bg-[#2B2923] text-[#9C988D]">U</kbd>
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
          isFavorite={favorites.has(selectedEntry.item.id)}
          onToggleFavorite={() => toggleFavorite(selectedEntry.item.id)}
        />
      )}

      {/* Item editor modal */}
      {modal && (
        <div
          className="fixed inset-0 bg-black/60 flex items-center justify-center z-50 p-4"
          onClick={(e) => { if (e.target === e.currentTarget) setModal(null); }}
        >
          <div className="bg-[#11110F] border border-[#2B2923] w-full max-w-lg max-h-[90vh] overflow-hidden flex flex-col">
            <div className="flex items-center justify-between px-6 py-4 border-b border-[#2B2923]">
              <h2 className="font-mono text-sm font-semibold text-[#F4F1E8]">
                {modal.mode === "create"
                  ? `New ${TYPE_LABELS[modal.itemType].slice(0, -1)}`
                  : `Edit ${TYPE_LABELS[modal.entry.plaintext.type as VaultItemType].slice(0, -1)}`}
              </h2>
              <button
                onClick={() => setModal(null)}
                className="p-1.5 text-[#9C988D] hover:text-[#F4F1E8] hover:bg-[#181713] transition-colors"
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
