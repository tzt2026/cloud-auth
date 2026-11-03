import { useEffect, useId, useRef, useState } from "react";
import { useNavigate } from "react-router-dom";
import { useAuthSession } from "@/lib/auth/context";

/**
 * Account actions live in the header, never in a second row below mobile tabs.
 * Keep a single logout control, mounted only while the account menu is open.
 */
export function SessionBlock() {
  const { account, pending, logout, getSessionToken } = useAuthSession();
  const navigate = useNavigate();
  const [open, setOpen] = useState(false);
  const rootRef = useRef<HTMLDivElement>(null);
  const triggerRef = useRef<HTMLButtonElement>(null);
  const menuId = useId();
  const username = account?.username ?? "Mira Cloud";

  useEffect(() => {
    if (!open) return;
    function onPointerDown(event: PointerEvent) {
      if (event.target instanceof Node && !rootRef.current?.contains(event.target)) {
        setOpen(false);
      }
    }
    // Escape and focus leaving the block are handled at the document level for
    // the same reason as the outside click: the container stays a plain layout
    // element instead of carrying interactive handlers on a `div`.
    //
    // Escape only belongs to this menu when it owns focus, so a dialog or menu
    // opened elsewhere on the page keeps its own handling instead of being
    // swallowed here.
    function onKeyDown(event: KeyboardEvent) {
      if (event.key !== "Escape") return;
      if (!(event.target instanceof Node) || !rootRef.current?.contains(event.target)) return;
      event.preventDefault();
      setOpen(false);
      triggerRef.current?.focus();
    }
    function onFocusIn(event: FocusEvent) {
      if (event.target instanceof Node && !rootRef.current?.contains(event.target)) {
        setOpen(false);
      }
    }
    document.addEventListener("pointerdown", onPointerDown);
    document.addEventListener("keydown", onKeyDown);
    document.addEventListener("focusin", onFocusIn);
    return () => {
      document.removeEventListener("pointerdown", onPointerDown);
      document.removeEventListener("keydown", onKeyDown);
      document.removeEventListener("focusin", onFocusIn);
    };
  }, [open]);

  async function handleLogout() {
    await logout();
    if (!getSessionToken()) {
      void navigate("/login", { replace: true });
    }
  }

  return (
    <div className="console-account" ref={rootRef}>
      <button
        ref={triggerRef}
        type="button"
        className="console-identity console-identity-trigger"
        aria-label="账户菜单"
        aria-expanded={open}
        aria-controls={menuId}
        disabled={pending === "logout"}
        onClick={() => setOpen((current) => !current)}
      >
        <span aria-hidden="true" className="console-avatar">
          {username.trim().slice(0, 1).toUpperCase() || "M"}
        </span>
        <span className="console-identity-copy">
          <strong>{username}</strong>
        </span>
        <span className="console-account-chevron" aria-hidden="true" />
      </button>
      {open ? (
        <div className="console-account-menu" id={menuId} role="group" aria-label="账户操作">
          <button
            type="button"
            className="console-account-logout"
            onClick={() => void handleLogout()}
            disabled={pending !== null}
          >
            {pending === "logout" ? "退出中…" : "退出登录"}
          </button>
        </div>
      ) : null}
    </div>
  );
}
