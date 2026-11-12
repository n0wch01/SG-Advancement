import { ApiError } from "../api";

export function Loading() {
  return <p className="muted">불러오는 중…</p>;
}

export function ErrorBox({ error }: { error: Error }) {
  const status = error instanceof ApiError ? ` (${error.status})` : "";
  return (
    <p className="error" role="alert">
      불러오지 못했습니다{status}: {error.message}
    </p>
  );
}

export function Empty({ children }: { children: React.ReactNode }) {
  return <p className="muted empty">{children}</p>;
}
