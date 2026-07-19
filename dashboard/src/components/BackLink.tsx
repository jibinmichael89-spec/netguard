import { ArrowLeft } from "lucide-react";
import { useNavigate } from "react-router-dom";

type BackLinkProps = {
  /** Used when there is no in-app history to go back to. */
  fallbackTo: string;
  label: string;
  className?: string;
};

/**
 * Prefer the previous page in history (e.g. Online Devices filter).
 * Fall back to a known route when the user opened this page directly.
 */
export default function BackLink({
  fallbackTo,
  label,
  className = "inline-flex items-center gap-1 text-sm text-gray-400 transition hover:text-ng-accent",
}: BackLinkProps) {
  const navigate = useNavigate();

  const handleClick = () => {
    const idx = (window.history.state as { idx?: number } | null)?.idx;
    if (typeof idx === "number" && idx > 0) {
      navigate(-1);
      return;
    }
    navigate(fallbackTo);
  };

  return (
    <button type="button" onClick={handleClick} className={className}>
      <ArrowLeft className="h-4 w-4" />
      {label}
    </button>
  );
}
