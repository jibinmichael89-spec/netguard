import { Link, useLocation } from "react-router-dom";
import { Shield } from "lucide-react";
import { formatTimestamp } from "../utils/format";

interface NavbarProps {
  lastScanTime: string | null;
}

const NAV_LINKS = [
  { to: "/", label: "Dashboard" },
  { to: "/alerts", label: "Alerts" },
  { to: "/dns", label: "DNS" },
  { to: "/vault", label: "Vault" },
  { to: "/settings", label: "Settings" },
  { to: "/msp", label: "MSP" },
];

export default function Navbar({ lastScanTime }: NavbarProps) {
  const location = useLocation();

  return (
    <header className="sticky top-0 z-50 border-b border-ng-border bg-ng-bg/95 backdrop-blur-sm">
      <div className="mx-auto flex max-w-7xl flex-col gap-4 px-4 py-4 sm:flex-row sm:items-center sm:justify-between sm:px-6 lg:px-8">
        <div className="flex items-center gap-3">
          <div className="flex h-9 w-9 items-center justify-center rounded-lg bg-ng-accent/10">
            <Shield className="h-5 w-5 text-ng-accent" />
          </div>
          <div>
            <h1 className="text-lg font-bold tracking-tight text-white">
              NetGuard
            </h1>
            <p className="text-xs text-gray-500">
              Last scan:{" "}
              <span className="text-gray-400">
                {lastScanTime ? formatTimestamp(lastScanTime) : "—"}
              </span>
            </p>
          </div>
        </div>

        <nav className="flex flex-wrap gap-1">
          {NAV_LINKS.map(({ to, label }) => {
            const active =
              to === "/"
                ? location.pathname === "/"
                : location.pathname.startsWith(to);
            return (
              <Link
                key={to}
                to={to}
                className={`rounded-lg px-4 py-2 text-sm font-medium transition ${
                  active
                    ? "bg-ng-accent/15 text-ng-accent"
                    : "text-gray-400 hover:bg-ng-elevated hover:text-white"
                }`}
              >
                {label}
              </Link>
            );
          })}
        </nav>
      </div>
    </header>
  );
}
