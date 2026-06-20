interface StrengthMeterProps {
  score: number;
}

function scoreColor(score: number): string {
  if (score < 40) return "bg-ng-alert";
  if (score <= 70) return "bg-ng-warning";
  return "bg-ng-safe";
}

function scoreLabel(score: number): string {
  if (score < 40) return "Weak";
  if (score <= 70) return "Fair";
  return "Strong";
}

function scoreTextColor(score: number): string {
  if (score < 40) return "text-ng-alert";
  if (score <= 70) return "text-ng-warning";
  return "text-ng-safe";
}

export default function StrengthMeter({ score }: StrengthMeterProps) {
  const color = scoreColor(score);
  const label = scoreLabel(score);

  return (
    <div className="space-y-1.5">
      <div className="flex items-center justify-between text-xs">
        <span className="text-gray-400">Password strength</span>
        <span className={`font-semibold ${scoreTextColor(score)}`}>
          {score}/100 — {label}
        </span>
      </div>
      <div className="h-2 w-full overflow-hidden rounded-full bg-ng-elevated">
        <div
          className={`h-full rounded-full transition-all ${color}`}
          style={{ width: `${Math.min(score, 100)}%` }}
        />
      </div>
    </div>
  );
}
