interface LoadingSpinnerProps {
  label?: string;
  fullPage?: boolean;
}

export default function LoadingSpinner({
  label = "Loading...",
  fullPage = false,
}: LoadingSpinnerProps) {
  const content = (
    <div className="flex flex-col items-center justify-center gap-4">
      <div
        className="h-10 w-10 animate-spin rounded-full border-2 border-gray-600 border-t-[#00D4FF]"
        role="status"
        aria-label={label}
      />
      <p className="text-sm font-medium text-gray-300">{label}</p>
    </div>
  );

  if (fullPage) {
    return (
      <div className="flex min-h-[50vh] items-center justify-center">{content}</div>
    );
  }

  return content;
}
