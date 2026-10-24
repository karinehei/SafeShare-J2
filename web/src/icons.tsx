import type { ReactNode } from "react"

export type IconName = "files" | "findings" | "compare" | "download" | "rules" | "how" | "file"

const glyphs: Record<IconName, ReactNode> = {
  files: <path d="M4 7.5A1.5 1.5 0 0 1 5.5 6H9l2 2h7.5A1.5 1.5 0 0 1 20 9.5v8A1.5 1.5 0 0 1 18.5 19h-13A1.5 1.5 0 0 1 4 17.5v-10z" />,
  findings: (
    <>
      <path d="M9 6h11M9 12h11M9 18h7" />
      <path d="M5 6h.01M5 12h.01M5 18h.01" />
    </>
  ),
  compare: (
    <>
      <rect x="3.5" y="4.5" width="7" height="15" rx="1.5" />
      <rect x="13.5" y="4.5" width="7" height="15" rx="1.5" />
    </>
  ),
  download: (
    <>
      <path d="M12 4v10" />
      <path d="m8 10 4 4 4-4" />
      <path d="M5 19h14" />
    </>
  ),
  rules: (
    <>
      <path d="M5 5.5A1.5 1.5 0 0 1 6.5 4H19v14H6.5A1.5 1.5 0 0 0 5 19.5v-14z" />
      <path d="M5 18.5h14" />
    </>
  ),
  how: (
    <>
      <circle cx="6" cy="7" r="2" />
      <circle cx="18" cy="7" r="2" />
      <circle cx="12" cy="17" r="2" />
      <path d="m7.7 8.4 3 6.2M16.3 8.4l-3 6.2" />
    </>
  ),
  file: (
    <>
      <path d="M7 3.5h6.5L19 9v10.5a1 1 0 0 1-1 1H7a1 1 0 0 1-1-1v-15a1 1 0 0 1 1-1z" />
      <path d="M13.5 3.5V9H19" />
    </>
  ),
}

export function Icon({ name }: { name: IconName }) {
  return (
    <svg className="icon" viewBox="0 0 24 24" aria-hidden="true" focusable="false">
      {glyphs[name]}
    </svg>
  )
}

export function Mark() {
  return (
    <svg className="mark" viewBox="0 0 32 32" aria-hidden="true" focusable="false">
      <path d="M16 4.5 26 8.4v7.1c0 6-4.1 9.7-10 11.4C10.1 25.2 6 21.5 6 15.5V8.4L16 4.5z" />
      <path className="mark-check" d="M11.4 16.3 14.4 19.4 20.8 12.8" />
    </svg>
  )
}
