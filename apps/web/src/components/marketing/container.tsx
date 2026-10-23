import type { ReactNode } from "react";

export const CONTAINER = "mx-auto w-full max-w-[1120px] px-4 sm:px-6";

/** A page section: 96px of space either side of a 1px divider (48px on mobile). */
export function Section({
  id,
  title,
  intro,
  children,
}: {
  id?: string;
  title: string;
  intro?: ReactNode;
  children: ReactNode;
}) {
  return (
    <section id={id} className="scroll-mt-14 border-t border-divider py-12 md:py-24">
      <div className={CONTAINER}>
        <div className="max-w-[640px]">
          <h2 className="text-h1 font-semibold text-fg">{title}</h2>
          {intro && <p className="mt-3 text-body text-muted">{intro}</p>}
        </div>
        <div className="mt-10 md:mt-12">{children}</div>
      </div>
    </section>
  );
}
